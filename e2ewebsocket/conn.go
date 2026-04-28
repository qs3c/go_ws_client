package e2ewebsocket

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	im_parser "github.com/qs3c/e2e-secure-ws/e2ewebsocket/im_parser"
)

type Conn struct {
	conn     *websocket.Conn
	hostId   string
	config   *Config
	sessions sync.Map
	msgChan  chan readMsgItem

	imParser im_parser.IMParser
	writeMu  sync.Mutex

	writeDeadlineNanos atomic.Int64

	connMu   sync.Mutex
	connCond *sync.Cond
	closed   bool
}

func NewSecureConn(config *Config, imParser im_parser.IMParser) (*Conn, error) {
	if imParser == nil {
		return nil, errors.New("imParser is nil")
	}
	c := &Conn{
		config:   config,
		msgChan:  make(chan readMsgItem, 128),
		imParser: imParser,
	}
	c.connCond = sync.NewCond(&c.connMu)
	go c.readLoop()
	return c, nil
}

type readMsgItem struct {
	sessionId SessionID
	remoteId  string
	msgType   int
	msg       []byte
	err       error
}

func (c *Conn) readLoop() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("readLoop panic: %v", r)
		}
		close(c.msgChan)
		log.Println("readLoop exited")
	}()

	var lastConn *websocket.Conn

	for {
		c.connMu.Lock()
		for (c.conn == nil || c.conn == lastConn) && !c.closed {
			c.connCond.Wait()
		}
		if c.closed {
			c.connMu.Unlock()
			return
		}
		conn := c.conn
		lastConn = conn
		c.connMu.Unlock()

		for {
			if err := c.readRecord(conn); err != nil {
				c.connMu.Lock()
				if c.closed {
					c.connMu.Unlock()
					return
				}

				replaced := c.conn != conn
				if !replaced {
					c.msgChan <- readMsgItem{err: err}
				}
				c.connMu.Unlock()
				break
			}
		}
	}
}

func (c *Conn) readRecord(conn *websocket.Conn) error {
	msgType, msg, err := conn.ReadMessage()
	if err != nil {
		log.Printf("readLoop ReadMessage error: %v", err)
		return err
	}

	if msgType != websocket.BinaryMessage {
		c.msgChan <- readMsgItem{msgType: msgType, msg: msg}
		return nil
	}

	msgData, err := c.imParser.BytesToMsgDataReadBound(msg)
	if err != nil {
		if errors.Is(err, im_parser.ErrDropSecureWS) {
			return nil
		}
		if errors.Is(err, im_parser.ErrBypassSecureWS) {
			c.msgChan <- readMsgItem{msgType: msgType, msg: msg}
			return nil
		}
		log.Printf("readLoop MsgDataFromServerReadBound error: %v", err)
		return nil
	}

	senderId := msgData.GetSendID()
	if senderId == "" {
		log.Printf("readLoop secure message missing sender id")
		return nil
	}
	sessionId := getSessionID(c.hostId, senderId)

	actual, loaded := c.sessions.LoadOrStore(sessionId, NewSession(sessionId, senderId, c))
	session := actual.(*Session)
	if !loaded {
		go func(s *Session) {
			if err := s.Handshake(); err != nil {
				log.Printf("Passive handshake failed for session %s: %v", s.id, err)
			}
		}(session)
	}

	handshakeComplete := session.isHandshakeComplete.Load()
	plaintext, err := session.in.decrypt(msgData.GetContent())
	if err != nil {
		log.Printf("readLoop decrypt error: %v", err)
		c.terminateSession(session, err)
		return nil
	}
	if len(plaintext) < 1 {
		log.Printf("readLoop secure payload is empty")
		c.terminateSession(session, errors.New("empty secure payload"))
		return nil
	}

	typ := recordType(plaintext[0])
	data := plaintext[1:]
	msgData.SetContent(data)

	switch typ {
	default:
		log.Printf("readLoop unexpected message type: %d", typ)
		c.terminateSession(session, errors.New("UnexpectedMessage"))
		return nil
	case recordTypeAlert:
		if string(data) != "Alert" {
			log.Printf("readLoop invalid alert message")
			c.terminateSession(session, errors.New("AlertMessageLenError"))
			return nil
		}
		log.Printf("readLoop received alert from %s", senderId)
		c.closeSessionLocally(session, errors.New("received alert"))
		return nil
	case recordTypeApplicationData:
		if !handshakeComplete && loaded {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			if !session.isHandshakeComplete.Load() {
				log.Printf("readLoop waiting for handshake completion for session %s...", sessionId)
				select {
				case <-session.handshakeComplete:
				case <-ctx.Done():
					log.Printf("readLoop handshake wait timeout for session %s", sessionId)
					c.terminateSession(session, errors.New("alertUnexpectedMessage"))
					return nil
				case <-session.done:
					return nil
				}
			}
		}

		msgDataBytes, err := c.imParser.MsgDataToBytesReadBound(msgData)
		if err != nil {
			log.Printf("readLoop MsgDataToBytesReadBound error: %v", err)
			c.terminateSession(session, err)
			return nil
		}
		c.msgChan <- readMsgItem{
			sessionId: sessionId,
			remoteId:  senderId,
			msgType:   msgType,
			msg:       msgDataBytes,
		}
	case recordTypeHandshake:
		select {
		case session.handshakeChan <- sessionMsg{typ: recordTypeHandshake, data: data}:
		default:
			log.Printf("readLoop handshake channel blocked for session %s", session.id)
			c.terminateSession(session, errors.New("handshake channel blocked"))
			return nil
		}
	case recordTypeChangeCipherSpec:
		if len(data) != 3 || string(data) != "CCS" {
			c.terminateSession(session, errors.New("alertDecodeError"))
			return nil
		}
		if err := session.in.changeCipherSpec(); err != nil {
			log.Printf("readLoop changeCipherSpec error: %v", err)
			c.terminateSession(session, errors.New("change cipher failed"))
			return nil
		}
	}
	return nil
}

func (c *Conn) ReadMessage() (int, []byte, error) {
	item, ok := <-c.msgChan
	if !ok {
		return 0, nil, errors.New("connection closed")
	}
	return item.msgType, item.msg, item.err
}

func (c *Conn) WriteMessage(messageType int, message []byte) error {
	if messageType != websocket.BinaryMessage {
		return c.writeRawMessage(messageType, message)
	}

	msgData, err := c.imParser.BytesToMsgDataWriteBound(message)
	if err != nil {
		if errors.Is(err, im_parser.ErrBypassSecureWS) {
			return c.writeRawMessage(messageType, message)
		}
		return err
	}

	remoteId := msgData.GetRecvID()
	if remoteId == "" {
		return c.writeRawMessage(messageType, message)
	}

	sessionId := getSessionID(c.hostId, remoteId)

	var session *Session
	if val, ok := c.sessions.Load(sessionId); ok {
		session = val.(*Session)
	}
	if session == nil {
		session = NewSession(sessionId, remoteId, c)
		actual, _ := c.sessions.LoadOrStore(sessionId, session)
		session = actual.(*Session)
	}

	if err := session.Handshake(); err != nil {
		c.terminateSession(session, err)
		return err
	}

	err = c.writeRecordLocked(recordTypeApplicationData, msgData, session)
	if err != nil {
		return c.Close()
	}
	return nil
}

func (c *Conn) writeRawMessage(messageType int, message []byte) error {
	c.connMu.Lock()
	conn := c.conn
	c.connMu.Unlock()
	if conn == nil {
		return errNotConnected
	}
	return c.writeWebSocketMessage(conn, messageType, message)
}

func (c *Conn) writeRecordLocked(typ recordType, msgData im_parser.MsgData, session *Session) error {
	if msgData == nil {
		return errors.New("nil msgData")
	}

	securePayload := make([]byte, 1+len(msgData.GetContent()))
	securePayload[0] = byte(typ)
	copy(securePayload[1:], msgData.GetContent())

	encContent, err := session.out.encrypt(nil, securePayload, c.config.rand())
	if err != nil {
		c.terminateSession(session, err)
		return nil
	}
	msgData.SetContent(encContent)

	ex := msgData.GetEx()
	if !strings.HasPrefix(ex, im_parser.SecureWSMarker) {
		msgData.SetEx(im_parser.SecureWSMarker + ex)
	}

	msgDataBytes, err := c.imParser.MsgDataToBytesWriteBound(msgData)
	if err != nil {
		return err
	}

	c.connMu.Lock()
	conn := c.conn
	c.connMu.Unlock()
	if conn == nil {
		return errNotConnected
	}
	return c.writeWebSocketMessage(conn, websocket.BinaryMessage, msgDataBytes)
}

func (c *Conn) writeWebSocketMessage(conn *websocket.Conn, messageType int, message []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if err := c.refreshWriteDeadline(conn); err != nil {
		return err
	}
	return conn.WriteMessage(messageType, message)
}

func (c *Conn) refreshWriteDeadline(conn *websocket.Conn) error {
	if conn == nil {
		return errNotConnected
	}
	if ns := c.writeDeadlineNanos.Load(); ns > 0 {
		return conn.SetWriteDeadline(time.Now().Add(time.Duration(ns)))
	}
	return conn.SetWriteDeadline(time.Time{})
}

func (c *Conn) Close() error {
	c.connMu.Lock()
	var err error
	if c.conn != nil {
		err = c.conn.Close()
		c.conn = nil
	}
	c.connMu.Unlock()
	return err
}

func (c *Conn) ShutDown() error {
	c.connMu.Lock()
	c.closed = true
	var err error
	if c.conn != nil {
		err = c.conn.Close()
		c.conn = nil
	}
	c.connCond.Signal()
	c.connMu.Unlock()

	c.sessions.Range(func(key, value any) bool {
		session := value.(*Session)
		session.Close()
		return true
	})

	return err
}

var errNotConnected = errors.New("not connected")

func (c *Conn) SetReadDeadline(timeout time.Duration) error {
	if c.conn == nil {
		return errNotConnected
	}
	return c.conn.SetReadDeadline(time.Now().Add(timeout))
}

func (c *Conn) SetWriteDeadline(timeout time.Duration) error {
	if timeout > 0 {
		c.writeDeadlineNanos.Store(timeout.Nanoseconds())
	} else {
		c.writeDeadlineNanos.Store(0)
	}
	if c.conn == nil {
		return errNotConnected
	}
	if timeout <= 0 {
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
		return c.conn.SetWriteDeadline(time.Time{})
	}
	return nil
}

func (c *Conn) SetReadLimit(limit int64) {
	if c.conn == nil {
		return
	}
	c.conn.SetReadLimit(limit)
}

func (c *Conn) SetPingHandler(handler PingPongHandler) {
	if c.conn == nil {
		return
	}
	c.conn.SetPingHandler(handler)
}

func (c *Conn) SetPongHandler(handler PingPongHandler) {
	if c.conn == nil {
		return
	}
	c.conn.SetPongHandler(handler)
}

func (c *Conn) LocalAddr() string {
	if c.conn == nil {
		return ""
	}
	return c.conn.LocalAddr().String()
}

func (c *Conn) Dial(urlStr string, requestHeader http.Header) (*http.Response, error) {
	conn, httpResp, err := websocket.DefaultDialer.Dial(urlStr, requestHeader)
	if err != nil {
		return httpResp, err
	}

	c.connMu.Lock()
	c.conn = conn
	c.connCond.Signal()
	c.connMu.Unlock()

	return httpResp, nil
}

func (c *Conn) DialAndSetUserId(urlStr string, hostId string, requestHeader http.Header) (*http.Response, error) {
	c.hostId = hostId

	conn, httpResp, err := websocket.DefaultDialer.Dial(urlStr, requestHeader)
	if err != nil {
		return httpResp, err
	}

	c.connMu.Lock()
	c.conn = conn
	c.connCond.Signal()
	c.connMu.Unlock()

	return httpResp, nil
}

func (c *Conn) IsNil() bool {
	return c.conn == nil
}

func getSessionID(A, B string) SessionID {
	if A < B {
		return SessionID(A + "_" + B)
	}
	return SessionID(B + "_" + A)
}

func (c *Conn) terminateSession(session *Session, reason error) error {
	if session == nil {
		return reason
	}

	msgData := c.imParser.ConstructMsgData(c.hostId, session.remoteId, []byte("Alert"))
	_ = c.writeRecordLocked(recordTypeAlert, msgData, session)

	session.Close()
	c.sessions.Delete(session.id)

	log.Printf("Session %s terminated: %v", session.id, reason)
	return reason
}

func (c *Conn) closeSessionLocally(session *Session, reason error) {
	if session == nil {
		return
	}
	session.Close()
	c.sessions.Delete(session.id)
	log.Printf("Session %s closed locally: %v", session.id, reason)
}

type PingPongHandler func(string) error
