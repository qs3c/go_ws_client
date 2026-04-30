package e2ewebsocket

import (
	"testing"

	im_parser "github.com/qs3c/e2e-secure-ws/e2ewebsocket/im_parser"
)

type fakeInboundMsgData struct {
	sendID  string
	recvID  string
	content []byte
	ex      string
}

func (f *fakeInboundMsgData) GetSendID() string         { return f.sendID }
func (f *fakeInboundMsgData) GetRecvID() string         { return f.recvID }
func (f *fakeInboundMsgData) GetContent() []byte        { return f.content }
func (f *fakeInboundMsgData) SetContent(content []byte) { f.content = content }
func (f *fakeInboundMsgData) GetEx() string             { return f.ex }
func (f *fakeInboundMsgData) SetEx(ex string)           { f.ex = ex }

var _ im_parser.MsgData = (*fakeInboundMsgData)(nil)

func TestInboundPeerIDUsesRecvIDForSenderSyncCopy(t *testing.T) {
	conn := &Conn{hostId: "alice"}
	msg := &fakeInboundMsgData{sendID: "alice", recvID: "bob"}
	if got := conn.inboundPeerID(msg); got != "bob" {
		t.Fatalf("inboundPeerID() = %q, want %q", got, "bob")
	}
}

func TestShouldDropSecureSelfEcho(t *testing.T) {
	conn := &Conn{hostId: "alice"}

	if !conn.shouldDropSecureSelfEcho(&fakeInboundMsgData{sendID: "alice", recvID: "bob"}) {
		t.Fatal("expected secure sender echo to be dropped")
	}
	if conn.shouldDropSecureSelfEcho(&fakeInboundMsgData{sendID: "bob", recvID: "alice"}) {
		t.Fatal("expected peer message to be processed")
	}
	if conn.shouldDropSecureSelfEcho(&fakeInboundMsgData{sendID: "alice", recvID: "alice"}) {
		t.Fatal("expected self-chat message not to be classified as sender echo")
	}
}
