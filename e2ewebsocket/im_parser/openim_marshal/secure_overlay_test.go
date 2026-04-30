package openimmarshal

import (
	"errors"
	"strings"
	"testing"

	"github.com/openimsdk/protocol/sdkws"
	imparser "github.com/qs3c/e2e-secure-ws/e2ewebsocket/im_parser"
	"github.com/qs3c/e2e-secure-ws/encoder"
	"google.golang.org/protobuf/proto"
)

type noopCompressor struct{}

func (noopCompressor) Compress(rawData []byte) ([]byte, error)          { return rawData, nil }
func (noopCompressor) CompressWithPool(rawData []byte) ([]byte, error)  { return rawData, nil }
func (noopCompressor) DeCompress(compressedData []byte) ([]byte, error) { return compressedData, nil }
func (noopCompressor) DecompressWithPool(compressedData []byte) ([]byte, error) {
	return compressedData, nil
}

func newTestParser() *OpenIMParser {
	return NewOpenIMParser(encoder.NewGobEncoder(), noopCompressor{})
}

func encodeReq(t *testing.T, req Req) []byte {
	t.Helper()
	data, err := encoder.NewGobEncoder().Encode(req)
	if err != nil {
		t.Fatalf("encode req failed: %v", err)
	}
	return data
}

func encodeResp(t *testing.T, resp Resp) []byte {
	t.Helper()
	data, err := encoder.NewGobEncoder().Encode(resp)
	if err != nil {
		t.Fatalf("encode resp failed: %v", err)
	}
	return data
}

func marshalMsgData(t *testing.T, msg *sdkws.MsgData) []byte {
	t.Helper()
	data, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal msg data failed: %v", err)
	}
	return data
}

func TestBytesToMsgDataWriteBound_SecuresTextOnly(t *testing.T) {
	parser := newTestParser()

	tests := []struct {
		name        string
		contentType int32
		wantErr     error
	}{
		{name: "text", contentType: secureTextContentType, wantErr: nil},
		{name: "typing_status", contentType: 113, wantErr: imparser.ErrBypassSecureWS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := Req{
				ReqIdentifier: 1003,
				SendID:        "alice",
				OperationID:   "op-1",
				MsgIncr:       "msg-1",
				Data: marshalMsgData(t, &sdkws.MsgData{
					SendID:      "alice",
					RecvID:      "bob",
					SessionType: 1,
					MsgFrom:     100,
					ContentType: tt.contentType,
					Content:     []byte("payload"),
				}),
			}

			msgData, err := parser.BytesToMsgDataWriteBound(encodeReq(t, req))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("unexpected error: got %v want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && msgData == nil {
				t.Fatal("expected msgData for secure text message")
			}
		})
	}
}

func TestBytesToMsgDataReadBound_DropsInternalAck(t *testing.T) {
	parser := newTestParser()

	_, err := parser.BytesToMsgDataReadBound(encodeResp(t, Resp{
		ReqIdentifier: 1003,
		OperationID:   imparser.SecureWSMarker + "op-1",
		MsgIncr:       imparser.SecureWSMarker + "msg-1",
		ErrCode:       0,
	}))
	if !errors.Is(err, imparser.ErrDropSecureWS) {
		t.Fatalf("expected ErrDropSecureWS, got %v", err)
	}
}

func TestBytesToMsgDataReadBound_AllowsInternalPushPayload(t *testing.T) {
	parser := newTestParser()
	push := sdkws.PushMessages{
		Msgs: map[string]*sdkws.PullMsgs{
			"si_alice_bob": {
				Msgs: []*sdkws.MsgData{
					{SendID: "alice", RecvID: "bob", Ex: imparser.SecureWSMarker, Content: []byte("ciphertext")},
				},
			},
		},
	}
	payload, err := proto.Marshal(&push)
	if err != nil {
		t.Fatalf("marshal push failed: %v", err)
	}

	items, err := parser.BytesToMsgDataReadBoundBatch(encodeResp(t, Resp{
		ReqIdentifier: 2001,
		OperationID:   imparser.SecureWSMarker + "op-1",
		MsgIncr:       imparser.SecureWSMarker + "msg-1",
		Data:          payload,
	}))
	if err != nil {
		t.Fatalf("BytesToMsgDataReadBoundBatch failed: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	item, ok := items[0].(*MsgData)
	if !ok {
		t.Fatalf("expected *MsgData, got %T", items[0])
	}
	if !item.IsSecureReadBound() {
		t.Fatal("expected internal push payload to remain secure")
	}
}

func TestConstructMsgData_UsesTransientOptions(t *testing.T) {
	parser := newTestParser()

	msgData, ok := parser.ConstructMsgData("alice", "bob", []byte("hello")).(*MsgData)
	if !ok {
		t.Fatal("expected openim msgData wrapper")
	}
	if msgData.OfflinePushInfo != nil {
		t.Fatal("secure control message should not carry offline push info")
	}

	for key, want := range secureControlOptions {
		if got := msgData.Options[key]; got != want {
			t.Fatalf("option %q: got %v want %v", key, got, want)
		}
	}
}

func TestMsgDataToBytesWriteBound_TagsInternalReqIDs(t *testing.T) {
	parser := newTestParser()

	wire, err := parser.MsgDataToBytesWriteBound(parser.ConstructMsgData("alice", "bob", []byte("hello")))
	if err != nil {
		t.Fatalf("MsgDataToBytesWriteBound failed: %v", err)
	}

	var req Req
	if err := encoder.NewGobEncoder().Decode(wire, &req); err != nil {
		t.Fatalf("decode req failed: %v", err)
	}
	if !strings.HasPrefix(req.OperationID, imparser.SecureWSMarker) {
		t.Fatalf("operationID missing secure marker: %q", req.OperationID)
	}
	if !strings.HasPrefix(req.MsgIncr, imparser.SecureWSMarker) {
		t.Fatalf("msgIncr missing secure marker: %q", req.MsgIncr)
	}
}

func TestBytesToMsgDataReadBoundBatch_SplitsMixedPushMessages(t *testing.T) {
	parser := newTestParser()
	push := sdkws.PushMessages{
		Msgs: map[string]*sdkws.PullMsgs{
			"si_alice_bob": {
				Msgs: []*sdkws.MsgData{
					{SendID: "alice", RecvID: "bob", Ex: imparser.SecureWSMarker, Content: []byte("ciphertext")},
					{SendID: "system", RecvID: "alice", Ex: "", Content: []byte("plain")},
				},
			},
		},
	}
	payload, err := proto.Marshal(&push)
	if err != nil {
		t.Fatalf("marshal push failed: %v", err)
	}

	items, err := parser.BytesToMsgDataReadBoundBatch(encodeResp(t, Resp{ReqIdentifier: 2001, Data: payload}))
	if err != nil {
		t.Fatalf("BytesToMsgDataReadBoundBatch failed: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}

	first, ok := items[0].(*MsgData)
	if !ok {
		t.Fatalf("expected first item to be *MsgData, got %T", items[0])
	}
	second, ok := items[1].(*MsgData)
	if !ok {
		t.Fatalf("expected second item to be *MsgData, got %T", items[1])
	}
	if !first.IsSecureReadBound() {
		t.Fatal("expected first item to be marked secure")
	}
	if first.GetEx() != "" {
		t.Fatalf("expected secure marker to be trimmed, got %q", first.GetEx())
	}
	if second.IsSecureReadBound() {
		t.Fatal("expected second item to remain non-secure")
	}
}

func TestMsgDataToBytesReadBound_PreservesRealtimeConversationBucket(t *testing.T) {
	parser := newTestParser()
	push := sdkws.PushMessages{
		Msgs: map[string]*sdkws.PullMsgs{
			"si_alice_bob": {
				Msgs: []*sdkws.MsgData{
					{SendID: "alice", RecvID: "bob", Ex: imparser.SecureWSMarker, Content: []byte("ciphertext")},
				},
			},
		},
	}
	payload, err := proto.Marshal(&push)
	if err != nil {
		t.Fatalf("marshal push failed: %v", err)
	}

	items, err := parser.BytesToMsgDataReadBoundBatch(encodeResp(t, Resp{ReqIdentifier: 2001, Data: payload}))
	if err != nil {
		t.Fatalf("BytesToMsgDataReadBoundBatch failed: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}

	item := items[0].(*MsgData)
	item.SetContent([]byte(`{"content":"hello"}`))
	wire, err := parser.MsgDataToBytesReadBound(item)
	if err != nil {
		t.Fatalf("MsgDataToBytesReadBound failed: %v", err)
	}

	var resp Resp
	if err := encoder.NewGobEncoder().Decode(wire, &resp); err != nil {
		t.Fatalf("decode resp failed: %v", err)
	}
	var forwarded sdkws.PushMessages
	if err := proto.Unmarshal(resp.Data, &forwarded); err != nil {
		t.Fatalf("unmarshal forwarded push failed: %v", err)
	}
	if _, ok := forwarded.GetMsgs()["bob"]; ok {
		t.Fatal("decrypted realtime push should not be bucketed by receiver userID")
	}
	pullMsg := forwarded.GetMsgs()["si_alice_bob"]
	if pullMsg == nil || len(pullMsg.Msgs) != 1 {
		t.Fatalf("expected original conversation bucket to be preserved, got %#v", forwarded.GetMsgs())
	}
	if string(pullMsg.Msgs[0].Content) != `{"content":"hello"}` {
		t.Fatalf("unexpected forwarded content: %q", string(pullMsg.Msgs[0].Content))
	}
}

func TestBytesToMsgDataReadBoundBatch_UsesRealtimeCacheForFollowupSync(t *testing.T) {
	parser := newTestParser()
	realtimePush := sdkws.PushMessages{
		Msgs: map[string]*sdkws.PullMsgs{
			"si_alice_bob": {
				Msgs: []*sdkws.MsgData{
					{
						SendID:      "alice",
						RecvID:      "bob",
						ClientMsgID: "client-20",
						ServerMsgID: "server-20",
						Seq:         20,
						Ex:          imparser.SecureWSMarker,
						Content:     []byte("ciphertext"),
					},
				},
			},
		},
	}
	realtimePayload, err := proto.Marshal(&realtimePush)
	if err != nil {
		t.Fatalf("marshal realtime push failed: %v", err)
	}
	items, err := parser.BytesToMsgDataReadBoundBatch(encodeResp(t, Resp{ReqIdentifier: 2001, Data: realtimePayload}))
	if err != nil {
		t.Fatalf("BytesToMsgDataReadBoundBatch realtime failed: %v", err)
	}
	realtimeItem := items[0].(*MsgData)
	realtimeItem.ContentType = secureTextContentType
	realtimeItem.SetContent([]byte(`{"content":"hello"}`))
	if _, err := parser.MsgDataToBytesReadBound(realtimeItem); err != nil {
		t.Fatalf("MsgDataToBytesReadBound realtime failed: %v", err)
	}

	syncPush := sdkws.PushMessages{
		Msgs: map[string]*sdkws.PullMsgs{
			"si_alice_bob": {
				Msgs: []*sdkws.MsgData{
					{SendID: "alice", RecvID: "bob", Seq: 19, Ex: imparser.SecureWSMarker, Content: []byte("old-ciphertext")},
					{SendID: "alice", RecvID: "bob", ClientMsgID: "client-20", ServerMsgID: "server-20", Seq: 20, Ex: imparser.SecureWSMarker, Content: []byte("ciphertext")},
				},
			},
		},
	}
	syncPayload, err := proto.Marshal(&syncPush)
	if err != nil {
		t.Fatalf("marshal sync push failed: %v", err)
	}

	syncItems, err := parser.BytesToMsgDataReadBoundBatch(encodeResp(t, Resp{ReqIdentifier: 1002, Data: syncPayload}))
	if err != nil {
		t.Fatalf("BytesToMsgDataReadBoundBatch sync failed: %v", err)
	}
	if len(syncItems) != 1 {
		t.Fatalf("expected 1 sync item, got %d", len(syncItems))
	}
	syncWire, err := parser.MsgDataToBytesReadBound(syncItems[0])
	if err != nil {
		t.Fatalf("MsgDataToBytesReadBound sync failed: %v", err)
	}

	var resp Resp
	if err := encoder.NewGobEncoder().Decode(syncWire, &resp); err != nil {
		t.Fatalf("decode sync resp failed: %v", err)
	}
	var forwarded sdkws.PushMessages
	if err := proto.Unmarshal(resp.Data, &forwarded); err != nil {
		t.Fatalf("unmarshal forwarded sync failed: %v", err)
	}
	pullMsg := forwarded.GetMsgs()["si_alice_bob"]
	if pullMsg == nil || len(pullMsg.Msgs) != 1 {
		t.Fatalf("expected only cached realtime message to be forwarded, got %#v", pullMsg)
	}
	msg := pullMsg.Msgs[0]
	if msg.Seq != 20 {
		t.Fatalf("expected seq 20, got %d", msg.Seq)
	}
	if string(msg.Content) != `{"content":"hello"}` {
		t.Fatalf("expected decrypted content, got %q", string(msg.Content))
	}
	if strings.HasPrefix(msg.Ex, imparser.SecureWSMarker) {
		t.Fatalf("expected secure marker to be stripped from cached message, got %q", msg.Ex)
	}
}

func TestBytesToMsgDataReadBoundBatch_SanitizesSyncedSecureMessages(t *testing.T) {
	parser := newTestParser()
	push := sdkws.PushMessages{
		Msgs: map[string]*sdkws.PullMsgs{
			"si_alice_bob": {
				Msgs: []*sdkws.MsgData{
					{SendID: "alice", RecvID: "bob", Ex: imparser.SecureWSMarker, Content: []byte("ciphertext")},
					{SendID: "system", RecvID: "alice", Ex: "", Content: []byte("plain")},
				},
			},
		},
	}
	payload, err := proto.Marshal(&push)
	if err != nil {
		t.Fatalf("marshal push failed: %v", err)
	}

	items, err := parser.BytesToMsgDataReadBoundBatch(encodeResp(t, Resp{
		ReqIdentifier: 1002,
		OperationID:   "sync-op",
		MsgIncr:       "sync-incr",
		Data:          payload,
	}))
	if err != nil {
		t.Fatalf("BytesToMsgDataReadBoundBatch failed: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 sanitized sync response, got %d", len(items))
	}

	item, ok := items[0].(*MsgData)
	if !ok {
		t.Fatalf("expected *MsgData, got %T", items[0])
	}
	if item.IsSecureReadBound() {
		t.Fatal("sync response should not be treated as secure realtime data")
	}
	if item.MsgData != nil {
		t.Fatal("sanitized sync response should forward the whole push envelope")
	}
	pullMsg := item.PushMsg.GetMsgs()["si_alice_bob"]
	if pullMsg == nil || len(pullMsg.Msgs) != 1 {
		t.Fatalf("expected only the non-secure message to remain, got %#v", pullMsg)
	}
	if string(pullMsg.Msgs[0].Content) != "plain" {
		t.Fatalf("unexpected forwarded content: %q", string(pullMsg.Msgs[0].Content))
	}

	wire, err := parser.MsgDataToBytesReadBound(item)
	if err != nil {
		t.Fatalf("MsgDataToBytesReadBound failed: %v", err)
	}
	var resp Resp
	if err := encoder.NewGobEncoder().Decode(wire, &resp); err != nil {
		t.Fatalf("decode resp failed: %v", err)
	}
	if resp.ReqIdentifier != 1002 || resp.OperationID != "sync-op" || resp.MsgIncr != "sync-incr" {
		t.Fatalf("unexpected response metadata: %#v", resp)
	}

	var forwarded sdkws.PushMessages
	if err := proto.Unmarshal(resp.Data, &forwarded); err != nil {
		t.Fatalf("unmarshal forwarded push failed: %v", err)
	}
	forwardedPull := forwarded.GetMsgs()["si_alice_bob"]
	if forwardedPull == nil || len(forwardedPull.Msgs) != 1 {
		t.Fatalf("expected re-encoded response to keep only plain message, got %#v", forwardedPull)
	}
}

func TestBytesToMsgDataReadBoundBatch_ForwardsEmptySanitizedSyncResponse(t *testing.T) {
	parser := newTestParser()
	push := sdkws.PushMessages{
		Msgs: map[string]*sdkws.PullMsgs{
			"si_alice_bob": {
				Msgs: []*sdkws.MsgData{
					{SendID: "alice", RecvID: "bob", Ex: imparser.SecureWSMarker, Content: []byte("ciphertext")},
				},
			},
		},
	}
	payload, err := proto.Marshal(&push)
	if err != nil {
		t.Fatalf("marshal push failed: %v", err)
	}

	items, err := parser.BytesToMsgDataReadBoundBatch(encodeResp(t, Resp{ReqIdentifier: 1002, Data: payload}))
	if err != nil {
		t.Fatalf("BytesToMsgDataReadBoundBatch failed: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 sanitized sync response, got %d", len(items))
	}
	item := items[0].(*MsgData)
	pullMsg := item.PushMsg.GetMsgs()["si_alice_bob"]
	if pullMsg == nil {
		t.Fatal("expected original conversation bucket to be preserved")
	}
	if len(pullMsg.Msgs) != 0 {
		t.Fatalf("expected secure-only sync bucket to be emptied, got %d messages", len(pullMsg.Msgs))
	}
	if _, err := parser.MsgDataToBytesReadBound(item); err != nil {
		t.Fatalf("MsgDataToBytesReadBound should encode empty sanitized sync response: %v", err)
	}
}
