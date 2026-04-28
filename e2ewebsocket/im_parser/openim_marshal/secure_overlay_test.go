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
