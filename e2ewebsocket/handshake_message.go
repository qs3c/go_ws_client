package e2ewebsocket

import (
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

type helloMsg struct {
	original []byte

	random []byte

	cipherSuites                 []uint16
	supportedVersions            []uint16
	supportedCurves              []CurveID
	supportedSignatureAlgorithms []SignatureScheme

	secureRenegotiationSupported bool
	secureRenegotiation          []byte

	extensions []uint16
}

func (m *helloMsg) marshal() ([]byte, error) {
	var exts cryptobyte.Builder

	// 扩展1 supportedVersions
	if len(m.supportedVersions) > 0 {
		exts.AddUint16(extensionSupportedVersions)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
				for _, vers := range m.supportedVersions {
					exts.AddUint16(vers)
				}
			})
		})
	}

	// 扩展2 supportedCurves
	if len(m.supportedCurves) > 0 {
		exts.AddUint16(extensionSupportedCurves)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				for _, curve := range m.supportedCurves {
					exts.AddUint16(uint16(curve))
				}
			})
		})
	}

	extBytes, err := exts.Bytes()
	if err != nil {
		return nil, err
	}


	// 构造hello消息主体
	var b cryptobyte.Builder
	// 后续 unmarshal 时会跳过这 8+24，4字节

	// 1 消息类型
	b.AddUint8(typeHelloMsg)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		// 2 代表版本号
		b.AddUint16(m.supportedVersions[0])
		// 3 随机数
		addBytesWithLength(b, m.random, 32)
		// 4 密码套件
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, suite := range m.cipherSuites {
				b.AddUint16(suite)
			}
		})
		// // 5 压缩方法
		// b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		// 	b.AddBytes(m.compressionMethods)
		// })
		// 6 扩展
		if len(extBytes) > 0 {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(extBytes)
			})
		}
	})

	return b.Bytes()
}

func (m *helloMsg) unmarshal(data []byte) bool {

	*m = helloMsg{original: data}
	s := cryptobyte.String(data)

	// 跳过 1消息类型(1字节)和长度(3字节)
	// 读取 2代表版号(2字节)
	// 读取 3随机数(32字节)
	if !s.Skip(4) || !s.ReadUint16(&m.supportedVersions[0]) || !s.ReadBytes(&m.random, 32) {
		return false
	}

	// 读取 4密码套件(2字节长度和n个2字节套件列表)
	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return false
	}
	m.cipherSuites = []uint16{}
	m.secureRenegotiationSupported = false
	for !cipherSuites.Empty() {
		var suite uint16
		if !cipherSuites.ReadUint16(&suite) {
			return false
		}
		if suite == scsvRenegotiation {
			m.secureRenegotiationSupported = true
		}
		m.cipherSuites = append(m.cipherSuites, suite)
	}
	// // 读取 5压缩方法(1字节长度和n个1字节压缩方法列表)
	// if !readUint8LengthPrefixed(&s, &m.compressionMethods) {
	// 	return false
	// }
	// 读取 6扩展(2字节长度和n个2字节扩展列表)
	if s.Empty() {
		return true
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}

	seenExts := make(map[uint16]bool)
	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		if seenExts[extension] {
			return false
		}
		seenExts[extension] = true
		m.extensions = append(m.extensions, extension)

		switch extension {
		case extensionSupportedCurves:
			// RFC 4492, sections 5.1.1 and RFC 8446, Section 4.2.7
			var curves cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&curves) || curves.Empty() {
				return false
			}
			for !curves.Empty() {
				var curve uint16
				if !curves.ReadUint16(&curve) {
					return false
				}
				m.supportedCurves = append(m.supportedCurves, CurveID(curve))
			}
		case extensionSupportedVersions:
			// RFC 8446, Section 4.2.1
			var versList cryptobyte.String
			if !extData.ReadUint8LengthPrefixed(&versList) || versList.Empty() {
				return false
			}
			for !versList.Empty() {
				var vers uint16
				if !versList.ReadUint16(&vers) {
					return false
				}
				m.supportedVersions = append(m.supportedVersions, vers)
			}
		default:
			// Ignore unknown extensions.
			continue
		}

		if !extData.Empty() {
			return false
		}
	}

	return true
}

func (m *helloMsg) originalBytes() []byte {
	return m.original
}

// The marshalingFunction type is an adapter to allow the use of ordinary
// functions as cryptobyte.MarshalingValue.
type marshalingFunction func(b *cryptobyte.Builder) error

func (f marshalingFunction) Marshal(b *cryptobyte.Builder) error {
	return f(b)
}

// addBytesWithLength appends a sequence of bytes to the cryptobyte.Builder. If
// the length of the sequence is not the value specified, it produces an error.
func addBytesWithLength(b *cryptobyte.Builder, v []byte, n int) {
	b.AddValue(marshalingFunction(func(b *cryptobyte.Builder) error {
		if len(v) != n {
			return fmt.Errorf("invalid value length: expected %d, got %d", n, len(v))
		}
		b.AddBytes(v)
		return nil
	}))
}

func readUint24LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint24LengthPrefixed((*cryptobyte.String)(out))
}

type transcriptHash interface {
	Write([]byte) (int, error)
}

func transcriptMsg(msg handshakeMessage, h transcriptHash) error {
	// 已经有自己的原始二进制，直接写入
	if msgWithOrig, ok := msg.(handshakeMessageWithOriginalBytes); ok {
		if orig := msgWithOrig.originalBytes(); orig != nil {
			h.Write(msgWithOrig.originalBytes())
			return nil
		}
	}

	// 没有原始二进制，那就自己marshal再写入
	data, err := msg.marshal()
	if err != nil {
		return err
	}
	h.Write(data)
	return nil
}

type keyExchangeMsg struct {
	key []byte
}

func (m *keyExchangeMsg) marshal() ([]byte, error) {
	length := len(m.key)
	x := make([]byte, length+4)
	x[0] = typeKeyExchange
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	copy(x[4:], m.key)

	return x, nil

	// var b cryptobyte.Builder
    // b.AddUint8(typeKeyExchange)
    // b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
    //     b.AddBytes(m.key)
    // })
    // return b.Bytes()
}

func (m *keyExchangeMsg) unmarshal(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	m.key = data[4:]
	return true
}



type finishedMsg struct {
	verifyData []byte
}

func (m *finishedMsg) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeFinished)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(m.verifyData)
	})

	return b.Bytes()
}

func (m *finishedMsg) unmarshal(data []byte) bool {
	s := cryptobyte.String(data)
	return s.Skip(1) &&
		readUint24LengthPrefixed(&s, &m.verifyData) &&
		s.Empty()
}
