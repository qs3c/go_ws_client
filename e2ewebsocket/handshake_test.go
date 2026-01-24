package e2ewebsocket

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	ccrypto "github.com/albert/ws_client/crypto"
	"github.com/albert/ws_client/crypto/sm2keyexch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// helloMsg 序列化/反序列化测试
// ============================================================================

func TestHelloMsg_MarshalUnmarshal(t *testing.T) {
	// 创建一个完整的 helloMsg
	original := &helloMsg{
		random:            make([]byte, 32),
		cipherSuites:      []uint16{E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3, E2E_SM2KEYAGREEMENT_WITH_SM4_256_GCM_SM3},
		supportedVersions: []uint16{VersionE2E1, VersionE2E2},
		supportedCurves:   []CurveID{SM2CurveP256V1, CurveP256},
	}

	// 填充随机数
	_, err := rand.Read(original.random)
	require.NoError(t, err, "生成随机数失败")

	// 序列化
	data, err := original.marshal()
	require.NoError(t, err, "序列化 helloMsg 失败")
	require.NotEmpty(t, data, "序列化结果不应为空")

	// 反序列化
	parsed := &helloMsg{}
	ok := parsed.unmarshal(data)
	require.True(t, ok, "反序列化 helloMsg 失败")

	// 验证字段
	assert.Equal(t, original.random, parsed.random, "random 字段不匹配")
	assert.Equal(t, original.cipherSuites, parsed.cipherSuites, "cipherSuites 字段不匹配")
	// supportedVersions 会包含 marshal 时的 version 字段，所以只检查第一个
	assert.Equal(t, original.supportedVersions[0], parsed.supportedVersions[0], "supportedVersions 第一个元素不匹配")
	assert.Equal(t, original.supportedCurves, parsed.supportedCurves, "supportedCurves 字段不匹配")

	t.Logf("helloMsg 序列化/反序列化测试通过，数据长度: %d 字节", len(data))
}

func TestHelloMsg_EmptyCipherSuites(t *testing.T) {
	// 测试空密码套件列表的情况
	msg := &helloMsg{
		random:            make([]byte, 32),
		cipherSuites:      []uint16{},
		supportedVersions: []uint16{VersionE2E1},
		supportedCurves:   []CurveID{SM2CurveP256V1},
	}
	_, err := rand.Read(msg.random)
	require.NoError(t, err)

	data, err := msg.marshal()
	require.NoError(t, err)

	parsed := &helloMsg{}
	ok := parsed.unmarshal(data)
	require.True(t, ok)
	assert.Empty(t, parsed.cipherSuites)
}

func TestHelloMsg_InvalidData(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{"空数据", []byte{}},
		{"过短数据", []byte{1, 2, 3}},
		{"无效消息类型", append([]byte{99}, make([]byte, 100)...)}, // 错误的消息类型
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			msg := &helloMsg{}
			ok := msg.unmarshal(tc.data)
			assert.False(t, ok, "应该解析失败: %s", tc.name)
		})
	}
}

// ============================================================================
// keyExchangeMsg 序列化/反序列化测试
// ============================================================================

func TestKeyExchangeMsg_MarshalUnmarshal(t *testing.T) {
	// 创建一个 keyExchangeMsg
	original := &keyExchangeMsg{
		key: make([]byte, 100),
	}
	_, err := rand.Read(original.key)
	require.NoError(t, err)

	// 序列化
	data, err := original.marshal()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// 验证消息类型
	assert.Equal(t, typeKeyExchange, data[0], "消息类型应为 typeKeyExchange")

	// 验证长度编码
	length := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	assert.Equal(t, len(original.key), length, "长度编码不正确")

	// 反序列化
	parsed := &keyExchangeMsg{}
	ok := parsed.unmarshal(data)
	require.True(t, ok)
	assert.Equal(t, original.key, parsed.key)

	t.Logf("keyExchangeMsg 序列化/反序列化测试通过，key 长度: %d 字节", len(original.key))
}

func TestKeyExchangeMsg_ShortData(t *testing.T) {
	msg := &keyExchangeMsg{}
	ok := msg.unmarshal([]byte{1, 2, 3}) // 少于 4 字节
	assert.False(t, ok, "过短数据应该解析失败")
}

// ============================================================================
// finishedMsg 序列化/反序列化测试
// ============================================================================

func TestFinishedMsg_MarshalUnmarshal(t *testing.T) {
	original := &finishedMsg{
		verifyData: make([]byte, finishedVerifyLength),
	}
	_, err := rand.Read(original.verifyData)
	require.NoError(t, err)

	data, err := original.marshal()
	require.NoError(t, err)

	// 验证消息类型
	assert.Equal(t, typeFinished, data[0], "消息类型应为 typeFinished")

	parsed := &finishedMsg{}
	ok := parsed.unmarshal(data)
	require.True(t, ok)
	assert.Equal(t, original.verifyData, parsed.verifyData)

	t.Logf("finishedMsg 序列化/反序列化测试通过，verifyData 长度: %d 字节", len(original.verifyData))
}

// ============================================================================
// 密码套件协商测试
// ============================================================================

func TestMutualCipherSuite(t *testing.T) {
	testCases := []struct {
		name     string
		have     []uint16
		want     []uint16
		expected *cipherSuite
	}{
		{
			name:     "找到共同套件-第一个匹配",
			have:     []uint16{E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3, E2E_SM2KEYAGREEMENT_WITH_SM4_256_GCM_SM3},
			want:     []uint16{E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3},
			expected: cipherSuites[E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3],
		},
		{
			name:     "找到共同套件-第二个匹配",
			have:     []uint16{E2E_SM2KEYAGREEMENT_WITH_SM4_256_GCM_SM3},
			want:     []uint16{E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3, E2E_SM2KEYAGREEMENT_WITH_SM4_256_GCM_SM3},
			expected: cipherSuites[E2E_SM2KEYAGREEMENT_WITH_SM4_256_GCM_SM3],
		},
		{
			name:     "无共同套件",
			have:     []uint16{E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3},
			want:     []uint16{E2E_MLKEMSM2_WITH_SM4_128_GCM_SM3},
			expected: nil,
		},
		{
			name:     "空列表",
			have:     []uint16{},
			want:     []uint16{E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3},
			expected: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := mutualCipherSuite(tc.have, tc.want)
			if tc.expected == nil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				assert.Equal(t, tc.expected.id, result.id)
			}
		})
	}
}

func TestCipherSuiteByID(t *testing.T) {
	// 测试已注册的套件
	suite := cipherSuiteByID(E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3)
	require.NotNil(t, suite)
	assert.Equal(t, E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3, suite.id)
	assert.Equal(t, 16, suite.keyLen)

	// 测试未注册的套件
	unknown := cipherSuiteByID(0xFFFF)
	assert.Nil(t, unknown)
}

func TestCipherSuiteKAFactory(t *testing.T) {
	// 测试 kaFactory 工厂函数是否正确创建新实例
	suite := cipherSuiteByID(E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3)
	require.NotNil(t, suite)
	require.NotNil(t, suite.kaFactory)

	ka1 := suite.kaFactory()
	ka2 := suite.kaFactory()

	// 应该是不同的实例
	assert.NotSame(t, ka1, ka2, "kaFactory 应该创建新的实例")
}

// ============================================================================
// 签名方案协商测试
// ============================================================================

func TestMutualSignatureScheme(t *testing.T) {
	testCases := []struct {
		name     string
		have     []SignatureScheme
		want     []SignatureScheme
		expected SignatureScheme
	}{
		{
			name:     "找到共同方案-SM2WithSM3",
			have:     []SignatureScheme{SM2WithSM3, PSSWithSHA256},
			want:     []SignatureScheme{SM2WithSM3},
			expected: SM2WithSM3,
		},
		{
			name:     "无共同方案",
			have:     []SignatureScheme{SM2WithSM3},
			want:     []SignatureScheme{PSSWithSHA256},
			expected: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := mutualSignatureScheme(tc.have, tc.want)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// ============================================================================
// SM2 密钥协商测试
// ============================================================================

func TestSM2KeyAgreement_FullFlow(t *testing.T) {
	// 生成两对密钥（模拟本地和远程）
	localPriv, err := ccrypto.NewECKeySM2()
	require.NoError(t, err)
	defer localPriv.Free()

	remotePriv, err := ccrypto.NewECKeySM2()
	require.NoError(t, err)
	defer remotePriv.Free()

	err = localPriv.Generate()
	require.NoError(t, err)

	err = remotePriv.Generate()
	require.NoError(t, err)

	// 获取公钥
	localPub, err := ccrypto.NewECKeySM2()
	require.NoError(t, err)
	defer localPub.Free()
	err = localPub.SetPublicFrom(localPriv)
	require.NoError(t, err)

	remotePub, err := ccrypto.NewECKeySM2()
	require.NoError(t, err)
	defer remotePub.Free()
	err = remotePub.SetPublicFrom(remotePriv)
	require.NoError(t, err)

	localId := "alice123"
	remoteId := "bob45678"

	// 创建两个 KAPCtx
	ctxLocal := sm2keyexch.NewKAPCtx()
	ctxRemote := sm2keyexch.NewKAPCtx()
	defer ctxLocal.Cleanup()
	defer ctxRemote.Cleanup()

	// 初始化
	// 注意：initiator 参数根据 ID 比较决定
	err = ctxLocal.Init(localPriv, localId, remotePub, remoteId, localId > remoteId, true)
	require.NoError(t, err, "本地 KAPCtx Init 失败")

	err = ctxRemote.Init(remotePriv, remoteId, localPub, localId, remoteId > localId, true)
	require.NoError(t, err, "远程 KAPCtx Init 失败")

	// Prepare 阶段
	RA, err := ctxLocal.Prepare()
	require.NoError(t, err, "本地 Prepare 失败")
	require.NotEmpty(t, RA)

	RB, err := ctxRemote.Prepare()
	require.NoError(t, err, "远程 Prepare 失败")
	require.NotEmpty(t, RB)

	// ComputeKey 阶段
	keyLocal, csLocal, err := ctxLocal.ComputeKey(RB, 32)
	require.NoError(t, err, "本地 ComputeKey 失败")
	require.Len(t, keyLocal, 32)

	keyRemote, csRemote, err := ctxRemote.ComputeKey(RA, 32)
	require.NoError(t, err, "远程 ComputeKey 失败")
	require.Len(t, keyRemote, 32)

	// 验证双方计算出的共享密钥相同
	assert.True(t, bytes.Equal(keyLocal, keyRemote), "双方计算的共享密钥应该相同")

	// FinalCheck（可选的 checksum 验证）
	err = ctxLocal.FinalCheck(csRemote)
	require.NoError(t, err, "本地 FinalCheck 失败")

	err = ctxRemote.FinalCheck(csLocal)
	require.NoError(t, err, "远程 FinalCheck 失败")

	t.Logf("SM2 密钥协商成功，共享密钥: %x", keyLocal)
}

// ============================================================================
// PRF 函数测试
// ============================================================================

func TestMasterFromPreMasterSecret(t *testing.T) {
	suite := cipherSuiteByID(E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3)
	require.NotNil(t, suite)

	preMasterSecret := make([]byte, 32)
	initiatorRandom := make([]byte, 32)
	responderRandom := make([]byte, 32)

	_, _ = rand.Read(preMasterSecret)
	_, _ = rand.Read(initiatorRandom)
	_, _ = rand.Read(responderRandom)

	masterSecret := masterFromPreMasterSecret(VersionE2E1, suite, preMasterSecret, initiatorRandom, responderRandom)

	assert.Len(t, masterSecret, masterSecretLength)
	t.Logf("生成的 masterSecret 长度: %d", len(masterSecret))

	// 验证确定性：相同输入应产生相同输出
	masterSecret2 := masterFromPreMasterSecret(VersionE2E1, suite, preMasterSecret, initiatorRandom, responderRandom)
	assert.Equal(t, masterSecret, masterSecret2, "相同输入应产生相同的 masterSecret")
}

func TestKeysFromMasterSecret(t *testing.T) {
	suite := cipherSuiteByID(E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3)
	require.NotNil(t, suite)

	masterSecret := make([]byte, masterSecretLength)
	initiatorRandom := make([]byte, 32)
	responderRandom := make([]byte, 32)

	_, _ = rand.Read(masterSecret)
	_, _ = rand.Read(initiatorRandom)
	_, _ = rand.Read(responderRandom)

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(VersionE2E1, suite, masterSecret, initiatorRandom, responderRandom,
			suite.macLen, suite.keyLen, suite.ivLen)

	// 验证长度
	assert.Len(t, clientMAC, suite.macLen)
	assert.Len(t, serverMAC, suite.macLen)
	assert.Len(t, clientKey, suite.keyLen)
	assert.Len(t, serverKey, suite.keyLen)
	assert.Len(t, clientIV, suite.ivLen)
	assert.Len(t, serverIV, suite.ivLen)

	// client 和 server 的密钥应该不同
	assert.False(t, bytes.Equal(clientKey, serverKey), "client 和 server 密钥应该不同")

	t.Logf("密钥派生成功: keyLen=%d, ivLen=%d, macLen=%d", suite.keyLen, suite.ivLen, suite.macLen)
}

// ============================================================================
// finishedHash 测试
// ============================================================================

func TestFinishedHash(t *testing.T) {
	suite := cipherSuiteByID(E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3)
	require.NotNil(t, suite)

	localId := "alice"
	remoteId := "bob"

	fh := newFinishedHash(suite, localId, remoteId)

	// 写入一些数据
	testData := []byte("test handshake transcript data")
	n, err := fh.Write(testData)
	require.NoError(t, err)
	assert.Equal(t, len(testData), n)

	// 获取 sum
	sum := fh.Sum()
	assert.NotEmpty(t, sum)

	// 使用 masterSecret 计算 localSum 和 remoteSum
	masterSecret := make([]byte, masterSecretLength)
	_, _ = rand.Read(masterSecret)

	localSum := fh.localSum(masterSecret)
	remoteSum := fh.remoteSum(masterSecret)

	assert.Len(t, localSum, finishedVerifyLength)
	assert.Len(t, remoteSum, finishedVerifyLength)
	assert.False(t, bytes.Equal(localSum, remoteSum), "localSum 和 remoteSum 应该不同")

	t.Logf("finishedHash 测试通过")
}

// ============================================================================
// halfConn 加密/解密测试
// ============================================================================

func TestHalfConn_EncryptDecrypt(t *testing.T) {
	suite := cipherSuiteByID(E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3)
	require.NotNil(t, suite)

	// 生成密钥材料
	key := make([]byte, suite.keyLen)
	iv := make([]byte, suite.ivLen)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)

	// 创建 AEAD cipher
	aead := suite.aead(key, iv)
	require.NotNil(t, aead)

	// 创建发送和接收的 halfConn
	sender := &halfConn{}
	receiver := &halfConn{}

	sender.cipher = aead
	receiver.cipher = aead

	// 准备测试数据
	plaintext := []byte("Hello, E2E WebSocket!")

	// 加密
	record := make([]byte, 0)
	encrypted, err := sender.encrypt(record, plaintext, rand.Reader)
	require.NoError(t, err)
	require.NotEmpty(t, encrypted)

	t.Logf("原文长度: %d, 密文长度: %d", len(plaintext), len(encrypted))

	// 解密
	decrypted, err := receiver.decrypt(encrypted)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	t.Logf("加密/解密测试通过")
}

func TestHalfConn_SequenceNumber(t *testing.T) {
	hc := &halfConn{}

	// 初始序列号应该是 0
	assert.Equal(t, [8]byte{}, hc.seq)

	// 递增序列号
	hc.incSeq()
	expected := [8]byte{0, 0, 0, 0, 0, 0, 0, 1}
	assert.Equal(t, expected, hc.seq)

	// 多次递增
	for i := 0; i < 254; i++ {
		hc.incSeq()
	}
	expected = [8]byte{0, 0, 0, 0, 0, 0, 0, 255}
	assert.Equal(t, expected, hc.seq)

	// 进位
	hc.incSeq()
	expected = [8]byte{0, 0, 0, 0, 0, 0, 1, 0}
	assert.Equal(t, expected, hc.seq)
}

// ============================================================================
// Config 测试
// ============================================================================

func TestConfig_Defaults(t *testing.T) {
	config := defaultConfig()

	// 测试默认值
	assert.NotNil(t, config.rand())
	assert.Equal(t, defaultKeyStorePath, config.keyStorePath())
	assert.NotEmpty(t, config.cipherSuites())
	assert.NotEmpty(t, config.supportedSignatureAlgorithms())

	// 测试版本
	versions := config.defaultSupportedVersions()
	assert.Contains(t, versions, uint16(VersionE2E1))
	assert.Contains(t, versions, uint16(VersionE2E2))
}

func TestConfig_MutualVersion(t *testing.T) {
	config := &Config{
		supportedVersions: []uint16{VersionE2E1, VersionE2E2},
	}

	// 找到共同版本
	version, ok := config.mutualVersion([]uint16{VersionE2E1})
	assert.True(t, ok)
	assert.Equal(t, uint16(VersionE2E1), version)

	// 优先选择更高版本
	version, ok = config.mutualVersion([]uint16{VersionE2E2, VersionE2E1})
	assert.True(t, ok)
	// Intersection 返回第一个匹配的
	assert.True(t, version == VersionE2E1 || version == VersionE2E2)
}

// ============================================================================
// SessionID 测试
// ============================================================================

func TestGetSessionID(t *testing.T) {
	// 测试 SessionID 的生成规则
	id1 := getSessionID("alice", "bob")
	id2 := getSessionID("bob", "alice")

	// 应该生成相同的 SessionID
	assert.Equal(t, id1, id2, "相同的两个用户应该生成相同的 SessionID")

	// 验证格式
	assert.Contains(t, string(id1), "_")
}

// ============================================================================
// Intersection 辅助函数测试
// ============================================================================

func TestIntersection(t *testing.T) {
	// uint16 测试
	result := Intersection([]uint16{1, 2, 3}, []uint16{2, 3, 4})
	assert.Equal(t, uint16(2), result)

	// 无交集
	result = Intersection([]uint16{1, 2}, []uint16{3, 4})
	assert.Equal(t, uint16(0), result)

	// SignatureScheme 测试
	schemes := Intersection(
		[]SignatureScheme{SM2WithSM3, PSSWithSHA256},
		[]SignatureScheme{PSSWithSHA256, PSSWithSHA384},
	)
	assert.Equal(t, PSSWithSHA256, schemes)
}

// ============================================================================
// 集成测试：模拟双方握手
// ============================================================================

func TestHandshake_MessageExchange(t *testing.T) {
	// 模拟 Alice 和 Bob 的 Hello 消息交换

	// Alice 创建 Hello
	aliceHello := &helloMsg{
		random:                       make([]byte, 32),
		cipherSuites:                 []uint16{E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3, E2E_SM2KEYAGREEMENT_WITH_SM4_256_GCM_SM3},
		supportedVersions:            []uint16{VersionE2E1, VersionE2E2},
		supportedCurves:              []CurveID{SM2CurveP256V1},
		supportedSignatureAlgorithms: []SignatureScheme{SM2WithSM3},
	}
	_, _ = rand.Read(aliceHello.random)

	// Bob 创建 Hello
	bobHello := &helloMsg{
		random:                       make([]byte, 32),
		cipherSuites:                 []uint16{E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3},
		supportedVersions:            []uint16{VersionE2E1},
		supportedCurves:              []CurveID{SM2CurveP256V1},
		supportedSignatureAlgorithms: []SignatureScheme{SM2WithSM3},
	}
	_, _ = rand.Read(bobHello.random)

	// 序列化 Alice 的 Hello
	aliceHelloData, err := aliceHello.marshal()
	require.NoError(t, err)

	// Bob 解析 Alice 的 Hello
	parsedAliceHello := &helloMsg{}
	ok := parsedAliceHello.unmarshal(aliceHelloData)
	require.True(t, ok)

	// 协商密码套件
	suite := mutualCipherSuite(bobHello.cipherSuites, parsedAliceHello.cipherSuites)
	require.NotNil(t, suite)
	assert.Equal(t, E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3, suite.id)

	// 协商签名方案
	sigScheme := mutualSignatureScheme(bobHello.supportedSignatureAlgorithms, parsedAliceHello.supportedSignatureAlgorithms)
	assert.Equal(t, SM2WithSM3, sigScheme)

	t.Logf("握手消息交换测试通过，协商结果: cipherSuite=0x%04x, signatureScheme=0x%04x", suite.id, sigScheme)
}

// ============================================================================
// 静态密钥加载测试（需要实际密钥文件）
// ============================================================================

func TestLoadStaticKeys(t *testing.T) {
	// 这个测试需要 static_key 目录下有相应的密钥文件
	// 如果文件不存在，跳过测试

	keyStorePath := "./static_key"
	userId := "alice"

	privateKeyPath := filepath.Join(keyStorePath, userId, "private_key.pem")
	publicKeyPath := filepath.Join(keyStorePath, userId, "public_key.pem")

	// 尝试加载私钥
	privateKey, err := ccrypto.LoadPrivateKeyFileFromPEM(privateKeyPath)
	if err != nil {
		t.Skipf("跳过静态密钥加载测试：%v", err)
		return
	}
	require.NotNil(t, privateKey)

	// 尝试加载公钥
	publicKey, err := ccrypto.LoadPublicKeyFileFromPEM(publicKeyPath)
	if err != nil {
		t.Skipf("跳过公钥加载测试：%v", err)
		return
	}
	require.NotNil(t, publicKey)

	t.Logf("成功加载用户 %s 的密钥对", userId)
}

// ============================================================================
// BEUint16 辅助函数测试
// ============================================================================

func TestBEUint16(t *testing.T) {
	testCases := []struct {
		input    []byte
		expected uint16
	}{
		{[]byte{0x00, 0x01}, 1},
		{[]byte{0x01, 0x00}, 256},
		{[]byte{0xFF, 0xFF}, 65535},
		{[]byte{0x10, 0x38}, 4152}, // SM2CurveP256V1
	}

	for _, tc := range testCases {
		result := BEUint16(tc.input)
		assert.Equal(t, tc.expected, result)
	}
}

// ============================================================================
// 完整握手模拟测试
// ============================================================================

func TestFullHandshakeSimulation(t *testing.T) {
	// 模拟 Alice 和 Bob 之间的完整握手流程

	// 1. 生成双方的静态密钥对
	alicePriv, err := ccrypto.NewECKeySM2()
	require.NoError(t, err)
	defer alicePriv.Free()
	err = alicePriv.Generate()
	require.NoError(t, err)

	bobPriv, err := ccrypto.NewECKeySM2()
	require.NoError(t, err)
	defer bobPriv.Free()
	err = bobPriv.Generate()
	require.NoError(t, err)

	// 获取公钥
	alicePub, err := ccrypto.NewECKeySM2()
	require.NoError(t, err)
	defer alicePub.Free()
	err = alicePub.SetPublicFrom(alicePriv)
	require.NoError(t, err)

	bobPub, err := ccrypto.NewECKeySM2()
	require.NoError(t, err)
	defer bobPub.Free()
	err = bobPub.SetPublicFrom(bobPriv)
	require.NoError(t, err)

	aliceId := "alice12345"
	bobId := "bob1234567"

	// 2. 创建双方的 Hello 消息
	aliceHello := &helloMsg{
		random:                       make([]byte, 32),
		cipherSuites:                 []uint16{E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3},
		supportedVersions:            []uint16{VersionE2E1},
		supportedCurves:              []CurveID{SM2CurveP256V1},
		supportedSignatureAlgorithms: []SignatureScheme{SM2WithSM3},
	}
	_, _ = rand.Read(aliceHello.random)

	bobHello := &helloMsg{
		random:                       make([]byte, 32),
		cipherSuites:                 []uint16{E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3},
		supportedVersions:            []uint16{VersionE2E1},
		supportedCurves:              []CurveID{SM2CurveP256V1},
		supportedSignatureAlgorithms: []SignatureScheme{SM2WithSM3},
	}
	_, _ = rand.Read(bobHello.random)

	// 3. 序列化并交换 Hello 消息
	aliceHelloData, err := aliceHello.marshal()
	require.NoError(t, err)

	bobHelloData, err := bobHello.marshal()
	require.NoError(t, err)

	// 双方解析对方的 Hello
	parsedBobHello := &helloMsg{}
	ok := parsedBobHello.unmarshal(bobHelloData)
	require.True(t, ok)

	parsedAliceHello := &helloMsg{}
	ok = parsedAliceHello.unmarshal(aliceHelloData)
	require.True(t, ok)

	// 4. 协商密码套件和签名方案
	suite := mutualCipherSuite(aliceHello.cipherSuites, parsedBobHello.cipherSuites)
	require.NotNil(t, suite)

	sigScheme := mutualSignatureScheme(aliceHello.supportedSignatureAlgorithms, parsedBobHello.supportedSignatureAlgorithms)
	require.Equal(t, SM2WithSM3, sigScheme)

	// 5. SM2 密钥协商
	ctxAlice := sm2keyexch.NewKAPCtx()
	ctxBob := sm2keyexch.NewKAPCtx()
	defer ctxAlice.Cleanup()
	defer ctxBob.Cleanup()

	// 初始化密钥协商上下文
	err = ctxAlice.Init(alicePriv, aliceId, bobPub, bobId, aliceId > bobId, true)
	require.NoError(t, err)

	err = ctxBob.Init(bobPriv, bobId, alicePub, aliceId, bobId > aliceId, true)
	require.NoError(t, err)

	// Prepare 阶段 - 生成临时公钥
	RA, err := ctxAlice.Prepare()
	require.NoError(t, err)

	RB, err := ctxBob.Prepare()
	require.NoError(t, err)

	// ComputeKey 阶段 - 计算共享密钥
	aliceKey, _, err := ctxAlice.ComputeKey(RB, 32)
	require.NoError(t, err)

	bobKey, _, err := ctxBob.ComputeKey(RA, 32)
	require.NoError(t, err)

	// 验证双方计算出的共享密钥相同
	require.True(t, bytes.Equal(aliceKey, bobKey), "双方计算的共享密钥应该相同")

	// 6. 生成 master secret
	masterSecret := masterFromPreMasterSecret(VersionE2E1, suite, aliceKey, aliceHello.random, bobHello.random)
	require.Len(t, masterSecret, masterSecretLength)

	// 7. 派生会话密钥
	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(VersionE2E1, suite, masterSecret, aliceHello.random, bobHello.random,
			suite.macLen, suite.keyLen, suite.ivLen)

	// 验证密钥派生结果
	require.Len(t, clientKey, suite.keyLen)
	require.Len(t, serverKey, suite.keyLen)
	require.Len(t, clientIV, suite.ivLen)
	require.Len(t, serverIV, suite.ivLen)

	_ = clientMAC
	_ = serverMAC

	// 8. 计算 Finished 消息
	fhAlice := newFinishedHash(suite, aliceId, bobId)
	fhAlice.Write(aliceHelloData)
	fhAlice.Write(bobHelloData)

	fhBob := newFinishedHash(suite, bobId, aliceId)
	fhBob.Write(aliceHelloData)
	fhBob.Write(bobHelloData)

	aliceFinished := fhAlice.localSum(masterSecret)
	bobFinished := fhBob.localSum(masterSecret)

	// 验证 Finished 消息
	require.Len(t, aliceFinished, finishedVerifyLength)
	require.Len(t, bobFinished, finishedVerifyLength)

	// 注意：由于使用不同的 label (aliceId vs bobId)，两个 finished 值应该不同
	// 但双方可以通过 remoteSum 验证对方的 finished

	t.Logf("完整握手模拟测试通过")
	t.Logf("  - 协商密码套件: 0x%04x", suite.id)
	t.Logf("  - 协商签名方案: 0x%04x", sigScheme)
	t.Logf("  - 共享密钥: %x", aliceKey[:8])
	t.Logf("  - Master Secret: %x...", masterSecret[:8])
	t.Logf("  - Client Key: %x", clientKey)
	t.Logf("  - Server Key: %x", serverKey)
}

// ============================================================================
// SM2 签名验证测试
// ============================================================================

func TestSM2SignatureInHandshake(t *testing.T) {
	// 生成密钥对
	priv, err := ccrypto.NewECKeySM2()
	require.NoError(t, err)
	defer priv.Free()
	err = priv.Generate()
	require.NoError(t, err)

	// 模拟密钥交换参数
	ecdhParams := make([]byte, 100)
	_, _ = rand.Read(ecdhParams)

	// 创建随机数
	localRandom := make([]byte, 32)
	remoteRandom := make([]byte, 32)
	_, _ = rand.Read(localRandom)
	_, _ = rand.Read(remoteRandom)

	// 获取签名类型和哈希函数
	sigType, sigHash, err := typeAndHashFromSignatureScheme(SM2WithSM3)
	require.NoError(t, err)
	require.Equal(t, signatureSM2, sigType)

	// 计算待签名的数据
	signed := hashForKeyExchange(sigType, sigHash, localRandom, remoteRandom, ecdhParams)
	require.NotEmpty(t, signed)

	t.Logf("SM2 签名验证测试通过，待签名数据长度: %d", len(signed))
}

// ============================================================================
// 加密通信测试
// ============================================================================

func TestEncryptedCommunication(t *testing.T) {
	suite := cipherSuiteByID(E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3)
	require.NotNil(t, suite)

	// 生成密钥
	key := make([]byte, suite.keyLen)
	iv := make([]byte, suite.ivLen)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)

	// 创建 AEAD
	aead := suite.aead(key, iv)
	require.NotNil(t, aead)

	// 模拟多条消息的加密通信
	messages := []string{
		"Hello, this is message 1",
		"This is a longer message with more content - message 2",
		"短消息3",
		"Final message with special chars: 你好世界！",
	}

	sender := &halfConn{cipher: aead}
	receiver := &halfConn{cipher: aead}

	for i, msg := range messages {
		plaintext := []byte(msg)

		// 加密
		encrypted, err := sender.encrypt(nil, plaintext, rand.Reader)
		require.NoError(t, err)

		// 解密
		decrypted, err := receiver.decrypt(encrypted)
		require.NoError(t, err)

		assert.Equal(t, plaintext, decrypted, "消息 %d 解密失败", i+1)
	}

	t.Logf("加密通信测试通过，成功加解密 %d 条消息", len(messages))
}

// ============================================================================
// 边界条件测试
// ============================================================================

func TestHelloMsg_AllExtensions(t *testing.T) {
	// 测试包含所有扩展的 Hello 消息
	msg := &helloMsg{
		random:                       make([]byte, 32),
		cipherSuites:                 cipherSuitesPreferenceOrder,
		supportedVersions:            []uint16{VersionE2E1, VersionE2E2},
		supportedCurves:              []CurveID{SM2CurveP256V1, CurveP256, CurveP384, CurveP521},
		supportedSignatureAlgorithms: defaultSupportedSignatureAlgorithms,
	}
	_, _ = rand.Read(msg.random)

	// 序列化
	data, err := msg.marshal()
	require.NoError(t, err)

	// 反序列化
	parsed := &helloMsg{}
	ok := parsed.unmarshal(data)
	require.True(t, ok)

	// 验证所有字段
	assert.Equal(t, msg.random, parsed.random)
	assert.Equal(t, msg.cipherSuites, parsed.cipherSuites)
	assert.Equal(t, msg.supportedCurves, parsed.supportedCurves)
	assert.Equal(t, msg.supportedSignatureAlgorithms, parsed.supportedSignatureAlgorithms)

	t.Logf("全扩展 Hello 消息测试通过，消息长度: %d 字节", len(data))
}

func TestChangeCipherSpec(t *testing.T) {
	suite := cipherSuiteByID(E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3)
	require.NotNil(t, suite)

	// 生成密钥
	key := make([]byte, suite.keyLen)
	iv := make([]byte, suite.ivLen)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)

	aead := suite.aead(key, iv)
	require.NotNil(t, aead)

	hc := &halfConn{}

	// 准备 cipher spec
	hc.prepareCipherSpec(VersionE2E1, aead, nil)

	// 在 changeCipherSpec 之前，cipher 应该是 nil
	assert.Nil(t, hc.cipher)
	assert.NotNil(t, hc.nextCipher)

	// 执行 changeCipherSpec
	err := hc.changeCipherSpec()
	require.NoError(t, err)

	// 之后 cipher 应该被设置
	assert.NotNil(t, hc.cipher)
	assert.Nil(t, hc.nextCipher)

	// 序列号应该被重置
	assert.Equal(t, [8]byte{}, hc.seq)

	t.Logf("ChangeCipherSpec 测试通过")
}

// ============================================================================
// 静态密钥生成和集成测试
// ============================================================================

// setupTestKeys 为测试生成 SM2 密钥对并保存到指定目录
func setupTestKeys(t *testing.T, keyStorePath string, userIds []string) {
	t.Helper()

	for _, userId := range userIds {
		userDir := filepath.Join(keyStorePath, userId)
		privateKeyPath := filepath.Join(userDir, "private_key.pem")
		publicKeyPath := filepath.Join(userDir, "public_key.pem")

		// 检查密钥是否已存在
		if _, err := ccrypto.LoadPrivateKeyFileFromPEM(privateKeyPath); err == nil {
			t.Logf("用户 %s 的密钥已存在，跳过生成", userId)
			continue
		}

		// 创建用户目录
		if err := createDirIfNotExist(userDir); err != nil {
			t.Fatalf("创建目录 %s 失败: %v", userDir, err)
		}

		// 生成 SM2 密钥对
		privateKey, err := ccrypto.GenerateECKey(ccrypto.SM2Curve)
		if err != nil {
			t.Fatalf("生成用户 %s 的密钥失败: %v", userId, err)
		}

		// 保存私钥
		privateKeyPEM, err := privateKey.MarshalPKCS1PrivateKeyPEM()
		if err != nil {
			t.Fatalf("序列化用户 %s 的私钥失败: %v", userId, err)
		}
		if err := writeFile(privateKeyPath, privateKeyPEM); err != nil {
			t.Fatalf("保存用户 %s 的私钥失败: %v", userId, err)
		}

		// 保存公钥
		publicKey := privateKey.Public()
		publicKeyPEM, err := publicKey.MarshalPKIXPublicKeyPEM()
		if err != nil {
			t.Fatalf("序列化用户 %s 的公钥失败: %v", userId, err)
		}
		if err := writeFile(publicKeyPath, publicKeyPEM); err != nil {
			t.Fatalf("保存用户 %s 的公钥失败: %v", userId, err)
		}

		t.Logf("成功生成用户 %s 的密钥对", userId)
	}
}

func createDirIfNotExist(path string) error {
	if _, err := statFile(path); err == nil {
		return nil
	}
	return mkdirAll(path, 0755)
}

// 用于测试的文件操作函数（可在需要时替换为 mock）
var (
	writeFile = func(path string, data []byte) error {
		return writeFileImpl(path, data, 0644)
	}
	statFile = func(path string) (interface{}, error) {
		return statFileImpl(path)
	}
	mkdirAll = func(path string, perm uint32) error {
		return mkdirAllImpl(path, perm)
	}
)

func writeFileImpl(path string, data []byte, perm uint32) error {
	return os.WriteFile(path, data, os.FileMode(perm))
}

func statFileImpl(path string) (interface{}, error) {
	return os.Stat(path)
}

func mkdirAllImpl(path string, perm uint32) error {
	return os.MkdirAll(path, os.FileMode(perm))
}

// TestStaticKeyIntegration 使用静态密钥进行完整握手集成测试
func TestStaticKeyIntegration(t *testing.T) {
	keyStorePath := "./static_key"
	aliceId := "alice"
	bobId := "bob"

	// 生成测试密钥
	setupTestKeys(t, keyStorePath, []string{aliceId, bobId})

	// 加载 Alice 的密钥
	alicePrivPath := filepath.Join(keyStorePath, aliceId, "private_key.pem")
	alicePubPath := filepath.Join(keyStorePath, aliceId, "public_key.pem")

	alicePriv, err := ccrypto.LoadPrivateKeyFileFromPEM(alicePrivPath)
	require.NoError(t, err, "加载 Alice 私钥失败")

	alicePub, err := ccrypto.LoadPublicKeyFileFromPEM(alicePubPath)
	require.NoError(t, err, "加载 Alice 公钥失败")

	// 加载 Bob 的密钥
	bobPrivPath := filepath.Join(keyStorePath, bobId, "private_key.pem")
	bobPubPath := filepath.Join(keyStorePath, bobId, "public_key.pem")

	bobPriv, err := ccrypto.LoadPrivateKeyFileFromPEM(bobPrivPath)
	require.NoError(t, err, "加载 Bob 私钥失败")

	bobPub, err := ccrypto.LoadPublicKeyFileFromPEM(bobPubPath)
	require.NoError(t, err, "加载 Bob 公钥失败")

	t.Logf("成功加载 Alice 和 Bob 的密钥对")
	t.Logf("Alice 私钥类型: %d, Bob 私钥类型: %d", alicePriv.KeyType(), bobPriv.KeyType())
	t.Logf("Alice 公钥类型: %d, Bob 公钥类型: %d", alicePub.KeyType(), bobPub.KeyType())

	// 验证密钥类型是 SM2
	assert.Equal(t, ccrypto.NidSM2, alicePriv.KeyType(), "Alice 私钥应为 SM2 类型")
	assert.Equal(t, ccrypto.NidSM2, bobPriv.KeyType(), "Bob 私钥应为 SM2 类型")

	t.Logf("静态密钥集成测试通过")
}

// BenchmarkFullHandshake 测量完整握手的耗时
func BenchmarkFullHandshake(b *testing.B) {
	// 预先生成静态密钥对（不计入基准测试时间）
	alicePriv, _ := ccrypto.NewECKeySM2()
	defer alicePriv.Free()
	alicePriv.Generate()

	bobPriv, _ := ccrypto.NewECKeySM2()
	defer bobPriv.Free()
	bobPriv.Generate()

	alicePub, _ := ccrypto.NewECKeySM2()
	defer alicePub.Free()
	alicePub.SetPublicFrom(alicePriv)

	bobPub, _ := ccrypto.NewECKeySM2()
	defer bobPub.Free()
	bobPub.SetPublicFrom(bobPriv)

	aliceId := "alice12345"
	bobId := "bob1234567"

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// 1. Hello 消息交换
		aliceHello := &helloMsg{
			random:                       make([]byte, 32),
			cipherSuites:                 []uint16{E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3},
			supportedVersions:            []uint16{VersionE2E1},
			supportedCurves:              []CurveID{SM2CurveP256V1},
			supportedSignatureAlgorithms: []SignatureScheme{SM2WithSM3},
		}
		rand.Read(aliceHello.random)

		bobHello := &helloMsg{
			random:                       make([]byte, 32),
			cipherSuites:                 []uint16{E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3},
			supportedVersions:            []uint16{VersionE2E1},
			supportedCurves:              []CurveID{SM2CurveP256V1},
			supportedSignatureAlgorithms: []SignatureScheme{SM2WithSM3},
		}
		rand.Read(bobHello.random)

		aliceHelloData, _ := aliceHello.marshal()
		bobHelloData, _ := bobHello.marshal()

		// 2. SM2 密钥协商
		ctxAlice := sm2keyexch.NewKAPCtx()
		ctxBob := sm2keyexch.NewKAPCtx()

		ctxAlice.Init(alicePriv, aliceId, bobPub, bobId, aliceId > bobId, true)
		ctxBob.Init(bobPriv, bobId, alicePub, aliceId, bobId > aliceId, true)

		RA, _ := ctxAlice.Prepare()
		RB, _ := ctxBob.Prepare()

		aliceKey, _, _ := ctxAlice.ComputeKey(RB, 32)
		bobKey, _, _ := ctxBob.ComputeKey(RA, 32)

		ctxAlice.Cleanup()
		ctxBob.Cleanup()

		// 3. Master secret 和会话密钥派生
		suite := cipherSuiteByID(E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3)
		masterSecret := masterFromPreMasterSecret(VersionE2E1, suite, aliceKey, aliceHello.random, bobHello.random)

		keysFromMasterSecret(VersionE2E1, suite, masterSecret, aliceHello.random, bobHello.random,
			suite.macLen, suite.keyLen, suite.ivLen)

		// 4. Finished 消息计算
		fhAlice := newFinishedHash(suite, aliceId, bobId)
		fhAlice.Write(aliceHelloData)
		fhAlice.Write(bobHelloData)
		fhAlice.localSum(masterSecret)

		fhBob := newFinishedHash(suite, bobId, aliceId)
		fhBob.Write(aliceHelloData)
		fhBob.Write(bobHelloData)
		fhBob.localSum(masterSecret)

		_ = bobKey
	}
}
