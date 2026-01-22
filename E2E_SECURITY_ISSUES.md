# E2E WebSocket 密钥协商协议 - 安全问题与解决方案

## 概述

本文档详细列出了 `e2ewebsocket` 端到端加密WebSocket实现中发现的安全问题、潜在bug和改进建议。问题按严重程度分为三级：**严重**、**中等**、**低**。

---

## 一、严重问题 (Critical)

### 1.1 SM2密钥协商上下文未正确初始化

**文件**: `key_agreement.go:133-135`, `ecdh_curve/sm2p256v1.go:123-134`

**问题描述**:
在 `processRemoteKeyExchange` 函数中，创建了新的 `sm2Curve` 和空的 `sm2PrivateKey`，但调用 `key.ECDH(peerKey)` 时，底层的 `sm2keyexch.KAPCtx` **从未被正确初始化**（未调用 `Init` 和 `Prepare`）。

```go
// key_agreement.go:135
sm2Curve := ecdh_curve.NewSm2P256V1(ka.localId > ka.remoteId)
// ...
key := ecdh_curve.NewEmptySm2PrivateKey(sm2Curve)  // 空私钥！
// ...
ka.preMasterSecret, err = key.ECDH(peerKey)  // 调用会失败或产生错误结果
```

在 `sm2p256v1.go:134` 中：
```go
ctxLocal := sm2keyexch.NewKAPCtx()
// 缺少 ctxLocal.Init(...) 调用！
keyLocal, c.csLocal, err = ctxLocal.ComputeKey(RB, 32)  // 未初始化的ctx
```

**影响**:
- 密钥协商会失败或产生不可预测的共享密钥
- 可能导致两端计算出不同的密钥，通信无法正常加解密
- 严重的安全漏洞

**解决方案**:
需要在 `processRemoteKeyExchange` 中正确使用已初始化的 `ka.ctxLocal`（在 `generateLocalKeyExchange` 中已经通过 `Prepare` 获取了 RA），而不是创建新的未初始化的 curve：

```go
// 应该使用 ka.ctxLocal 来计算共享密钥，而不是新建 curve
keyLocal, csLocal, err := ka.ctxLocal.ComputeKey(publicKey, 32)
if err != nil {
    return nil, errKeyExchange
}
ka.preMasterSecret = keyLocal
```

---

### 1.2 Nonce重用风险（AEAD加密）

**文件**: `session.go:397-415`, `sm4tongsuo/sm4aead.go:56-74`

**问题描述**:
在 AEAD 加密中，nonce 通过 `copy(explicitNonce, hc.seq[:])` 从序列号复制，但 `sm4AEADCipher.Seal` 方法完全忽略了传入的 `nonce` 参数：

```go
// session.go:409
copy(explicitNonce, hc.seq[:])  // 生成 nonce

// sm4aead.go:56
func (c *sm4AEADCipher) Seal(dst, nonce, plaintext, aad []byte) []byte {
    // nonce 参数被完全忽略！
    c.enc.SetAAD(aad)
    ciphertext, err := c.enc.EncryptAll(plaintext)  // 使用的是构造时的固定 iv
    // ...
}
```

**影响**:
- GCM模式下Nonce重用会导致密钥泄露
- 攻击者可以恢复认证密钥并伪造消息
- **这是AEAD的致命漏洞**

**解决方案**:
1. 修改 `sm4AEADCipher` 在每次 `Seal`/`Open` 调用时使用传入的 nonce：

```go
func (c *sm4AEADCipher) Seal(dst, nonce, plaintext, aad []byte) []byte {
    // 重新创建加密器或设置新的IV
    enc, err := NewEncrypter(crypto.CipherModeGCM, c.key, nonce)
    if err != nil {
        return nil
    }
    enc.SetAAD(aad)
    // ...
}
```

2. 或者采用 TLS 1.3 的方式，将固定IV与序列号XOR后作为实际nonce

---

### 1.3 `helloMsg.unmarshal` 空切片访问

**文件**: `handshake_message.go:98`

**问题描述**:
```go
if !s.Skip(4) || !s.ReadUint16(&m.supportedVersions[0]) || ...
```
`m.supportedVersions` 在初始化时是 `nil`，直接访问 `[0]` 会导致 panic。

**影响**:
- 恶意构造的Hello消息可导致服务崩溃（DoS）

**解决方案**:
```go
*m = helloMsg{original: data}
m.supportedVersions = make([]uint16, 1)  // 预分配空间
// 或者先读取到临时变量
var version uint16
if !s.ReadUint16(&version) {
    return false
}
m.supportedVersions = append(m.supportedVersions, version)
```

---

## 二、中等问题 (Medium)

### 2.1 密码套件映射表不完整

**文件**: `cipher_suites.go:107-109`

**问题描述**:
`cipherSuites` map 只注册了一个套件 `E2E_MLKEMSM2_WITH_SM4_128_GCM_SM3`，但 `cipherSuitesPreferenceOrder` 列出了9个套件。当协商选择其他套件时会返回 `nil`。

```go
var cipherSuites = map[uint16]*cipherSuite{
    E2E_MLKEMSM2_WITH_SM4_128_GCM_SM3: {...},  // 只有这一个！
}
```

**影响**:
- 大部分密码套件无法使用
- 协商可能失败或选择到不存在的套件

**解决方案**:
补全所有密码套件的定义：

```go
var cipherSuites = map[uint16]*cipherSuite{
    E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3: {id: 0x002b, keyLen: 16, ...},
    E2E_SM2KEYAGREEMENT_WITH_SM4_256_GCM_SM3: {id: 0x002c, keyLen: 32, ...},
    // ... 其他套件
}
```

---

### 2.2 共享全局 `sm2KA` 实例导致并发问题

**文件**: `cipher_suites.go:208`

**问题描述**:
```go
var sm2KA = &sm2KeyAgreement{}
```
所有密码套件共享同一个 `sm2KeyAgreement` 实例，在多会话并发场景下会产生竞态条件。

**影响**:
- 不同会话的密钥材料可能互相覆盖
- 导致加密通信失败或安全漏洞

**解决方案**:
改为工厂函数，每次协商创建新实例：

```go
// cipher_suites.go
var cipherSuites = map[uint16]*cipherSuite{
    E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3: {
        // ...
        kaFactory: func() keyAgreement { return &sm2KeyAgreement{} },
    },
}

// handshake_state.go - 在 doFullHandshake 中
keyAgreement := hs.suite.kaFactory()
```

---

### 2.3 错误后继续执行风险

**文件**: `handshake_state.go:302-311`

**问题描述**:
加载私钥后的错误检查位置不对：

```go
localPrivateKey, err := ccrypto.LoadPrivateKeyFileFromPEM(...)
sm2ka.localStaticPrivateKey = localPrivateKey  // 先赋值
if err != nil {                                  // 后检查
    return err
}
```

虽然后续会返回，但如果代码重构可能引入问题。

**解决方案**:
```go
localPrivateKey, err := ccrypto.LoadPrivateKeyFileFromPEM(...)
if err != nil {
    return err
}
sm2ka.localStaticPrivateKey = localPrivateKey
```

---

### 2.4 会话Map无并发保护

**文件**: `conn.go:22`, `conn.go:137-143`, `conn.go:227-231`

**问题描述**:
`Conn.sessions` map 在多goroutine环境下被并发读写，没有加锁保护：

```go
type Conn struct {
    sessions map[SessionID]*Session  // 无锁保护
}

// 读写操作分布在 ReadMessage 和 WriteMessage 中
session := c.sessions[sessionId]       // 可能的并发读
c.sessions[sessionId] = session        // 可能的并发写
```

**影响**:
- 并发访问导致panic或数据损坏

**解决方案**:
使用 `sync.RWMutex` 或 `sync.Map`：

```go
type Conn struct {
    sessions    map[SessionID]*Session
    sessionsMu  sync.RWMutex
}

func (c *Conn) getOrCreateSession(id SessionID, remoteId string) *Session {
    c.sessionsMu.Lock()
    defer c.sessionsMu.Unlock()
    if s, ok := c.sessions[id]; ok {
        return s
    }
    s := NewSession(id, remoteId, c)
    c.sessions[id] = s
    return s
}
```

---

### 2.5 Finished Hash的label使用ID可能泄露信息

**文件**: `finished_hash.go:61`, `handshake_state.go:198`

**问题描述**:
```go
hs.finishedHash = newFinishedHash(hs.suite, hs.localId, hs.remoteId)
```
使用用户ID作为PRF的label，虽然增加了身份绑定，但ID可能包含敏感信息。

**影响**:
- 如果ID包含可识别信息，可能有隐私风险
- 建议使用固定label或对ID进行哈希

**解决方案**:
```go
// 使用ID的哈希值而非原始ID
localLabel := sha256.Sum256([]byte(hs.localId))
remoteLabel := sha256.Sum256([]byte(hs.remoteId))
hs.finishedHash = newFinishedHash(hs.suite,
    hex.EncodeToString(localLabel[:8]),
    hex.EncodeToString(remoteLabel[:8]))
```

---

## 三、低优先级问题 (Low)

### 3.1 硬编码的密钥存储路径

**文件**: `common.go:173`

**问题描述**:
```go
var defaultKeyStorePath string = "./static_key"
```

**影响**:
- 相对路径在不同工作目录下行为不一致
- 生产环境应使用安全的密钥存储

**解决方案**:
- 使用环境变量或配置文件
- 考虑集成KMS或硬件安全模块

---

### 3.2 SM2曲线公钥大小硬编码

**文件**: `ecdh_curve/sm2p256v1.go:14-16`

**问题描述**:
```go
var sm2p256v1PublicKeySize    = 91
var sm2p256v1PrivateKeySize   = 121
```
这些是DER编码后的大小，但代码中没有验证格式。

**解决方案**:
添加格式验证或使用常量注释说明编码格式。

---

### 3.3 PRF label使用英文字符串

**文件**: `prf.go:16-17`

**问题描述**:
```go
const masterSecretLabel = "master secret"
const keyExpansionLabel = "key expansion"
```
使用TLS标准label，但这是自定义协议，可能与TLS实现产生混淆。

**解决方案**:
使用自定义label以避免混淆：
```go
const masterSecretLabel = "e2e master secret"
const keyExpansionLabel = "e2e key expansion"
```

---

### 3.4 缺少SM2密钥交换的Checksum验证

**文件**: `key_agreement.go`, `ecdh_curve/sm2p256v1.go`

**问题描述**:
SM2密钥协商规范要求双方验证checksum（S1/SA和S2/SB），但当前实现中：
- `ctxLocal.FinalCheck(csRemote)` 从未被调用
- checksum值被计算但未传输和验证

**影响**:
- 缺少密钥确认步骤，可能存在中间人攻击风险

**解决方案**:
在协议中增加checksum交换和验证步骤。

---

### 3.5 readRecord的并发安全性

**文件**: `conn.go:102-104`, `session.go:156-161`

**问题描述**:
`readRecord` 被多个地方调用，且注释中提到可能有并发问题：
```go
// 其实感觉 readRecord 这个函数可能会有并发问题啊！是不是！
for len(s.hand) == 0 {
    if err := s.conn.readRecord(); err != nil {
        return nil, err
    }
}
```

**解决方案**:
- 添加读取锁
- 使用单独的goroutine处理消息分发

---

### 3.6 CBC模式未实现但已声明

**文件**: `cipher_suites.go:43-45`

**问题描述**:
声明了CBC模式的套件但 `session.go` 中CBC处理代码被注释：
```go
// case cbcMode:
// TODO:
```

**解决方案**:
- 要么完成CBC实现
- 要么从支持列表中移除CBC套件

---

## 四、架构和设计建议

### 4.1 密钥生命周期管理

当前实现缺少：
- 会话密钥过期机制
- 重协商触发条件
- 密钥轮换策略

### 4.2 错误处理统一

建议：
- 定义统一的错误类型
- 避免在错误消息中泄露敏感信息
- 实现统一的错误日志记录

### 4.3 测试覆盖

需要补充：
- 单元测试（尤其是加解密、密钥协商）
- 集成测试（完整握手流程）
- 模糊测试（消息解析）
- 安全测试（重放、中间人攻击模拟）

---

## 五、问题优先级汇总

| 编号 | 问题 | 严重程度 | 影响 |
|------|------|----------|------|
| 1.1 | SM2密钥协商未正确初始化 | 严重 | 密钥协商失败 |
| 1.2 | AEAD Nonce重用 | 严重 | 密钥泄露 |
| 1.3 | Hello解析空切片访问 | 严重 | DoS |
| 2.1 | 密码套件映射不完整 | 中等 | 功能缺失 |
| 2.2 | 全局sm2KA并发问题 | 中等 | 数据竞争 |
| 2.3 | 错误检查位置不当 | 中等 | 潜在bug |
| 2.4 | Session Map无锁 | 中等 | 并发panic |
| 2.5 | ID作为label | 中等 | 隐私风险 |
| 3.1 | 硬编码路径 | 低 | 可维护性 |
| 3.2 | 公钥大小硬编码 | 低 | 可维护性 |
| 3.3 | PRF label | 低 | 清晰度 |
| 3.4 | 缺少Checksum验证 | 低 | 安全加固 |
| 3.5 | readRecord并发 | 低 | 潜在问题 |
| 3.6 | CBC未实现 | 低 | 功能完整性 |

---

## 六、建议修复顺序

1. **立即修复** (1-2天):
   - 1.1 SM2密钥协商初始化
   - 1.2 AEAD Nonce处理
   - 1.3 Hello消息解析

2. **短期修复** (1周):
   - 2.1 补全密码套件
   - 2.2 消除全局状态
   - 2.4 Session Map加锁

3. **中期完善** (2周):
   - 添加单元测试
   - 实现CBC模式或移除
   - 增加Checksum验证

4. **长期优化**:
   - 密钥生命周期管理
   - 安全审计
   - 性能优化

---

*文档生成时间: 2026-01-22*
*审查范围: e2ewebsocket/, crypto/*
