# e2ewebsocket 握手/记录层问题清单（仅分析，不改代码）

- 分析时间：2026-01-26
- 分析分支：`codex`（避免在 `main` 上产生任何改动）
- 代码版本：`348eeb11fa1c9af8f0fcdb893a7a709bf9e601e9`

> 结论先行：以当前实现来看，握手流程基本无法跑通（存在必现 panic/必现不一致），且记录层的 AEAD 认证范围/Nonce 使用方式存在严重安全隐患。下面按“阻断性 → 安全性 → 并发健壮性 → 设计一致性”列出问题点与定位。

## 0. 当前代码意图（便于对照）

- WebSocket Binary 帧承载“自定义 Record”：
  - header：`[recordType:1][senderId:10]`（见 `e2ewebsocket/conn.go:128-129`, `e2ewebsocket/conn.go:280-282`）
  - body：`session.{in,out}.{decrypt,encrypt}` 处理后的 payload（见 `e2ewebsocket/conn.go:152`, `e2ewebsocket/conn.go:286`）
- 握手意图（`Session.symHandshake`）：
  1) 互发 Hello（`e2ewebsocket/handshake_state.go:51-108`）
  2) 互发 KeyExchange（`e2ewebsocket/handshake_state.go:313-346`）
  3) 生成 masterSecret → 派生读写密钥（`e2ewebsocket/handshake_state.go:346-379`, `e2ewebsocket/prf.go:19-55`）
  4) 发送 CCS → Finished（`e2ewebsocket/handshake_state.go:369-398`）
  5) 读取 CCS → Finished（`e2ewebsocket/handshake_state.go:400-423`, `e2ewebsocket/conn.go:195-214`）

## 1. 阻断性问题（P0：会导致必现 panic / 握手必失败）

### 1.1 Hello 解析必现 panic：写入 `m.supportedVersions[0]`

- `helloMsg.unmarshal` 在 `*m = helloMsg{original: data}` 后，`m.supportedVersions` 仍是 `nil`，却直接 `&m.supportedVersions[0]` 写入：必然越界 panic。  
  - 位置：`e2ewebsocket/handshake_message.go:98`
- 同类问题：`helloMsg.marshal` 也直接读 `m.supportedVersions[0]`，虽然当前 `makeHello` 会填充 slice，但这属于“脆弱假设”（一旦外部构造 hello 未填充就会 panic）。  
  - 位置：`e2ewebsocket/handshake_message.go:66`

### 1.2 Hello 没有携带 SignatureAlgorithms：后续必然选不出签名方案

- `helloMsg` 结构体有 `supportedSignatureAlgorithms` 字段，但 `marshal/unmarshal` 只处理了 `supportedVersions`/`supportedCurves`，完全没发/没收签名算法扩展。  
  - 字段定义：`e2ewebsocket/handshake_message.go:17`
- `handshakeState.pickSignatureScheme` 依赖 `remoteHelloMsg.supportedSignatureAlgorithms` 做交集：空 slice 会导致选不出，握手直接失败。  
  - 位置：`e2ewebsocket/handshake_state.go:256-265`

### 1.3 `Session.unmarshalHandshakeMessage` 只支持 Hello：KeyExchange/Finished 永远解析不了

- `readHandshake` 最终调用 `unmarshalHandshakeMessage`，但 switch 里只有 `case typeHelloMsg`，其它类型直接 `alertUnexpectedMessage`。  
  - 位置：`e2ewebsocket/session.go:178-199`
- 而握手状态机明确会读取 `*keyExchangeMsg` 与 `*finishedMsg`：  
  - `e2ewebsocket/handshake_state.go:325-346`（读 KeyExchange）  
  - `e2ewebsocket/handshake_state.go:384-423`（读 Finished）

### 1.4 只“读侧”切换密钥：写侧永远不 `changeCipherSpec`，Finished 加密状态必不匹配

- 读侧在收到 `recordTypeChangeCipherSpec` 时调用了 `session.in.changeCipherSpec()`：  
  - `e2ewebsocket/conn.go:195-214`
- 但写侧发送 CCS（`Session.writeChangeCipherRecord`）仅写入一个 payload `{1}`，并没有调用 `s.out.changeCipherSpec()` 来启用 `nextCipher`：  
  - `e2ewebsocket/session.go:223-229`
- 结果：一方读侧已开始按新密钥解密，而另一方写侧仍用明文/旧状态发 Finished，解密必失败（或出现“双方状态错位”）。

### 1.5 `sm2KeyAgreement` 在 ciphersuite 中使用全局单例：跨 session 串状态 + 数据竞争

- `cipherSuites` 里把 `ka` 直接指向全局变量 `sm2KA := &sm2KeyAgreement{}`：  
  - `e2ewebsocket/cipher_suites.go:107-109`, `e2ewebsocket/cipher_suites.go:208`
- `sm2KeyAgreement` 内有大量握手态字段（`ctxLocal/kxmLocal/preMasterSecret/localId/remoteId/...`），单例复用会导致：
  - 并发握手数据竞争（race）
  - 不同 session 的密钥材料互相覆盖（严重逻辑错误）

### 1.6 `sm2KeyAgreement.ctxLocal` 可能为 nil：`Prepare()` 直接 panic

- `generateLocalKeyExchange` 直接 `ka.ctxLocal.Prepare()`，但当前握手路径里只给 `sm2ka` 填了 id/静态密钥，并未见到初始化 `ctxLocal`（Init/Prepare 的完整流程只在 `NewSM2KeyAgreement` 里做）。  
  - 调用点：`e2ewebsocket/key_agreement.go:68`
  - “只填字段不 Init” 发生在：`e2ewebsocket/handshake_state.go:298-314`

### 1.7 masterSecret / key expansion 的随机数顺序与“角色”不确定：双方很容易算出不同密钥

- masterSecret 计算使用 `initiatorRandom || responderRandom`（`prf.go`），但调用方直接传 `localHello.random, remoteHello.random`：  
  - `e2ewebsocket/prf.go:19-25`
  - `e2ewebsocket/handshake_state.go:346`
- 在对称握手模型下，双方的 “local/remote” 是互换的：A 用 `A||B`，B 用 `B||A`，masterSecret 直接不一致（除非你额外定义并统一“initiator/responder”的判定与顺序）。
- `keysFromMasterSecret` 同样依赖随机数顺序，并且返回 `clientKey/serverKey` 这类“需要明确角色”的材料；但当前代码把本端永远当 client（写用 clientKey，读用 serverKey），对端也会同样当 client：两端读写密钥映射天然对不上。  
  - `e2ewebsocket/prf.go:27-55`
  - `e2ewebsocket/handshake_state.go:359-379`

### 1.8 业务写入在握手前发送 ApplicationData：读侧会直接拒绝，导致首包必失败

- `Conn.WriteMessage` 先发 `recordTypeApplicationData`，之后才 `session.Handshake()`：  
  - `e2ewebsocket/conn.go:217-258`（函数整体）
  - `e2ewebsocket/conn.go:240`（先写 ApplicationData）
  - `e2ewebsocket/conn.go:246`（后做 Handshake）
- 读侧对 `recordTypeApplicationData` 有强校验：`!handshakeComplete` 时直接 `alertUnexpectedMessage`。  
  - `e2ewebsocket/conn.go:176-178`
- 结果：双方第一次通信极易在“应用数据先到/握手未完成”的组合下直接失败（除非上层严格保证先握手再发业务数据）。

### 1.9 收到 Handshake record 也不会自动驱动握手：可能出现“握手数据堆积但永远不处理”

- 读循环 `Conn.ReadMessage` 的退出条件是 `readQueue` 非空，但握手 record 只会被塞进 `session.hand`，不会进入 `readQueue`：  
  - `e2ewebsocket/conn.go:68-89`（ReadMessage 循环）
  - `e2ewebsocket/conn.go:189-194`（Handshake record 仅 append，不触发 Handshake）
- 如果上层只调用 `Conn.ReadMessage()` 而没有显式调用 `session.Handshake()`（或没有通过 `WriteMessage` 间接触发），会出现：
  - 握手消息不断到来但不被消费
  - `ReadMessage` 可能一直阻塞/空转等待应用数据，而应用数据又会因握手未完成被拒绝（见 1.8/读侧校验）

## 2. 安全性问题（P1：即使跑通也很危险）

### 2.1 Record header（type、senderId）未纳入 AEAD 认证：可被篡改导致类型/身份混淆

- `halfConn.encrypt/decrypt` 的 AAD 目前只包含 `seq + length`，未包含 `recordType`，更未包含 `senderId`。代码里甚至有“打算加 type 进 AAD”的注释但被注释掉了。  
  - `e2ewebsocket/session.go:319-324`（decrypt AAD 构造）
  - `e2ewebsocket/session.go:428-432`（encrypt AAD 构造 + 被注释掉的 `record[:1]`）
- 后果：
  - 攻击者可在不破坏 AEAD tag 的情况下篡改 header（取决于实现是否把 header 作为 ciphertext/AAD），造成 `Handshake`/`ApplicationData` 处理路径混淆、session 路由混淆、DoS 等。
  - 目前 header 是明文且不认证，协议层“身份绑定”很弱。

### 2.2 KeyExchange 哈希/签名逻辑与协商方案不一致（尤其 ECDSA）

- `hashForKeyExchange` 对 `signatureECDSA` 一律使用 `SHA1`，忽略协商的 `SignatureScheme`（例如 ECDSAWithP256AndSHA256 应该是 SHA256）。  
  - `e2ewebsocket/key_agreement.go:271-273`
- `generateLocalKeyExchange` 当前直接调用 `sm2tongsuo.SignASN1`，看起来只实现了 SM2 路径；如果 `pickSignatureScheme` 将来选到 RSA/ECDSA/Ed25519，将出现签名算法与密钥类型不匹配/签名失败。  
  - `e2ewebsocket/key_agreement.go:88-108`
  - 对端校验时又强制 `sigType == signatureSM2`：`e2ewebsocket/key_agreement.go:216-220`

### 2.3 握手消息的类型/长度校验不完整

- `keyExchangeMsg.unmarshal` 只检查 `len(data) < 4`，没有校验 `data[0] == typeKeyExchange` 以及 `Uint24 length` 是否匹配。  
  - `e2ewebsocket/handshake_message.go:261-268`
- `finishedMsg.unmarshal` 也没有校验 `typeFinished`（只是 `Skip(1)`）。  
  - `e2ewebsocket/handshake_message.go:285-289`
- `Session.unmarshalHandshakeMessage` 也未在 switch 前检查 `len(data) > 0`，空 slice 会直接 panic。  
  - `e2ewebsocket/session.go:182-196`

### 2.4 AEAD Nonce 实际未被使用（依赖实现层面）：GCM/CCM 可能发生灾难性 nonce 复用

> 这一条不在 `e2ewebsocket/` 目录内，但它直接决定 record 加密是否安全/可用；当前 ciphersuite 直接引用了该实现（`e2ewebsocket/cipher_suites.go:107-109`）。

- `sm4AEADCipher.Seal/Open` 的参数里带 `nonce`，但函数体内没有使用 `nonce` 更新底层 iv/计数器，意味着“每条记录不同 nonce”的设计在实现层被完全忽略。  
  - `crypto/sm4tongsuo/sm4aead.go:56-75`
  - `crypto/sm4tongsuo/sm4aead.go:77-93`
- 同时 `ExplicitNonceLen()` 返回 `NonceSize()`（固定 12），这会让记录层每条消息都携带显式 nonce，但这些 nonce 并没有参与真实加解密：  
  - `crypto/sm4tongsuo/sm4aead.go:95-110`

## 3. 并发与健壮性问题（P2：容易 race、死锁、崩溃）

### 3.1 gorilla/websocket 并发读写约束未被满足

- `Conn.ReadMessage()`/`Session.readHandshake()` 最终都会调用 `wsconn.ReadMessage()`（`Conn.readRecordOrCCS`），没有任何全局读锁；握手 goroutine 与业务读 goroutine 并发读会触发数据竞争/协议错乱（gorilla/websocket 要求同一连接上只能有一个 reader）。  
  - 入口：`e2ewebsocket/conn.go:111-117`, `e2ewebsocket/session.go:153-162`
- `Conn.writeRecordLocked` 名字叫 locked 但没有锁，握手写与业务写并发同样危险（gorilla/websocket 要求同一连接上只能有一个 writer）。  
  - `e2ewebsocket/conn.go:262-295`

### 3.2 map/slice 没有并发保护

- `Conn.sessions map`、`Conn.readQueue []readMsgItem`、`Session.hand [][]byte` 都在多个路径读写，未见 mutex 保护。  
  - `e2ewebsocket/conn.go:24-47`, `e2ewebsocket/conn.go:54-109`, `e2ewebsocket/conn.go:111-214`
  - `e2ewebsocket/session.go:23-55`, `e2ewebsocket/session.go:153-174`
- `halfConn` 内部 `seq/cipher/nextCipher` 等状态会被读写侧使用，但锁被注释掉了。  
  - `e2ewebsocket/session.go:278-289`

### 3.3 读路径缺少长度检查：短包直接 panic

- `readRecordOrCCS` 直接 `msg[0]`、`msg[1:11]`、`msg[11:]`，不检查 `len(msg) >= 11`。  
  - `e2ewebsocket/conn.go:128-129`, `e2ewebsocket/conn.go:152`

### 3.4 senderId 固定 10 字节但按 string 直接使用：易产生 `\x00` 尾随导致 session/key 路径异常

- 写侧 `copy(outBuf[1:11], c.hostId)` 会对不足 10 字节的 id 进行 0 填充；读侧 `string(msg[1:11])` 会把 0 字节直接带进字符串。  
  - `e2ewebsocket/conn.go:129`, `e2ewebsocket/conn.go:280-282`
- 影响：
  - `getSessionID` 的字符串比较/拼接不稳定（`A < B` 的语义被 0 字节污染）
  - `handshake_state` 里 `filepath.Join(..., hs.remoteId, ...)` 可能出现包含 0 字节的路径片段

### 3.5 `halfConn.decrypt` 的 Stream 分支不返回 plaintext

- `case cipher.Stream:` 只做 XOR，没有给 `plaintext` 赋值，最终返回 `nil, nil`（逻辑错误）。  
  - `e2ewebsocket/session.go:301-303`

## 4. 设计与一致性问题（P3：不一定立刻崩，但会不断踩坑）

### 4.1 `defaultConfig()` 返回全局单例：修改配置会污染所有连接

- `defaultConfig()` 返回 `&emptyConfig`（全局变量），随后 `makeHello` 会对 `config.supportedVersions` 等字段写入，导致跨 Conn 共享状态。  
  - `e2ewebsocket/common.go:180-184`

### 4.2 `mutualVersion` 的返回值语义不正确 + 版本选择策略可疑

- `Intersection` 无交集会返回 0，但 `mutualVersion` 在 `peerVersions != nil` 时依旧返回 `(0, true)`，上层会把版本 0 当成“协商成功”。  
  - `e2ewebsocket/common.go:252-259`, `e2ewebsocket/tool_func.go:15-31`
- 版本选择返回的是“对方列表中第一个命中项”，在 `supportedVersions = [0x0301, 0x0302]` 这种顺序下会总是选到旧版本。  
  - `e2ewebsocket/common.go:244-250`, `e2ewebsocket/common.go:252-259`

### 4.3 cipherSuite/signatureScheme 的交集策略在“对称握手”下不具备确定性

- `Intersection(a,b)` 返回的是 `b` 中第一个命中的元素（`tool_func.go`），`mutualCipherSuite(have,want)`/`mutualSignatureScheme(have,want)` 本质上是“偏向对端优先级”。  
  - `e2ewebsocket/tool_func.go:15-31`
  - `e2ewebsocket/cipher_suites.go:183-190`, `e2ewebsocket/cipher_suites.go:193-200`
- 若双方 preference order 不同，会出现 A 选 B 的第一项、B 又选 A 的第一项，最终两端选择结果不一致（除非你定义清晰的 client/server 或 initiator/responder 角色）。

### 4.4 KeyStore 默认路径/内容与代码预期可能不一致

- 默认 `defaultKeyStorePath = \"./static_key\"`，但仓库里的 key 目录在 `e2ewebsocket/static_key` 下。  
  - `e2ewebsocket/common.go:173`, `e2ewebsocket/common.go:186-190`
- `handshake_state` 强依赖存在 `.../<id>/private_key.pem` 与 `.../<id>/public_key.pem`。  
  - `e2ewebsocket/handshake_state.go:302-310`

### 4.5 文本编码问题：中文注释大量显示为乱码

- 多个文件的中文注释在 UTF-8 环境下表现为乱码（疑似 GBK/ANSI 编码），会影响跨平台协作与长期维护。
