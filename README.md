# go_ws_client

> 基于 Go 语言实现的 WebSocket 客户端库，面向 [OpenIM](https://github.com/openimsdk/open-im-server) 等各类即时通讯平台，内置端到端（E2E）加密握手协议，支持国密算法（SM2/SM3/SM4）。

---

## ✨ 功能特性

| 功能 | 描述 |
|------|------|
| **普通 WebSocket 客户端** | 连接 OpenIM 服务器，收发 IM 消息（文本/二进制/Ping-Pong） |
| **E2E 加密通信** | 自研类 TLS 握手协议，保障客户端间端到端消息加密 |
| **国密算法支持** | 通过 [Tongsuo](https://github.com/Tongsuo-Project/Tongsuo) (cgo) 集成 SM2 密钥交换、SM3 哈希、SM4 对称加密 |
| **Gzip 压缩** | `sync.Pool` 池化的 Gzip 压缩器，降低内存分配开销 |
| **多格式编码** | Gob / JSON 双编码器，可插拔替换 |
| **多格式配置** | JSON / YAML 配置文件，通过文件扩展名自动识别 |
| **Protobuf 序列化** | 消息体使用 `openimsdk/protocol` Protobuf 定义 |

---

## 📦 项目结构

```
go_ws_client/
├── ws_client.go          # 普通 WebSocket 客户端主程序（build tag: client）
├── builder.go            # IM 消息构建器（MsgData → Req → 编码+压缩）
├── types.go              # 公共请求/响应结构体（Req / Resp / Message）
│
├── compressor/           # 压缩器
│   └── compressor.go     # Compressor 接口 + GzipCompressor 实现（sync.Pool 优化）
│
├── encoder/              # 编码器
│   └── encoder.go        # Encoder 接口 + GobEncoder / JsonEncoder 实现
│
├── configparser/         # 配置解析器
│   ├── config_parser.go  # Parser 接口 + JsonParser / YamlParser 实现
│   └── types.go          # ClientConfig 结构体
│
├── config/               # 示例配置文件
│   ├── client.json       # JSON 格式配置示例
│   └── client2.yaml      # YAML 格式配置示例
│
├── e2ewebsocket/         # E2E 加密 WebSocket 核心模块
│   ├── common.go         # 协议常量、Config、曲线/签名方案定义
│   ├── conn.go           # Conn（E2E 连接）：readLoop、WriteMessage、Session 管理
│   ├── session.go        # Session 生命周期与握手状态机
│   ├── handshake_state.go# 握手流程：Hello → KeyExchange → Finished
│   ├── key_agreement.go  # SM2 密钥协商（KAP 协议）
│   ├── cipher_suites.go  # 密码套件注册与选择
│   ├── auth.go           # 签名算法分发与验证（SM2WithSM3 / ECDSA / Ed25519 / RSA）
│   ├── handshake_message.go # 握手消息序列化/反序列化
│   ├── mock_server.go    # 测试用 Mock Relay Server
│   ├── im_parser/        # IM 消息解析适配层（读/写边界）
│   └── static_key/       # 测试用静态密钥存储目录
│
├── crypto/               # 国密加密库（cgo + Tongsuo）
│   ├── key.go            # EVP 密钥加载/生成/序列化
│   ├── cipher.go         # 对称/AEAD 加密原语
│   ├── bio.go            # OpenSSL BIO 封装
│   ├── sm2tongsuo/       # SM2 签名/验签
│   ├── sm3tongsuo/       # SM3 哈希
│   ├── sm4tongsuo/       # SM4 对称加密
│   ├── sm2keyexch/       # SM2 密钥交换（KAP）
│   ├── ecdh_curve/       # ECDH 曲线支持
│   └── shim.c / shim.h   # cgo 桥接层
│
├── keystore/             # 运行时密钥存储目录（PEM 格式）
├── scripts/              # Tongsuo 构建脚本（Linux/macOS/Windows）
├── test/                 # 集成测试
├── third_party/          # Tongsuo 源码子模块及安装目录
└── TONGSUO_SETUP.md      # Tongsuo 构建与运行时配置文档
```

---

## 🏗️ 架构概览

### 普通 WebSocket 客户端

```
用户输入（stdin）
    │
    ▼
Builder.OfflinePushInfo().MsgData(text)   ← 构造 sdkws.MsgData (Protobuf)
    │
    ▼
Builder.Req(protoBytes)                   ← 封装为 Req 结构体
    │
    ▼
Builder.Build()                           ← Gob 编码 + Gzip 压缩
    │
    ▼
websocket.WriteMessage(BinaryMessage)     ← 发送至 OpenIM 服务器

服务器推送 (BinaryMessage)
    │
    ▼
Gzip 解压 → Gob 解码 → Resp
    │          Protobuf 反序列化 → PushMessages
    ▼
打印会话 ID 与消息内容
```

### E2E 加密握手协议（e2ewebsocket）

```
   Peer A (Initiator, ID 较大)          Peer B (Responder, ID 较小)
        │                                        │
        │──────── HelloMsg ──────────────────────►│
        │◄──────── HelloMsg ─────────────────────│
        │  协商: 版本 / 密码套件 / 签名算法         │
        │                                        │
        │──────── KeyExchangeMsg (SM2 KAP) ──────►│
        │◄──────── KeyExchangeMsg (SM2 KAP) ─────│
        │  双方独立推导 preMasterSecret            │
        │                                        │
        │  masterSecret = PRF(preMs, randoms)    │
        │  → 生成 initiatorKey / responderKey    │
        │                                        │
        │──────── ChangeCipherSpec ──────────────►│
        │──────── Finished (HMAC verify) ────────►│
        │◄──────── ChangeCipherSpec ─────────────│
        │◄──────── Finished (HMAC verify) ───────│
        │                                        │
        │  Session 握手完成，双向 AEAD 加密通信     │
```

**关键设计点：**
- 每对 `(A, B)` 拥有独立 `Session`，通过 `sync.Map` 管理
- `readLoop` goroutine 负责消息分发：握手消息→`handshakeChan`，应用数据→`msgChan`
- `WriteMessage` 调用前无条件调用 `session.Handshake()`，内置 `sync.Mutex` 防并发重入
- 仅加密 `MsgData.Content` 字段，其余元数据（SendID/RecvID 等）明文传输（供 Relay Server 路由）

---

## ⚙️ 快速开始

### 前置依赖

- Go 1.24.6+
- （使用 E2E 加密或国密功能时）需先构建 Tongsuo，详见 [TONGSUO_SETUP.md](./TONGSUO_SETUP.md)

### 1. 克隆项目

```bash
git clone <repo-url>
cd go_ws_client
git submodule update --init --recursive
```

### 2. 构建 Tongsuo（可选，仅 E2E 加密/国密功能需要）

**Linux：**
```bash
./scripts/build_tongsuo_linux.sh
source ./scripts/set_tongsuo_env.sh
```

**macOS：**
```bash
./scripts/build_tongsuo_macos.sh
source ./scripts/set_tongsuo_env.sh
```

**Windows（PowerShell）：**
```powershell
.\scripts\build_tongsuo_windows.ps1
.\scripts\set_tongsuo_env.ps1
```

### 3. 配置客户端

编辑 `config/client.json`（或 `config/client2.yaml`）：

```json
{
    "operationID": "your-operation-id",
    "sendID": "your-user-id",
    "receiveID": "target-user-id",
    "senderNickname": "YourNickname",
    "token": "your-jwt-token",
    "serverAddr": "ws://your-openim-server:10001/"
}
```

| 字段 | 说明 |
|------|------|
| `operationID` | 操作唯一标识（任意字符串） |
| `sendID` | 发送方用户 ID |
| `receiveID` | 接收方用户 ID |
| `senderNickname` | 发送方昵称 |
| `token` | JWT 鉴权 Token（从 OpenIM 获取） |
| `serverAddr` | WebSocket 服务器地址（`ws://` 或 `wss://`） |

### 4. 运行客户端

```bash
# 使用默认配置文件 ./config/client.json
go run -tags client .

# 指定配置文件
go run -tags client . -config ./config/client.json

# 使用 YAML 配置
go run -tags client . -config ./config/client2.yaml
```

运行后在终端输入消息按回车发送，输入 `exit` 退出：

```
> Hello, World!
> exit
```

---

## 🔐 国密支持（Tongsuo / SM 算法）

本项目通过 cgo 调用 [Tongsuo](https://github.com/Tongsuo-Project/Tongsuo)（基于 OpenSSL fork 的国密密码库），支持以下算法：

| 算法 | 用途 |
|------|------|
| **SM2** | 非对称密钥对生成、数字签名、密钥协商（KAP 协议） |
| **SM3** | 哈希摘要（替代 SHA-256，用于签名和 HMAC） |
| **SM4** | 对称加密（替代 AES，用于应用数据加密） |

密钥以 PEM 格式存储于 `keystore/<userID>/` 目录：
```
keystore/
└── alice/
    ├── private_key.pem   # SM2 私钥（PKCS#8 格式）
    └── public_key.pem    # SM2 公钥（PKIX 格式）
```

---

## 🧪 运行测试

```bash
# 运行全部测试
go test ./...

# 运行 E2E 握手测试
go test ./e2ewebsocket/... -v

# 运行加密库测试
go test ./test/... -v
```

> ⚠️ 涉及国密的测试需要提前完成 Tongsuo 构建，并正确设置库路径环境变量。

---

## 📐 核心接口

### E2E 连接（`e2ewebsocket` 包）

```go
// 创建 E2E 安全连接
conn, err := e2ewebsocket.NewSecureConn(wsConn, hostID, config, imParser)

// 发送消息（内部自动完成握手）
err = conn.WriteMessage(websocket.BinaryMessage, msgBytes)

// 接收消息
msgType, data, err := conn.ReadMessage()
```

---