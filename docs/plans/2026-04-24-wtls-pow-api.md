# wTLS PoW API 实施规划

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**目标：** 在 TLS 1.3 握手中开放 PoW（工作量证明）所需的外部控制接口，包括客户端 random 可控、服务端自定义 EncryptedExtensions 字段、服务端握手暂停钩子，以及 TLS 指纹规格配置接口。

**架构思路：** 最小化修改原则——所有 PoW 逻辑由调用方实现，库仅开放钩子和字段。新增字段统一挂载到 `Config` 结构体，并通过回调函数（`func` 类型字段）提供扩展点，避免引入新类型文件。

**技术栈：** Go 标准库 `crypto/tls` fork（包名 `wtls`），仅限 TLS 1.3 路径，`golang.org/x/crypto` 辅助包。

---

## 阶段一：客户端 random 可控 + 读取服务端自定义扩展

本阶段完成后，客户端可通过回调向 `ClientHello.random` 注入外部计算的工作量证明值，并在握手完成后读取服务端通过 `EncryptedExtensions` 下发的 `ZeroBits` 和 `ShareNodes` 字段。

---

### 任务 1.1：在 `Config` 中添加客户端 random 回调字段

**涉及文件：**
- 修改：`common.go`（`Config` 结构体定义处）

**背景：**
`Config` 结构体位于 `common.go` 约第 568 行。当前 random 由 `handshake_client.go:105` 处 `io.ReadFull(config.rand(), hello.random)` 填充。我们需要在 `Config` 中增加一个回调，让外部有机会替换该值。

**步骤 1：定位 `Config` 结构体末尾，添加字段**

在 `Config` 结构体中（紧靠其他回调字段附近，例如 `VerifyConnection` 之后或结构体末尾的空行前），添加：

```go
// GetClientRandom 如果非 nil，在 ClientHello 即将发出前被调用。
// 参数 random 是已生成的 32 字节随机值（由 Config.Rand 填充）。
// 返回值将替换原始 random；若返回 nil 或长度不为 32，则保持原值不变。
// 仅在 TLS 1.3 握手中生效；ECH 模式下针对 inner hello 调用。
// 工作量证明（PoW）的计算应在此回调中完成或触发。
GetClientRandom func(random []byte) []byte
```

**步骤 2：编译验证**

```bash
go build ./...
```

预期：无报错输出。

**步骤 3：提交**

```bash
git add common.go
git commit -m "feat(config): add GetClientRandom callback field to Config"
```

---

### 任务 1.2：在 `makeClientHello` 后调用 `GetClientRandom` 回调

**涉及文件：**
- 修改：`handshake_client.go`

**背景：**
`clientHandshake`（第 222 行）调用 `makeClientHello` 得到 `hello` 后，在第 257 行进入 ECH 分支。注入点需要覆盖两种情况：
1. 非 ECH 模式：`hello.random` 在 `makeClientHello` 内第 105 行已填充，需在发送前替换。
2. ECH 模式：outer hello 的 random 在第 265–268 行重新填充，inner hello 的 random 在 `makeClientHello` 内填充——PoW 应针对 inner hello（实际握手内容）。

注入应在 `clientHandshake` 中，`makeClientHello` 返回后、ECH 处理之前，先处理 inner/non-ECH 的 random；ECH outer random 保持随机（不受 PoW 控制，符合 ECH 语义）。

**步骤 1：在 `clientHandshake` 中的合适位置添加回调调用**

定位 `handshake_client.go` 第 232–278 行的 `clientHandshake` 函数。在 `makeClientHello` 返回后（第 235 行之后）、`loadSession` 调用之前，插入如下代码：

```go
// 若配置了 GetClientRandom，允许外部替换 ClientHello.random（用于 PoW 注入）。
// ECH 模式下，此处修改的是 inner hello（真实握手内容）的 random。
if c.config.GetClientRandom != nil {
    if r := c.config.GetClientRandom(hello.random); len(r) == 32 {
        hello.random = r
    }
}
```

插入位置：第 235 行（`if err != nil { return err }`）之后，第 237 行（`session, earlySecret, ...`）之前。

**步骤 2：编译验证**

```bash
go build ./...
```

预期：无报错输出。

**步骤 3：运行相关测试**

```bash
go test -run TestHandshake -count=1 -timeout 60s
```

预期：PASS（无新失败项，已知失败项 `TestHandshakeMLKEM/GODEBUG_*` 除外）。

**步骤 4：提交**

```bash
git add handshake_client.go
git commit -m "feat(client): invoke GetClientRandom callback before sending ClientHello"
```

---

### 任务 1.3：定义自定义扩展类型常量

**涉及文件：**
- 修改：`common.go`（扩展类型常量区域）

**背景：**
`ZeroBits` 和 `ShareNodes` 是 wTLS 自定义的私有扩展，需要分配扩展类型号。TLS 私有使用范围为 `0xFF01–0xFFFF`（RFC 8446 Section 11）。选取：
- `extensionWTLSZeroBits  = 0xFF10`
- `extensionWTLSShareNodes = 0xFF11`

这两个常量用于 `marshal`/`unmarshal` 两侧编解码。

**步骤 1：在 `common.go` 中查找现有扩展常量块，添加两个新常量**

在已有的 `const` 块（`extensionServerName = 0`、`extensionALPN` 等附近）末尾追加：

```go
// wTLS 私有扩展（TLS 私有使用范围 0xFF01-0xFFFF）
extensionWTLSZeroBits   uint16 = 0xFF10 // EncryptedExtensions 中的二级 PoW 难度值
extensionWTLSShareNodes uint16 = 0xFF11 // EncryptedExtensions 中的节点信息清单
```

**步骤 2：编译验证**

```bash
go build ./...
```

**步骤 3：提交**

```bash
git add common.go
git commit -m "feat(extensions): define private extension type constants for ZeroBits and ShareNodes"
```

---

### 任务 1.4：扩展 `encryptedExtensionsMsg` 结构体并更新编解码

**涉及文件：**
- 修改：`handshake_messages.go`

**背景：**
`encryptedExtensionsMsg`（第 1003 行）目前不含 wTLS 字段。需要：
1. 添加 `zeroBits uint8` 和 `shareNodes []byte` 字段。
2. 在 `marshal()`（第 1011 行）中追加序列化逻辑。
3. 在 `unmarshal()`（第 1054 行）的 `switch` 分支（第 1078 行）中添加解析分支。

**步骤 1：在结构体中添加字段**

```go
type encryptedExtensionsMsg struct {
    alpnProtocol            string
    quicTransportParameters []byte
    earlyData               bool
    echRetryConfigs         []byte
    serverNameAck           bool
    // wTLS 扩展字段
    zeroBits   uint8  // 二级 PoW 难度值（前置零位长度），0 表示不启用
    shareNodes []byte // 服务端首次分享的节点信息清单
}
```

**步骤 2：在 `marshal()` 末尾（`serverNameAck` 序列化之后、`}` 关闭之前）添加序列化逻辑**

在 `marshal()` 函数内，`if m.serverNameAck { ... }` 代码块之后插入：

```go
if m.zeroBits > 0 {
    b.AddUint16(extensionWTLSZeroBits)
    b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
        b.AddUint8(m.zeroBits)
    })
}
if len(m.shareNodes) > 0 {
    b.AddUint16(extensionWTLSShareNodes)
    b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
        b.AddBytes(m.shareNodes)
    })
}
```

**步骤 3：在 `unmarshal()` 的 `switch extension` 中添加解析分支**

在 `case extensionServerName:` 块之后、`default:` 之前插入：

```go
case extensionWTLSZeroBits:
    if !extData.ReadUint8(&m.zeroBits) {
        return false
    }
case extensionWTLSShareNodes:
    m.shareNodes = make([]byte, len(extData))
    if !extData.CopyBytes(m.shareNodes) {
        return false
    }
```

**步骤 4：编译验证**

```bash
go build ./...
```

**步骤 5：运行握手消息相关测试**

```bash
go test -run TestMarshal -count=1 -timeout 30s
go test -run TestHandshakeServer -count=1 -timeout 60s
```

预期：PASS。

**步骤 6：提交**

```bash
git add handshake_messages.go
git commit -m "feat(messages): add ZeroBits and ShareNodes fields to encryptedExtensionsMsg"
```

---

### 任务 1.5：在 `Config` 和 `ConnectionState` 中暴露读取结果

**涉及文件：**
- 修改：`common.go`（`ConnectionState` 结构体）

**背景：**
客户端读取到 `ZeroBits` 和 `ShareNodes` 后，需要一个途径将其暴露给调用方。最简洁的方式是在 `ConnectionState` 中增加字段，握手完成后由 `readServerParameters`（`handshake_client_tls13.go:523`）填充。

**步骤 1：在 `ConnectionState` 结构体末尾添加字段**

```go
// WTLSZeroBits 是服务端通过 EncryptedExtensions 下发的二级 PoW 难度值。
// 值为 0 表示服务端未设置或不启用二级 PoW。
WTLSZeroBits uint8

// WTLSShareNodes 是服务端首次分享的节点信息清单（原始字节）。
// 空切片表示服务端未下发节点信息。
WTLSShareNodes []byte
```

**步骤 2：在 `Conn` 结构体中添加暂存字段**（位于 `conn.go`）

在 `Conn` 结构体内，紧靠 `clientProtocol string` 等协议状态字段附近，添加：

```go
// wTLS 扩展：服务端下发的自定义字段
wtlsZeroBits   uint8
wtlsShareNodes []byte
```

**步骤 3：在 `handshake_client_tls13.go` 的 `readServerParameters` 中填充**

定位 `readServerParameters`（约第 523 行），找到解析 `encryptedExtensions` 后的代码，在其 `unmarshal` 成功后追加：

```go
c.wtlsZeroBits = encryptedExtensions.zeroBits
c.wtlsShareNodes = encryptedExtensions.shareNodes
```

**步骤 4：在 `ConnectionState()` 方法中填充输出字段**

找到 `conn.go` 中 `ConnectionState()` 方法，在构造 `state` 结构体后追加：

```go
state.WTLSZeroBits = c.wtlsZeroBits
state.WTLSShareNodes = c.wtlsShareNodes
```

**步骤 5：编译验证**

```bash
go build ./...
```

**步骤 6：运行 TLS 1.3 客户端握手测试**

```bash
go test -run TestHandshakeClientTLS13 -count=1 -timeout 60s
```

预期：PASS。

**步骤 7：提交**

```bash
git add common.go conn.go handshake_client_tls13.go
git commit -m "feat(client): expose WTLSZeroBits and WTLSShareNodes via ConnectionState"
```

---

## 阶段二：服务端握手暂停钩子 + 写入自定义扩展

本阶段完成后，服务端可通过钩子暂停握手、读取 `ClientHello.random` 进行外部 PoW 验证，并向 `EncryptedExtensions` 注入 `ZeroBits` 和 `ShareNodes`。

---

### 任务 2.1：在 `Config` 中添加服务端 PoW 验证钩子

**涉及文件：**
- 修改：`common.go`

**背景：**
服务端需要在解析完 `ClientHello` 后、发送 `ServerHello` 之前，允许外部阻塞验证工作量。钩子签名使用 `context.Context` 支持超时取消，返回 `error` 表示验证失败（触发握手中断）。

**步骤 1：在 `Config` 中添加钩子字段**

```go
// VerifyClientRandom 如果非 nil，在服务端收到并解析 ClientHello 后调用。
// 参数 random 是客户端 ClientHello.random 字段（32 字节，只读）。
// 返回非 nil error 将中断握手并向客户端发送 alertHandshakeFailure。
// 工作量验证应在此回调中完成；回调可阻塞直至验证结束。
// 仅在 TLS 1.3 握手中生效。
VerifyClientRandom func(ctx context.Context, random []byte) error
```

注意 `context` 包需要确认 `common.go` 已导入；若未导入，需在 `import` 块中添加 `"context"`。

**步骤 2：编译验证**

```bash
go build ./...
```

**步骤 3：提交**

```bash
git add common.go
git commit -m "feat(config): add VerifyClientRandom hook field to Config"
```

---

### 任务 2.2：在 `processClientHello` 中提前调用验证钩子

**涉及文件：**
- 修改：`handshake_server_tls13.go`

**背景：**
`processClientHello`（第 108 行）的执行顺序如下：

1. 第 118–197 行：协议合法性检查（版本、压缩方式、renegotiation 等）——CPU 开销极低
2. **第 198–200 行：选定密码套件、初始化 transcript hash**
3. 第 210–247 行：选定 key exchange 曲线组，**可能触发 HelloRetryRequest（额外一次网络往返）**
4. **第 250–259 行：ECDH / MLKEM 服务端密钥交换计算**（`ke.serverSharedSecret`）——这是最昂贵的计算
5. 第 261–290 行：ALPN 协商、QUIC 参数检查

PoW 验证钩子应插在**第 200 行之后、第 210 行之前**——即密码套件确定（random 验证所需的上下文信息已齐全）之后，ECDH 运算和可能的 HelloRetryRequest 之前。这样一旦 PoW 不通过，直接中止，无需执行任何昂贵计算，也不会发出 HelloRetryRequest 报文。

注意 `hs.ctx` 是当前握手的 `context.Context`（来自 `serverHandshakeStateTLS13` 结构体）。

**步骤 1：在 `processClientHello` 的第 200 行（`hs.transcript = hs.suite.hash.New()`）之后、第 210 行（`preferredGroups := c.config.curvePreferences(...)`）之前插入**

```go
// wTLS: 在 ECDH 密钥交换之前调用外部 PoW 验证钩子（若已配置）。
// 验证失败则立即中断，避免后续昂贵的密钥交换计算。
if hook := c.config.VerifyClientRandom; hook != nil {
    if err := hook(hs.ctx, hs.clientHello.random); err != nil {
        c.sendAlert(alertHandshakeFailure)
        return err
    }
}
```

**步骤 2：编译验证**

```bash
go build ./...
```

**步骤 3：运行服务端握手测试**

```bash
go test -run TestHandshakeServer -count=1 -timeout 60s
```

预期：PASS（无新增失败项）。

**步骤 4：提交**

```bash
git add handshake_server_tls13.go
git commit -m "feat(server): invoke VerifyClientRandom hook before ECDH to fail fast on invalid PoW"
```

---

### 任务 2.3：在 `Config` 中添加服务端 EncryptedExtensions 注入回调

**涉及文件：**
- 修改：`common.go`

**背景：**
服务端需要在发送 `EncryptedExtensions` 前，允许外部填充 `ZeroBits` 和 `ShareNodes`。回调接收 `ClientHelloInfo`（已有类型）以便根据客户端信息动态决定下发内容。

**步骤 1：在 `Config` 中添加回调字段**

```go
// GetEncryptedExtensionsData 如果非 nil，在服务端即将发送 EncryptedExtensions 前调用。
// 返回 zeroBits（二级 PoW 难度）和 shareNodes（节点信息清单）。
// zeroBits 为 0 表示不启用二级 PoW；shareNodes 为 nil 表示不下发节点信息。
// 仅在 TLS 1.3 握手中生效。
GetEncryptedExtensionsData func(info *ClientHelloInfo) (zeroBits uint8, shareNodes []byte)
```

**步骤 2：编译验证**

```bash
go build ./...
```

**步骤 3：提交**

```bash
git add common.go
git commit -m "feat(config): add GetEncryptedExtensionsData callback to Config"
```

---

### 任务 2.4：在 `sendServerParameters` 中调用注入回调

**涉及文件：**
- 修改：`handshake_server_tls13.go`

**背景：**
`sendServerParameters`（第 714 行）在第 778 行构造 `encryptedExtensions`，在第 812 行发送。需在填充结构体（第 778–810 行）之后、发送（第 812 行）之前，调用注入回调并填充 wTLS 字段。

`clientHelloInfo(hs.ctx, c, hs.clientHello)` 是已有的工具函数，可直接调用。

**步骤 1：在 `sendServerParameters` 中，第 812 行（`writeHandshakeRecord`）之前插入**

```go
// wTLS: 注入自定义 EncryptedExtensions 字段（若已配置）
if fn := c.config.GetEncryptedExtensionsData; fn != nil {
    encryptedExtensions.zeroBits, encryptedExtensions.shareNodes = fn(clientHelloInfo(hs.ctx, c, hs.clientHello))
}
```

**步骤 2：编译验证**

```bash
go build ./...
```

**步骤 3：运行全量测试（排除已知失败项）**

```bash
go test -count=1 -timeout 120s ./... 2>&1 | grep -v "TestHandshakeMLKEM"
```

预期：无新增失败项。

**步骤 4：提交**

```bash
git add handshake_server_tls13.go
git commit -m "feat(server): inject ZeroBits and ShareNodes into EncryptedExtensions via callback"
```

---

## 阶段三：TLS 指纹规格配置接口

本阶段完成后，调用方可通过 `Config.ClientHelloSpec` 注入外部 TLS 指纹规格（如 uTLS 浏览器指纹），覆盖 `makeClientHello` 中由库自动生成的字段。

---

### 任务 3.1：定义 `ClientHelloSpec` 类型

**涉及文件：**
- 修改：`common.go`

**背景：**
TLS 指纹规格覆盖的字段主要为：`cipherSuites`、`supportedCurves`（命名曲线）、`supportedPoints`（点格式）、`supportedVersions`、`supportedSignatureAlgorithms`、`keyShares`（密钥交换组）等。调用方提供规格后，`makeClientHello` 用其覆盖自动生成值。

不引入新文件，直接在 `common.go` 中定义结构体。字段全部为可选（零值/nil 表示"不覆盖，使用默认值"），最大化兼容性。

**步骤 1：在 `common.go` 中（`Config` 定义之前）添加类型**

```go
// ClientHelloSpec 描述 ClientHello 的指纹规格，用于模拟特定 TLS 客户端实现。
// 非零字段将覆盖 makeClientHello 的默认值；零值/nil 字段保持不变。
// 仅在 TLS 1.3 握手中生效。
type ClientHelloSpec struct {
    // CipherSuites 覆盖 ClientHello 中通告的加密套件列表（含 TLS 1.3 套件）。
    CipherSuites []uint16
    // SupportedCurves 覆盖支持的命名曲线（elliptic curves / named groups）。
    SupportedCurves []CurveID
    // SupportedPoints 覆盖支持的点格式（通常为 []uint8{0}，即 uncompressed）。
    SupportedPoints []uint8
    // SupportedVersions 覆盖 supported_versions 扩展列表。
    SupportedVersions []uint16
    // SupportedSignatureAlgorithms 覆盖签名算法列表。
    SupportedSignatureAlgorithms []SignatureScheme
    // KeyShareCurves 指定 key_shares 扩展中实际发送密钥的曲线列表。
    // 若非 nil，makeClientHello 将只为此列表中的曲线生成 key share。
    KeyShareCurves []CurveID
}
```

**步骤 2：在 `Config` 结构体中添加引用字段**

```go
// ClientHelloSpec 若非 nil，用于覆盖 ClientHello 中的指纹相关字段。
// 使用此字段可模拟特定 TLS 客户端（如浏览器）的握手指纹。
// 仅在 TLS 1.3 握手中生效。
ClientHelloSpec *ClientHelloSpec
```

**步骤 3：编译验证**

```bash
go build ./...
```

**步骤 4：提交**

```bash
git add common.go
git commit -m "feat(config): define ClientHelloSpec type and add to Config"
```

---

### 任务 3.2：在 `makeClientHello` 中应用 `ClientHelloSpec`

**涉及文件：**
- 修改：`handshake_client.go`

**背景：**
`makeClientHello`（第 44 行）在函数末尾（返回 `hello` 之前）应用规格覆盖。`keyShareCurves` 的处理较复杂：`makeClientHello` 在后续代码（约第 127–200 行）中生成 key shares；需在生成之前先判断是否有 `KeyShareCurves` 覆盖，若有则将 `config.curvePreferences` 替换为指定列表。

最简实现：在 `hello` 构造完毕（约第 84 行 `}` 之后）、各字段后续处理之前，插入一个 `applyClientHelloSpec` 辅助函数调用；该函数只覆盖直接字段（CipherSuites、SupportedCurves 等），`KeyShareCurves` 则通过一个局部变量传递给后续 key share 生成逻辑。

**步骤 1：在 `handshake_client.go` 中添加辅助函数**（文件末尾或适当位置）

```go
// applyClientHelloSpec 将 spec 中非零字段覆盖到 hello。
// 返回 keyShareCurves（nil 表示使用默认曲线偏好）。
func applyClientHelloSpec(hello *clientHelloMsg, spec *ClientHelloSpec) (keyShareCurves []CurveID) {
    if spec == nil {
        return nil
    }
    if len(spec.CipherSuites) > 0 {
        hello.cipherSuites = spec.CipherSuites
    }
    if len(spec.SupportedCurves) > 0 {
        hello.supportedCurves = spec.SupportedCurves
    }
    if len(spec.SupportedPoints) > 0 {
        hello.supportedPoints = spec.SupportedPoints
    }
    if len(spec.SupportedVersions) > 0 {
        hello.supportedVersions = spec.SupportedVersions
    }
    if len(spec.SupportedSignatureAlgorithms) > 0 {
        hello.supportedSignatureAlgorithms = spec.SupportedSignatureAlgorithms
    }
    return spec.KeyShareCurves // nil 时外层逻辑使用默认曲线
}
```

**步骤 2：在 `makeClientHello` 中，`hello` 各字段生成完毕后调用**

`makeClientHello` 的结构大致为：
- 第 71–84 行：构造基础 `hello`
- 第 89–103 行：设置 cipherSuites
- 第 105–108 行：填充 random
- 第 122–125 行：设置 supportedSignatureAlgorithms
- 第 127 行起：生成 key shares

在第 122–125 行（`supportedSignatureAlgorithms` 设置）之后、第 127 行（`keyShareKeys` 生成）之前，插入：

```go
// wTLS: 应用 TLS 指纹规格覆盖
specKeyShareCurves := applyClientHelloSpec(hello, config.ClientHelloSpec)
```

然后在后续 key share 生成代码中，找到使用 `config.curvePreferences(maxVersion)` 决定 key share 曲线的地方（约第 140–200 行），将其条件改为：如果 `specKeyShareCurves != nil`，则用 `specKeyShareCurves` 替代。

具体地，找到类似如下的循环（生成 key shares 的地方）：

```go
// 原始代码（示例，需根据实际行号确认）：
for _, curveID := range config.curvePreferences(maxVersion) {
    ...
}
```

改为：

```go
ksaCurves := config.curvePreferences(maxVersion)
if len(specKeyShareCurves) > 0 {
    ksaCurves = specKeyShareCurves
}
for _, curveID := range ksaCurves {
    ...
}
```

> **注意：** 实施前请先阅读 `makeClientHello` 第 127–220 行，确认 key share 生成循环的实际位置和变量名，按实际代码修改，不要凭猜测。

**步骤 3：编译验证**

```bash
go build ./...
```

**步骤 4：运行客户端握手测试**

```bash
go test -run TestHandshakeClient -count=1 -timeout 60s
```

预期：PASS。

**步骤 5：提交**

```bash
git add handshake_client.go
git commit -m "feat(client): apply ClientHelloSpec to override ClientHello fingerprint fields"
```

---

## 验证整体

所有三个阶段完成后，运行全量测试以确保没有引入新的失败项：

```bash
go build ./...
go vet ./...
go test -count=1 -timeout 120s ./...
```

预期：
- `go build` 和 `go vet` 无输出（无错误）。
- 测试仅 `TestHandshakeMLKEM/GODEBUG_tlsmlkem=0` 和 `TestHandshakeMLKEM/GODEBUG_tlssecpmlkem=0` 两个子测试失败（已知问题，见 AGENTS.md）。

---

## 文件改动汇总

| 文件 | 改动性质 | 说明 |
|------|---------|------|
| `common.go` | 新增字段/类型 | `Config.GetClientRandom`、扩展常量、`Config.VerifyClientRandom`、`Config.GetEncryptedExtensionsData`、`ClientHelloSpec` 类型、`Config.ClientHelloSpec`、`ConnectionState.WTLSZeroBits/WTLSShareNodes` |
| `conn.go` | 新增字段 | `Conn.wtlsZeroBits`、`Conn.wtlsShareNodes`；`ConnectionState()` 方法填充 |
| `handshake_client.go` | 新增逻辑 | 调用 `GetClientRandom` 回调；`applyClientHelloSpec` 辅助函数；key share 曲线覆盖 |
| `handshake_client_tls13.go` | 新增逻辑 | `readServerParameters` 中读取 wTLS 扩展字段 |
| `handshake_messages.go` | 新增字段+编解码 | `encryptedExtensionsMsg` 添加 `zeroBits`/`shareNodes`；`marshal`/`unmarshal` 更新 |
| `handshake_server_tls13.go` | 新增逻辑 | `processClientHello` 末尾调用 `VerifyClientRandom`；`sendServerParameters` 调用注入回调 |
