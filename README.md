# wTLS: TLS with Proof-of-Work

基于 Go 标准库 `crypto/tls` fork 的定制版本，支持在 ClientHello/ServerHello 握手过程中完成工作量认证（首包即认证），附带支持 TLS 指纹规格的定制配置，以提供抗审查的灵活性。


## 定制部分

### 客户端

1. 开放 ClientHello 中 random 字段的设置（外部工作量计算后，设置到该值）。
2. 支持 ServerHello 加密扩展（EncryptedExtensions）自定义字段的读取（`ZeroBits`, `ShareNodes`）。
3. 支持 TLS 指纹规格的外部配置：比如复用 uTLS 的指纹规格模拟浏览器；模拟未来某流行App……

> **实现：**
> - 提供一个回调接口，允许外部设置 random 字段的值。
> - 在 ECH 模式下，外部设置 SNI 和 random 字段的值需在加密之前完成。
> - TLS 指纹规格配置应当是一个通用的接口。


### 服务端

- 可由外部嵌入控制：读取 ClientHello.random 字段（用于验证工作量，外部负责），之后握手才继续。
- 可由外部向 ServerHello.EncryptedExtensions 中添加自定义字段：`ZeroBits`, `ShareNodes`。

> **实现：**
> 服务端允许外部注册 EncryptedExtensions 扩展，提前填充数据。


### 自定义字段

-  ZeroBits：uint8 类型，服务端设置的二级工作量认证的难度值（前置零位长度），客户端读取。
-  ShareNodes: []byte 类型，服务端向对端*首分享*的节点信息清单，它会与自签名证书合并加密。

> **提示：**
> - 节点信息和自签名证书的合计数据量，应与浏览器建立连接时，服务端发送的证书链数据量相当。
> - 这些数据会在 ServerHello 中加密传输，外部只能看到密文，因此相似的密文长度对于抗审查性具有重要意义。


### 注意

- 工作量的计算和验证逻辑完全由外部控制，库本身不包含任何与工作量相关的算法实现。
- 仅考虑 TLS 1.3 版本，TLS 1.2 及以下版本不在支持范围内。
- 由于是 fork 实现，为便于后期与 Go 标准库的更新合并，宜采用最小化修改的策略。

> **实现：**
> 注意 QUIC 的相关部分，如果被用于 QUIC 的底层支持，需要确保不会出错。


## 使用

```go
import "github.com/cxio/wtls"
```

### 客户端：注入工作量证明到 ClientHello.random

```go
cfg := &wtls.Config{
    // 在 ClientHello 发出前，将外部计算的 PoW 写入 random 字段。
    // 若返回值长度不为 32，保持原始随机值不变。
    GetClientRandom: func(random []byte) []byte {
        pow := computePoW(random) // 调用方自行实现
        return pow                // 必须恰好 32 字节
    },
}
conn, err := wtls.Dial("tcp", "example.com:443", cfg)
```

### 客户端：读取服务端下发的自定义扩展字段

```go
conn, err := wtls.Dial("tcp", "example.com:443", cfg)
if err != nil { ... }

state := conn.ConnectionState()
zeroBits  := state.WTLSZeroBits   // uint8，二级 PoW 难度（0 表示未启用）
shareNodes := state.WTLSShareNodes // []byte，服务端分享的节点信息清单
```

### 客户端：配置 TLS 指纹规格（模拟浏览器等）

```go
cfg := &wtls.Config{
    // 覆盖 ClientHello 中的指纹相关字段，模拟特定客户端实现。
    // 未设置（nil/零值）的字段保持默认值不变。
    ClientHelloSpec: &wtls.ClientHelloSpec{
        CipherSuites:                 []uint16{wtls.TLS_AES_128_GCM_SHA256, wtls.TLS_AES_256_GCM_SHA384},
        SupportedCurves:              []wtls.CurveID{wtls.X25519, wtls.CurveP256},
        SupportedSignatureAlgorithms: []wtls.SignatureScheme{wtls.ECDSAWithP256AndSHA256},
        KeyShareCurves:               []wtls.CurveID{wtls.X25519}, // 只为该曲线生成 key share
    },
}
```

### 服务端：验证 ClientHello.random 中的工作量

```go
cfg := &wtls.Config{
    Certificates: []wtls.Certificate{cert},

    // 在 ECDH 密钥交换之前调用，可阻塞直至验证完成。
    // 返回非 nil error 将向客户端发送 handshake_failure 并中断握手。
    VerifyClientRandom: func(ctx context.Context, random []byte) error {
        if !verifyPoW(random) { // 调用方自行实现
            return errors.New("invalid proof of work")
        }
        return nil
    },
}
ln, _ := wtls.Listen("tcp", ":443", cfg)
```

### 服务端：向 EncryptedExtensions 注入自定义字段

```go
cfg := &wtls.Config{
    Certificates: []wtls.Certificate{cert},

    // 在发送 EncryptedExtensions 前调用，返回值将注入到加密扩展中。
    // zeroBits 为 0 表示不启用二级 PoW；shareNodes 为 nil 表示不下发节点信息。
    GetEncryptedExtensionsData: func(info *wtls.ClientHelloInfo) (zeroBits uint8, shareNodes []byte) {
        return 20, getShareNodes(info) // 调用方自行实现
    },
}
```
