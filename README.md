# wTLS: TLS with Proof-of-Work

基于 Go 标准库 TLS fork 的定制版本，支持在 ClientHello/ServerHello 握手过程中完成工作量认证（首包即认证），附带支持 TLS 指纹规格的定制配置，以提供抗审查的灵活性。


## 定制部分

### 客户端

1. 开放 ClientHello 中 random 字段的设置（外部工作量计算后，设置到该值）。
2. 支持 ServerHello 加密扩展（EncryptedExtensions）自定义字段的读取（`ZeroBits`, `ShareNodes`）。
3. 支持 TLS 指纹规格的外部配置：比如复用 uTLS 的指纹规格模拟浏览器；模拟未来某流行App……

> **实现建议：**
> 提供一个回调接口，允许外部设置 random 字段的值。
> 在 ECH 模式下，外部设置 SNI 和 random 字段的值需在加密之前完成。
> TLS 指纹规格配置应当是一个通用的接口。


### 服务端

- 可由外部嵌入控制：读取 ClientHello.random 字段（用于验证工作量，外部负责），之后握手才继续。
- 可由外部向 ServerHello.EncryptedExtensions 中添加自定义字段：`ZeroBits`, `ShareNodes`。

> **实现建议：**
> 服务端允许外部注册 EncryptedExtensions 扩展，提前填充数据。


### 自定义字段

-  ZeroBits：uint8 类型，服务端设置的二级工作量认证的难度值（前置零位长度），客户端读取。
-  ShareNodes: []byte 类型，服务端向对端*首分享*的节点信息清单，它会与自签名证书合并加密。

> **提示 ：**
> 节点信息和自签名证书的合计数据量，应与浏览器建立连接时，服务端发送的证书链数据量相当。
> 这些数据会在 ServerHello 中加密传输，外部只能看到密文，因此相似的密文长度对于抗审查性具有重要意义。


### 注意

- 工作量的计算和验证逻辑完全由外部控制，库本身不包含任何与工作量相关的算法实现。
- 仅考虑 TLS 1.3 版本，TLS 1.2 及以下版本不在支持范围内。
- 由于是 fork 实现，为便于后期与 Go 标准库的更新合并，宜采用最小化修改的策略。

> **实现：**
> 注意 QUIC 的相关部分，如果被用于 QUIC 的底层支持，需要确保不会出错。


## 使用

（在项目完成后更新）
