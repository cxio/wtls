# wTLS PoW API 修改文件清单

本次实现（分支 `feature/wtls-pow-api`，共 11 个提交）涉及以下 `.go` 文件：

| 文件 | +行 | 改动说明 |
|------|-----|---------|
| `common.go` | +62 | 新增 `ClientHelloSpec` 类型；<br>`Config` 添加 `GetClientRandom`、`ClientHelloSpec`、`VerifyClientRandom`、`GetEncryptedExtensionsData` 字段；<br>`ConnectionState` 添加 `WTLSZeroBits`、`WTLSShareNodes` 字段；<br>扩展常量 `extensionWTLSZeroBits`、`extensionWTLSShareNodes`；<br>`Clone()` 同步新字段。 |
| `conn.go` | +6 | `Conn` 结构体添加 `wtlsZeroBits`、`wtlsShareNodes` 暂存字段；<br>`ConnectionState()` 方法填充对应输出。 |
| `handshake_client.go` | +46 | `clientHandshake` 中调用 `GetClientRandom` 回调；<br>新增 `applyClientHelloSpec` 辅助函数；<br>`makeClientHello` 中应用 `ClientHelloSpec` 并处理 `KeyShareCurves` 优先级。 |
| `handshake_client_tls13.go` | +4 | `readServerParameters` 中读取 `encryptedExtensions.zeroBits`/`shareNodes` 并写入 `Conn`。 |
| `handshake_messages.go` | +24 | `encryptedExtensionsMsg` 添加 `zeroBits`/`shareNodes` 字段；<br>`marshal()` 序列化逻辑；<br>`unmarshal()` 解析分支。 |
| `handshake_server_tls13.go` | +14 | `processClientHello` 中在 ECDH 前调用 `VerifyClientRandom` 钩子；<br>`sendServerParameters` 中调用 `GetEncryptedExtensionsData` 注入回调。 |
| `tls_test.go` | +4 | `TestCloneNonFuncFields` 豁免列表补充新函数字段；<br>`ClientHelloSpec` 指针字段的反射赋值 case。 |
