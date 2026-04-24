# AGENTS.md — wTLS 代理工作指南

## 项目定位

`github.com/cxio/wtls` 是对 Go 标准库 `crypto/tls`（go1.26.2）的最小化 fork，包名为 `wtls`。目标是在 TLS 1.3 握手中支持工作量证明（PoW）认证。**当前状态：fork 基础已完成，定制 API 尚未实现**（见 README 的"使用"节）。

## 常用命令

```bash
go build ./...          # 编译检查，无输出表示通过
go vet ./...            # 静态分析
go test -run TestXxx -count=1 -timeout 60s   # 运行单个测试
go test ./...           # 全量测试（耗时较长，有已知失败项）
```

## 已知测试失败（不要去修它）

`TestHandshakeMLKEM/GODEBUG_tlsmlkem=0` 和 `TestHandshakeMLKEM/GODEBUG_tlssecpmlkem=0` 两个子测试**固定失败**。

原因：`internal/godebug` 用 `sync.Once` 缓存 `$GODEBUG` 环境变量，`t.Setenv` 在测试运行中改变环境变量后不会刷新缓存，导致 GODEBUG 控制路径无法被测试覆盖。这是 stub 实现的已知限制，非业务 bug。

## 内部 stub/vendor 包

以下 `internal/` 包是为绕过 Go 标准库 `internal` 访问限制而手动 stub 的：

| 包 | 替代原始包 | 注意 |
|----|-----------|------|
| `internal/godebug` | `internal/godebug` | `sync.Once` 缓存，测试中 `t.Setenv` 无效 |
| `internal/boring` | `crypto/boring` | no-op，`Enabled()` 永远返回 `false` |
| `internal/cpu` | `internal/cpu` | 桥接 `golang.org/x/sys/cpu` |
| `internal/fips140/tls12` | `crypto/internal/fips140/tls12` | 用标准 `crypto/hmac` 重实现 |
| `internal/fips140/tls13` | `crypto/internal/fips140/tls13` | 用 `golang.org/x/crypto/hkdf` 重实现 |
| `internal/byteorder` | `internal/byteorder` | 逐字复制自 GOROOT |
| `internal/testenv` | `internal/testenv` | 最小测试辅助 |
| `internal/obscuretestdata` | `internal/obscuretestdata` | ROT13 实现 |

修改时：先确认原始标准库接口，再同步更新 stub。

## 设计约束

- **仅支持 TLS 1.3**，TLS 1.2 及以下版本不在 wTLS 定制范围（标准逻辑仍保留）。
- **工作量的计算/验证逻辑全部由外部调用方实现**，本库不内置任何 PoW 算法。
- **最小化修改原则**：每次改动应尽量小，以便后续跟进 Go 标准库更新合并。
- QUIC 相关路径需保持不出错（`quic.go`），改动握手流程时注意检查。

## 计划中的定制 API（尚未实现）

参考 README：

- **客户端**：开放 `ClientHello.random` 字段的外部回调设置；读取 `EncryptedExtensions` 中的 `ZeroBits`（uint8）和 `ShareNodes`（[]byte）；支持外部注入 TLS 指纹规格（比如作为用户，可直接配置使用 uTLS 的浏览器指纹规格数据）。
- **服务端**：握手暂停钩子，供外部读取 `ClientHello.random` 验证工作量；向 `EncryptedExtensions` 注入 `ZeroBits` 和 `ShareNodes`。

实现时应在 `handshake_client_tls13.go`、`handshake_server_tls13.go`、`handshake_messages.go` 中最小化修改。

## BoGo 兼容测试

`bogo_config.json` 记录了所有跳过的 BoGo 测试及原因，分两类：
- 永久跳过（如 DTLS、QUIC、0-RTT、SSLv2、GREASE 回退）
- 临时 TODO（标注 "first pass, this should be fixed"）

运行 BoGo 测试前需要 BoringSSL 工具链（当前模块版本 `v0.0.0-20250620172916-f51d8b099832`）。

## 模块信息

```
module github.com/cxio/wtls
go 1.26.2
依赖: golang.org/x/crypto v0.50.0, golang.org/x/sys v0.43.0
```

## 收尾工作

每次完成 docs/plans/ 下的实现计划后：

- 将被修改的文件列入 docs/modified/ 下的同名文件中，包含简要说明。
- 若有必要，补充 README.md 中的使用说明和示例代码。
