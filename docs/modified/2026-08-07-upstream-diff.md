# 相对上游 `crypto/tls` 的结构性差异

> 上游基线：Go 1.26.5 标准库 `crypto/tls`（`$GOROOT/src/crypto/tls`）。
> 本文档记录 fork 过程中相对上游源码所做的**结构性**改动，供后续随 Go 版本更新做 diff/合并参考。逐行细节差异请直接用 `diff`/`git diff` 对比对应文件。

## 包名与模块

- 包名保持原始 `tls`；导入路径为 `github.com/cxio/wtls`。
- 新增仓库根目录 `LICENSE`（Go 官方 BSD-3-Clause 许可证文本，署名保留 The Go Authors）与 `PATENTS` 文件，满足上游许可证的署名/再分发条件。
- 每个复制过来的文件均保留原始 `// Copyright ... The Go Authors...` 版权头。

## 未 fork 的文件/功能（有意裁剪）

| 上游文件/功能 | 处理方式 | 原因 |
|---|---|---|
| `defaults_boring.go`、`fipsonly/` | 不 fork | 不提供 BoringCrypto 支持 |
| `bogo_shim*.go`、`bogo_config.json` | 暂不 fork | BoGo（BoringSSL）互操作测试基础设施，留待后续评估是否需要 |
| `generate_cert.go` | 不 fork | `package main` 的独立脚本工具，非库 API 的一部分 |
| `internal/godebug` 提供的历史兼容开关（`tlsrsakex`、`tls3des`、`tlssha1`、`tlsmaxrsasize`、`tlsunsafeekm`、`x509keypairleaf`、`tls10server`、`tlsmlkem`、`tlssecpmlkem`） | 全部移除，固定采用各开关的"新（更安全）默认行为" | wTLS 是新项目，不需要为存量用户保留迁移期回退开关；这些开关均为运行时 `if` 分支的可用性开关，移除后是纯粹的行为简化，不影响协议正确性 |

## 因 Go 内部私有包（`internal/...`）不可外部导入而做的替换

Fork 后的模块位于标准库之外，无法导入任何 `internal/` 前缀的包（Go 编译器强制的可见性规则）。以下是每一处阻塞及其替换方案：

| 阻塞的内部依赖 | 替换方案 | 涉及文件 |
|---|---|---|
| `internal/byteorder` | 在本模块下新增等价的 `internal/byteorder`（仅实现实际用到的 `LEUint32`/`LEAppendUint32`，纯位运算重新实现） | `handshake_server_tls13.go` |
| `internal/cpu` | 移除硬件加速探测分支，`hasAESGCMHardwareSupport` 固定为 `true`（仅影响 AES-GCM 密码套件的偏好排序，不影响正确性） | `cipher_suites.go` |
| `internal/godebug` | 见上表，直接移除对应开关及其判断分支 | `common.go`、`conn.go`、`defaults.go`、`handshake_client.go`、`handshake_server.go`、`key_agreement.go`、`auth.go`、`tls.go` |
| `crypto/internal/boring` | 移除 `boring.Enabled`/`boring.Unreachable()` 等分支，统一走非 boring 路径 | `cipher_suites.go` |
| `crypto/internal/fips140/aes`、`crypto/internal/fips140/aes/gcm` | 改用公开 `crypto/aes` + `crypto/cipher.NewGCM` 构造 AES-GCM AEAD（`aeadAESGCM`/`aeadAESGCMTLS13`） | `cipher_suites.go` |
| `crypto/internal/fips140/tls12` | 按 RFC 5246 §5 用本文件已有的 `pHash` 重新实现 `prf12`；`extMasterFromPreMasterSecret` 统一走本地 PRF，不再区分 TLS1.2 的 FIPS 分支 | `prf.go` |
| `crypto/internal/fips140/tls13` | 按 RFC 8446 §7.1/7.2/7.3/7.5 用公开 `crypto/hkdf` 完整重新实现 TLS 1.3 密钥编排：`expandLabel`（HKDF-Expand-Label）、`deriveSecret`（Derive-Secret）、`EarlySecret`/`HandshakeSecret`/`MasterSecret`/`ExporterMasterSecret` 类型及其派生方法 | 新写入 `key_schedule.go`；调用点分布在 `handshake_client.go`、`handshake_client_tls13.go`、`handshake_server_tls13.go` |
| `crypto/tls/internal/fips140tls` | 新增 `fips140tlsRequired()` 函数（`defaults.go`），恒返回 `false`；原上游 `fips140tls.Required()` 调用点全部替换为该函数 | `common.go`、`handshake_client.go`、`handshake_server.go`、`handshake_server_tls13.go` |
| `vendor/golang.org/x/crypto/{chacha20poly1305,cryptobyte}` | 改为对真实公开模块 `golang.org/x/crypto` 的正式 `go.mod` 依赖（`go get golang.org/x/crypto`），导入路径不变（`golang.org/x/crypto/chacha20poly1305`、`golang.org/x/crypto/cryptobyte`） | `cipher_suites.go`、`key_schedule.go`、`ech.go` 等 |

### `fips_allowlists.go`（原 `defaults_fips140.go`）

该文件本身不依赖任何内部私有包（只用了公开的 `crypto/ecdsa`、`crypto/ed25519`、`crypto/elliptic`、`crypto/rsa`、`crypto/x509`），因此按原样保留（去掉了原来与 `defaults_boring.go` 互斥的 `//go:build !boringcrypto` 约束）。由于 `fips140tlsRequired()` 恒为 `false`，本文件中的 allow-list 目前是死代码，保留只是为了与上游保持逐行一致、便于未来 diff；如确认不再需要，可整体删除并同步清理各调用点。

## `//go:linkname` 编译指令的处理

上游部分标识符（`cipherSuitesTLS13`、`defaultCipherSuitesTLS13`、`defaultCipherSuitesTLS13NoAES`、`errNoCertificates`、`aeadAESGCMTLS13`）标注了 `//go:linkname`，用于允许 `github.com/quic-go/quic-go`、`github.com/xtls/xray-core` 等第三方包通过链接名直接访问 `crypto/tls` 包内的未导出符号。

该机制按**精确的包导入路径**匹配（如 `"crypto/tls".cipherSuitesTLS13`），对 fork 后的 `github.com/cxio/wtls` 没有意义（没有第三方代码会以这个新路径做 linkname）。因此所有 `//go:linkname` 编译指令及配套的 `_ "unsafe" // for linkname` 空导入均已移除，仅保留变量/函数本身。


## 测试迁移

### 已迁移的测试文件

`testdata/`（122 个文件）以及以下 `_test.go`：
`auth_test.go`、`cache_test.go`、`conn_test.go`、`ech_test.go`、`example_test.go`、
`handshake_client_test.go`、`handshake_messages_test.go`、`handshake_server_test.go`、
`handshake_test.go`、`handshake_unix_test.go`、`key_schedule_test.go`、`prf_test.go`、
`quic_test.go`、`ticket_test.go`、`tls_test.go`。

### 未迁移的测试文件（有意跳过）

| 文件 | 原因 |
|---|---|
| `bogo_shim_test.go`、`bogo_shim_unix_test.go`、`bogo_shim_notunix_test.go`、`bogo_config.json` | BoringSSL BoGo 互操作测试套件，需要外部 checkout `boringssl.googlesource.com/boringssl.git` 及 `ssl/test/runner`，基础设施成本高，且与 wTLS 的自定义特性无直接关系，本轮不迁移 |
| `fips140_test.go` | 专测 FIPS140-only 模式（`runWithFIPSEnabled`/`runWithFIPSDisabled`），wTLS 不提供该模式，整份文件的前提不成立 |
| `link_test.go` | 通过子进程 `go build` + `go tool nm` 校验 `//go:linkname` 暴露的符号是否存在；wTLS 已移除所有 `//go:linkname`（见上文"`//go:linkname` 编译指令的处理"一节），该测试的前提同样不成立 |

### 因迁移/裁剪产生的测试适配

- **`internal/testenv` → 本地 `mustHaveExternalNetwork`**（`tls_test.go`）：仅重新实现 `MustHaveExternalNetwork` 用到的简单判断（`runtime.GOOS`、`testing.Short()`），供 `TestVerifyHostname`/`TestRealResumption` 使用。
- **`crypto/internal/boring`/`crypto/tls/internal/fips140tls`/`crypto/fips140` → 移除或替换为 `fips140tlsRequired()`**：`tls_test.go` 中 `runWithFIPSEnabled`/`runWithFIPSDisabled`（仅被已跳过的 `fips140_test.go` 使用）已删除；其余 `fips140tls.Required()` 调用点替换为本包的 `fips140tlsRequired()`（恒 false）。`TestHandshakeMLKEM`、`tls_test.go:1313` 附近的 FIPS 专用跳过分支因恒为 false 直接删除。
- **`internal/byteorder` → `github.com/cxio/wtls/internal/byteorder`**（`handshake_client_test.go`）：补充了测试用到的 `BEUint16`。
- **`crypto/internal/fips140/tls13` → 本包 `key_schedule.go` 类型**（`key_schedule_test.go`，即 NIST ACVP 公开测试向量 `TestACVPVectors`）：`tls13.NewEarlySecret` 改为直接调用本包 `NewEarlySecret`；`tls13.TestingOnlyExporterSecret(x)` 改为直接访问同包可见的 `x.secret` 字段（不再需要标准库那种跨包访问的 TestingOnly 包装函数）。补充实现了 `EarlySecret.EarlyExporterMasterSecret` 方法（对应 RFC 8446 §7.1 的 "e exp master" 分支，此前实现遗漏）。
- **`example_test.go`**：删除了 `ExampleConfig_keyLogWriter`、`ExampleX509KeyPair_httpServer` 两个示例。原因：`net/http.Server.TLSConfig` 与 `net/http/httptest.Server.TLS` 字段类型硬编码为标准库 `*crypto/tls.Config`，wTLS 作为不同导入路径的 fork 无法直接赋值给这两个字段——这是任何非 `crypto/tls` 本身的 fork 都存在的天然限制，不是迁移遗漏。
- **GODEBUG 相关测试用例清理**：由于生产代码侧已移除 `tlssha1`/`tlsmlkem`/`tlssecpmlkem`/`x509keypairleaf` 等 GODEBUG 开关（见上文），相应依赖这些开关"恢复旧行为"的测试用例/子测试已同步删除或简化：
  - `auth_test.go` `TestSignatureSelection`：删除依赖 `GODEBUG=tlssha1=1` 的 4 行测试数据及 `godebug` 字段/环境变量注入逻辑（`badTests` 表中验证 SHA-1 应被拒绝的用例保持不变，天然与新默认行为吻合）。
  - `tls_test.go` `TestHandshakeMLKEM`：删除 "GODEBUG tlsmlkem=0"、"GODEBUG tlssecpmlkem=0" 两个子测试。
  - `tls_test.go` `TestX509KeyPairPopulateCertificate`：删除 "x509keypairleaf=0" 子测试，保留验证 `Leaf` 恒被填充的子测试。

### 验证结果

```
gofmt -l .        # 无输出（全部已格式化）
go vet ./...      # 通过
go build ./...    # 通过
go test ./... -count=1         # 通过
go test ./... -count=1 -race   # 通过
go test ./... -count=1 -short  # 通过（跳过依赖真实外部网络的测试）
```

## 尚未完成

- BoGo 互操作测试套件、`fips140_test.go`、`link_test.go` 仍未迁移（见上）。
- 尚未实现定制功能，当前只是一个能编译通过、测试通过、协议行为与上游等价的"干净基线"。
