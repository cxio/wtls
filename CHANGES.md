# CHANGES

## 2026-04-22

标准 crypto/tls 包正常 fork 修复，主要处理 internal 的问题。

### stub/vendor 包

创建了以下 **stub/vendor** 包，统一放在 `wtls/internal/` 下：

| 包路径 | 替换的原始包 | 实现方式 |
|--------|-------------|---------|
| byteorder	| byteorder | 逐字复制自 GOROOT |
| cpu	| cpu | 桥接到 golang.org/x/sys/cpu |
| godebug	| godebug | 最小实现（读 $GODEBUG 环境变量） |
| tls12	| crypto/internal/fips140/tls12 | 用标准库 crypto/hmac 重新实现 |
| tls13	| crypto/internal/fips140/tls13 | 用 golang.org/x/crypto/hkdf 重新实现 |
| boring	| crypto/boring | no-op stub（Enabled() 返回 false） |
| testenv	| testenv | 最小测试辅助实现 |
| obscuretestdata	| obscuretestdata | ROT13 实现 |
