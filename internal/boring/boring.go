// crypto/boring stub：提供与标准库 crypto/boring 兼容的 no-op 实现。
// 在非 BoringCrypto 工具链下使用。
package boring

// Enabled 报告当前是否使用 BoringCrypto，此 stub 始终返回 false。
func Enabled() bool {
	return false
}
