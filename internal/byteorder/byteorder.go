// Package byteorder 提供本模块内部使用的大端/小端整数编解码小工具。
//
// 标准库 crypto/tls 依赖同名的 internal/byteorder 包，但那是标准库私有包，
// fork 后的模块无法导入，因此在此重新实现所需的最小子集（纯位运算，
// 不涉及任何协议逻辑）。
package byteorder

// LEUint32 按小端序将 b 的前 4 个字节解析为 uint32。
func LEUint32(b []byte) uint32 {
	_ = b[3]
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// BEUint16 按大端序将 b 的前 2 个字节解析为 uint16。
func BEUint16(b []byte) uint16 {
	_ = b[1]
	return uint16(b[0])<<8 | uint16(b[1])
}

// LEAppendUint32 按小端序将 v 的 4 个字节追加到 b 之后。
func LEAppendUint32(b []byte, v uint32) []byte {
	return append(b,
		byte(v),
		byte(v>>8),
		byte(v>>16),
		byte(v>>24),
	)
}
