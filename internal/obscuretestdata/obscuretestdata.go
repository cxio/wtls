// 最小化 internal/obscuretestdata stub。
package obscuretestdata

// Rot13 对字节切片中的字母字符做 ROT13 变换。
func Rot13(data []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		switch {
		case b >= 'A' && b <= 'Z':
			out[i] = 'A' + (b-'A'+13)%26
		case b >= 'a' && b <= 'z':
			out[i] = 'a' + (b-'a'+13)%26
		default:
			out[i] = b
		}
	}
	return out
}
