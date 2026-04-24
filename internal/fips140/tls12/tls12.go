// TLS 1.2 PRF 与扩展主密钥派生（RFC 5246 / RFC 7627）。
// 替代标准库 crypto/internal/fips140/tls12，供外部模块使用。
package tls12

import (
	"crypto/hmac"
	"hash"
)

// PRF 实现 TLS 1.2 伪随机函数（RFC 5246 Section 5）。
func PRF[H hash.Hash](hash func() H, secret []byte, label string, seed []byte, keyLen int) []byte {
	labelAndSeed := make([]byte, len(label)+len(seed))
	copy(labelAndSeed, label)
	copy(labelAndSeed[len(label):], seed)
	result := make([]byte, keyLen)
	pHash(hash, result, secret, labelAndSeed)
	return result
}

func pHash[H hash.Hash](h func() H, result, secret, seed []byte) {
	hh := func() hash.Hash { return h() }
	mac := hmac.New(hh, secret)
	mac.Write(seed)
	a := mac.Sum(nil)
	for len(result) > 0 {
		mac.Reset()
		mac.Write(a)
		mac.Write(seed)
		b := mac.Sum(nil)
		n := copy(result, b)
		result = result[n:]
		mac = hmac.New(hh, secret)
		mac.Write(a)
		a = mac.Sum(nil)
	}
}

const (
	masterSecretLength        = 48
	extendedMasterSecretLabel = "extended master secret"
)

// MasterSecret 实现 TLS 1.2 扩展主密钥派生（RFC 7627）。
func MasterSecret[H hash.Hash](hash func() H, preMasterSecret, transcript []byte) []byte {
	return PRF(hash, preMasterSecret, extendedMasterSecretLabel, transcript, masterSecretLength)
}
