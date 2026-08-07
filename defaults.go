// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"slices"
)

// Defaults are collected in this file to allow distributions to more easily patch
// them to apply local policies.
//
// 原实现使用 internal/godebug 提供一批面向存量用户的迁移期兼容开关
// （如 tlsmlkem、tlssecpmlkem、tlsrsakex、tls3des 等）。internal/godebug
// 是标准库私有包，fork 后的模块无法导入；又因 wTLS 是新项目、不背历史
// 兼容包袱，这里直接去掉这些开关，固定采用当前最新、最安全的默认行为。
//
// fips140tlsRequired 原由 crypto/tls/internal/fips140tls（标准库内部子包）
// 提供，用于判断是否启用 FIPS140-only 模式的版本/套件限制。wTLS 不提供
// 该模式，因此恒为 false。
func fips140tlsRequired() bool { return false }

// defaultCurvePreferences is the default set of supported key exchanges, as
// well as the preference order.
func defaultCurvePreferences() []CurveID {
	return []CurveID{
		X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024,
		X25519, CurveP256, CurveP384, CurveP521,
	}
}

// defaultSupportedSignatureAlgorithms returns the signature and hash algorithms that
// the code advertises and supports in a TLS 1.2+ ClientHello and in a TLS 1.2+
// CertificateRequest. The two fields are merged to match with TLS 1.3.
// Note that in TLS 1.2, the ECDSA algorithms are not constrained to P-256, etc.
func defaultSupportedSignatureAlgorithms() []SignatureScheme {
	return []SignatureScheme{
		PSSWithSHA256,
		ECDSAWithP256AndSHA256,
		Ed25519,
		PSSWithSHA384,
		PSSWithSHA512,
		PKCS1WithSHA256,
		PKCS1WithSHA384,
		PKCS1WithSHA512,
		ECDSAWithP384AndSHA384,
		ECDSAWithP521AndSHA512,
		PKCS1WithSHA1,
		ECDSAWithSHA1,
	}
}

func supportedCipherSuites(aesGCMPreferred bool) []uint16 {
	if aesGCMPreferred {
		return slices.Clone(cipherSuitesPreferenceOrder)
	} else {
		return slices.Clone(cipherSuitesPreferenceOrderNoAES)
	}
}

// defaultCipherSuites 固定禁用 RSA 密钥交换与 3DES 密码套件（不再提供
// GODEBUG=tlsrsakex=1 / tls3des=1 这类回退开关）。
func defaultCipherSuites(aesGCMPreferred bool) []uint16 {
	cipherSuites := supportedCipherSuites(aesGCMPreferred)
	return slices.DeleteFunc(cipherSuites, func(c uint16) bool {
		return disabledCipherSuites[c] || rsaKexCiphers[c] || tdesCiphers[c]
	})
}

// defaultCipherSuitesTLS13 is also the preference order, since there are no
// disabled by default TLS 1.3 cipher suites. The same AES vs ChaCha20 logic as
// cipherSuitesPreferenceOrder applies.
//
// defaultCipherSuitesTLS13 原实现通过 //go:linkname 暴露给第三方包
// （见 cipher_suites.go 对应说明），fork 后不再保留该编译指令。
var defaultCipherSuitesTLS13 = []uint16{
	TLS_AES_128_GCM_SHA256,
	TLS_AES_256_GCM_SHA384,
	TLS_CHACHA20_POLY1305_SHA256,
}

// defaultCipherSuitesTLS13NoAES 同上，不再保留 //go:linkname 编译指令。
var defaultCipherSuitesTLS13NoAES = []uint16{
	TLS_CHACHA20_POLY1305_SHA256,
	TLS_AES_128_GCM_SHA256,
	TLS_AES_256_GCM_SHA384,
}
