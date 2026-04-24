// TLS 1.3 密钥调度实现（RFC 8446 Section 7.1）。
// 替代标准库 crypto/internal/fips140/tls13，供外部模块使用。
package tls13

import (
	"encoding/binary"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
)

// ExpandLabel 实现 RFC 8446 Section 7.1 的 HKDF-Expand-Label。
func ExpandLabel[H hash.Hash](h func() H, secret []byte, label string, context []byte, length int) []byte {
	if len("tls13 ")+len(label) > 255 || len(context) > 255 {
		panic("tls13: label or context too long")
	}
	hkdfLabel := make([]byte, 0, 2+1+len("tls13 ")+len(label)+1+len(context))
	hkdfLabel = binary.BigEndian.AppendUint16(hkdfLabel, uint16(length))
	hkdfLabel = append(hkdfLabel, byte(len("tls13 ")+len(label)))
	hkdfLabel = append(hkdfLabel, "tls13 "...)
	hkdfLabel = append(hkdfLabel, label...)
	hkdfLabel = append(hkdfLabel, byte(len(context)))
	hkdfLabel = append(hkdfLabel, context...)

	out := make([]byte, length)
	r := hkdf.Expand(func() hash.Hash { return h() }, secret, hkdfLabel)
	if _, err := io.ReadFull(r, out); err != nil {
		panic("tls13: hkdf expand failed: " + err.Error())
	}
	return out
}

func hExtract[H hash.Hash](h func() H, secret, salt []byte) []byte {
	if secret == nil {
		secret = make([]byte, h().Size())
	}
	return hkdf.Extract(func() hash.Hash { return h() }, secret, salt)
}

func deriveSecret[H hash.Hash](h func() H, secret []byte, label string, transcript hash.Hash) []byte {
	if transcript == nil {
		transcript = h()
	}
	return ExpandLabel(h, secret, label, transcript.Sum(nil), transcript.Size())
}

// EarlySecret 对应 TLS 1.3 密钥调度中的 Early Secret。
type EarlySecret struct {
	secret []byte
	hash   func() hash.Hash
}

// NewEarlySecret 从可选的 PSK 创建 EarlySecret。
func NewEarlySecret[H hash.Hash](h func() H, psk []byte) *EarlySecret {
	return &EarlySecret{
		secret: hExtract(h, psk, nil),
		hash:   func() hash.Hash { return h() },
	}
}

// ResumptionBinderKey 派生 res_binder_key。
func (s *EarlySecret) ResumptionBinderKey() []byte {
	return deriveSecret(s.hash, s.secret, "res binder", nil)
}

// ClientEarlyTrafficSecret 派生 client_early_traffic_secret。
func (s *EarlySecret) ClientEarlyTrafficSecret(transcript hash.Hash) []byte {
	return deriveSecret(s.hash, s.secret, "c e traffic", transcript)
}

// HandshakeSecret 从 ECDHE 共享密钥派生 HandshakeSecret。
func (s *EarlySecret) HandshakeSecret(sharedSecret []byte) *HandshakeSecret {
	derived := deriveSecret(s.hash, s.secret, "derived", nil)
	return &HandshakeSecret{
		secret: hExtract(s.hash, sharedSecret, derived),
		hash:   s.hash,
	}
}

// EarlyExporterMasterSecret 派生 early_exporter_master_secret。
func (s *EarlySecret) EarlyExporterMasterSecret(transcript hash.Hash) *ExporterMasterSecret {
	return &ExporterMasterSecret{
		secret: deriveSecret(s.hash, s.secret, "e exp master", transcript),
		hash:   s.hash,
	}
}

// HandshakeSecret 对应 TLS 1.3 密钥调度中的 Handshake Secret。
type HandshakeSecret struct {
	secret []byte
	hash   func() hash.Hash
}

// ClientHandshakeTrafficSecret 派生 client_handshake_traffic_secret。
func (s *HandshakeSecret) ClientHandshakeTrafficSecret(transcript hash.Hash) []byte {
	return deriveSecret(s.hash, s.secret, "c hs traffic", transcript)
}

// ServerHandshakeTrafficSecret 派生 server_handshake_traffic_secret。
func (s *HandshakeSecret) ServerHandshakeTrafficSecret(transcript hash.Hash) []byte {
	return deriveSecret(s.hash, s.secret, "s hs traffic", transcript)
}

// MasterSecret 派生 Master Secret。
func (s *HandshakeSecret) MasterSecret() *MasterSecret {
	derived := deriveSecret(s.hash, s.secret, "derived", nil)
	return &MasterSecret{
		secret: hExtract(s.hash, nil, derived),
		hash:   s.hash,
	}
}

// MasterSecret 对应 TLS 1.3 密钥调度中的 Master Secret。
type MasterSecret struct {
	secret []byte
	hash   func() hash.Hash
}

// ClientApplicationTrafficSecret 派生 client_application_traffic_secret_0。
func (s *MasterSecret) ClientApplicationTrafficSecret(transcript hash.Hash) []byte {
	return deriveSecret(s.hash, s.secret, "c ap traffic", transcript)
}

// ServerApplicationTrafficSecret 派生 server_application_traffic_secret_0。
func (s *MasterSecret) ServerApplicationTrafficSecret(transcript hash.Hash) []byte {
	return deriveSecret(s.hash, s.secret, "s ap traffic", transcript)
}

// ResumptionMasterSecret 派生 resumption_master_secret。
func (s *MasterSecret) ResumptionMasterSecret(transcript hash.Hash) []byte {
	return deriveSecret(s.hash, s.secret, "res master", transcript)
}

// ExporterMasterSecret 派生 exporter_master_secret。
func (s *MasterSecret) ExporterMasterSecret(transcript hash.Hash) *ExporterMasterSecret {
	return &ExporterMasterSecret{
		secret: deriveSecret(s.hash, s.secret, "exp master", transcript),
		hash:   s.hash,
	}
}

// ExporterMasterSecret 用于 RFC 5705 密钥导出。
type ExporterMasterSecret struct {
	secret []byte
	hash   func() hash.Hash
}

// Exporter 实现 RFC 8446 Section 7.5 的密钥导出。
func (s *ExporterMasterSecret) Exporter(label string, context []byte, length int) []byte {
	secret := deriveSecret(s.hash, s.secret, label, nil)
	h := s.hash()
	h.Write(context)
	return ExpandLabel(s.hash, secret, "exporter", h.Sum(nil), length)
}

// TestingOnlyExporterSecret 仅供测试使用，返回内部 secret。
func TestingOnlyExporterSecret(s *ExporterMasterSecret) []byte {
	return s.secret
}
