// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/ecdh"
	"crypto/fips140"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/mlkem"
	"errors"
	"hash"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

// This file contains the functions necessary to compute the TLS 1.3 key
// schedule. See RFC 8446, Section 7.
//
// 原实现经由 crypto/internal/fips140/tls13（FIPS 校验边界内实现）完成，
// fork 后不再追求 FIPS 140 认证边界，改为按 RFC 8446 §7.1/§7.2/§7.3/§7.5
// 直接用公开的 crypto/hkdf 重新实现完整的 TLS 1.3 密钥编排（key schedule）。

// expandLabel implements HKDF-Expand-Label from RFC 8446, Section 7.1.
func expandLabel(h func() hash.Hash, secret []byte, label string, context []byte, length int) []byte {
	var hkdfLabel cryptobyte.Builder
	hkdfLabel.AddUint16(uint16(length))
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("tls13 "))
		b.AddBytes([]byte(label))
	})
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(context)
	})
	out, err := hkdf.Expand(h, secret, string(hkdfLabel.BytesOrPanic()), length)
	if err != nil {
		// Expand 仅在请求长度过大时才会返回错误，
		// 而 TLS 1.3 场景下的长度都在其允许范围内。
		panic(err)
	}
	return out
}

// deriveSecret implements Derive-Secret from RFC 8446, Section 7.1.
//
// transcript 为 nil 时等价于消息集合为空（即哈希空字符串）。
func deriveSecret(h func() hash.Hash, secret []byte, label string, transcript hash.Hash) []byte {
	var transcriptBytes []byte
	if transcript != nil {
		transcriptBytes = transcript.Sum(nil)
	} else {
		transcriptBytes = h().Sum(nil)
	}
	return expandLabel(h, secret, label, transcriptBytes, h().Size())
}

// extract implements HKDF-Extract, panicking on the (practically
// unreachable for TLS 1.3) error case.
func extract(h func() hash.Hash, secret, salt []byte) []byte {
	out, err := hkdf.Extract(h, secret, salt)
	if err != nil {
		panic(err)
	}
	return out
}

// EarlySecret 对应 RFC 8446 §7.1 密钥编排图中的 Early Secret。
type EarlySecret struct {
	secret []byte
	hash   func() hash.Hash
}

// NewEarlySecret 由 PSK（会话恢复场景）或零值（无 PSK 的初始握手）计算 Early Secret。
func NewEarlySecret(h func() hash.Hash, psk []byte) *EarlySecret {
	if psk == nil {
		psk = make([]byte, h().Size())
	}
	salt := make([]byte, h().Size())
	return &EarlySecret{secret: extract(h, psk, salt), hash: h}
}

// ResumptionBinderKey 对应 Derive-Secret(., "res binder", "")。
// Go 的 crypto/tls 仅实现基于会话恢复的 PSK，不支持外部 PSK，
// 因此始终使用 "res binder" 标签。
func (s *EarlySecret) ResumptionBinderKey() []byte {
	return deriveSecret(s.hash, s.secret, "res binder", nil)
}

// ClientEarlyTrafficSecret 对应 Derive-Secret(., "c e traffic", ClientHello)。
func (s *EarlySecret) ClientEarlyTrafficSecret(transcript hash.Hash) []byte {
	return deriveSecret(s.hash, s.secret, "c e traffic", transcript)
}

// EarlyExporterMasterSecret 对应 Derive-Secret(., "e exp master", ClientHello)。
func (s *EarlySecret) EarlyExporterMasterSecret(transcript hash.Hash) *ExporterMasterSecret {
	return &ExporterMasterSecret{secret: deriveSecret(s.hash, s.secret, "e exp master", transcript), hash: s.hash}
}

// HandshakeSecret 由 Early Secret 和 (EC)DHE 共享密钥计算得到 Handshake Secret。
func (s *EarlySecret) HandshakeSecret(sharedSecret []byte) *HandshakeSecret {
	preSecret := deriveSecret(s.hash, s.secret, "derived", nil)
	salt := make([]byte, s.hash().Size())
	copy(salt, preSecret)
	return &HandshakeSecret{secret: extract(s.hash, sharedSecret, salt), hash: s.hash}
}

// HandshakeSecret 对应密钥编排图中的 Handshake Secret。
type HandshakeSecret struct {
	secret []byte
	hash   func() hash.Hash
}

// ClientHandshakeTrafficSecret 对应
// Derive-Secret(., "c hs traffic", ClientHello...ServerHello)。
func (s *HandshakeSecret) ClientHandshakeTrafficSecret(transcript hash.Hash) []byte {
	return deriveSecret(s.hash, s.secret, "c hs traffic", transcript)
}

// ServerHandshakeTrafficSecret 对应
// Derive-Secret(., "s hs traffic", ClientHello...ServerHello)。
func (s *HandshakeSecret) ServerHandshakeTrafficSecret(transcript hash.Hash) []byte {
	return deriveSecret(s.hash, s.secret, "s hs traffic", transcript)
}

// MasterSecret 由 Handshake Secret 计算得到 Master Secret。
func (s *HandshakeSecret) MasterSecret() *MasterSecret {
	preSecret := deriveSecret(s.hash, s.secret, "derived", nil)
	ikm := make([]byte, s.hash().Size())
	return &MasterSecret{secret: extract(s.hash, ikm, preSecret), hash: s.hash}
}

// MasterSecret 对应密钥编排图中的 Master Secret。
type MasterSecret struct {
	secret []byte
	hash   func() hash.Hash
}

// ClientApplicationTrafficSecret 对应
// Derive-Secret(., "c ap traffic", ClientHello...server Finished)。
func (s *MasterSecret) ClientApplicationTrafficSecret(transcript hash.Hash) []byte {
	return deriveSecret(s.hash, s.secret, "c ap traffic", transcript)
}

// ServerApplicationTrafficSecret 对应
// Derive-Secret(., "s ap traffic", ClientHello...server Finished)。
func (s *MasterSecret) ServerApplicationTrafficSecret(transcript hash.Hash) []byte {
	return deriveSecret(s.hash, s.secret, "s ap traffic", transcript)
}

// ResumptionMasterSecret 对应
// Derive-Secret(., "res master", ClientHello...client Finished)。
func (s *MasterSecret) ResumptionMasterSecret(transcript hash.Hash) []byte {
	return deriveSecret(s.hash, s.secret, "res master", transcript)
}

// ExporterMasterSecret 对应 Derive-Secret(., "exp master", ClientHello...server Finished)。
func (s *MasterSecret) ExporterMasterSecret(transcript hash.Hash) *ExporterMasterSecret {
	return &ExporterMasterSecret{secret: deriveSecret(s.hash, s.secret, "exp master", transcript), hash: s.hash}
}

// ExporterMasterSecret 用于计算 RFC 8446 §7.5 定义的 keying material exporter。
type ExporterMasterSecret struct {
	secret []byte
	hash   func() hash.Hash
}

// Exporter 实现 RFC 8446 §7.5 的 TLS-Exporter：
//
//	TLS-Exporter(label, context_value, key_length) =
//	    HKDF-Expand-Label(Derive-Secret(Secret, label, ""),
//	                       "exporter", Hash(context_value), key_length)
func (s *ExporterMasterSecret) Exporter(label string, context []byte, length int) []byte {
	derivedSecret := deriveSecret(s.hash, s.secret, label, nil)
	h := s.hash()
	h.Write(context)
	contextHash := h.Sum(nil)
	return expandLabel(s.hash, derivedSecret, "exporter", contextHash, length)
}

// nextTrafficSecret generates the next traffic secret, given the current one,
// according to RFC 8446, Section 7.2.
func (c *cipherSuiteTLS13) nextTrafficSecret(trafficSecret []byte) []byte {
	return expandLabel(c.hash.New, trafficSecret, "traffic upd", nil, c.hash.Size())
}

// trafficKey generates traffic keys according to RFC 8446, Section 7.3.
func (c *cipherSuiteTLS13) trafficKey(trafficSecret []byte) (key, iv []byte) {
	key = expandLabel(c.hash.New, trafficSecret, "key", nil, c.keyLen)
	iv = expandLabel(c.hash.New, trafficSecret, "iv", nil, aeadNonceLength)
	return
}

// finishedHash generates the Finished verify_data or PskBinderEntry according
// to RFC 8446, Section 4.4.4. See sections 4.4 and 4.2.11.2 for the baseKey
// selection.
func (c *cipherSuiteTLS13) finishedHash(baseKey []byte, transcript hash.Hash) []byte {
	finishedKey := expandLabel(c.hash.New, baseKey, "finished", nil, c.hash.Size())
	verifyData := hmac.New(c.hash.New, finishedKey)
	verifyData.Write(transcript.Sum(nil))
	return verifyData.Sum(nil)
}

// exportKeyingMaterial implements RFC5705 exporters for TLS 1.3 according to
// RFC 8446, Section 7.5.
func (c *cipherSuiteTLS13) exportKeyingMaterial(s *MasterSecret, transcript hash.Hash) func(string, []byte, int) ([]byte, error) {
	expMasterSecret := s.ExporterMasterSecret(transcript)
	return func(label string, context []byte, length int) ([]byte, error) {
		return expMasterSecret.Exporter(label, context, length), nil
	}
}

type keySharePrivateKeys struct {
	ecdhe *ecdh.PrivateKey
	mlkem crypto.Decapsulator
}

// A keyExchange implements a TLS 1.3 KEM.
type keyExchange interface {
	// keyShares generates one or two key shares.
	//
	// The first one will match the id, the second (if present) reuses the
	// traditional component of the requested hybrid, as allowed by
	// draft-ietf-tls-hybrid-design-09, Section 3.2.
	keyShares(rand io.Reader) (*keySharePrivateKeys, []keyShare, error)

	// serverSharedSecret computes the shared secret and the server's key share.
	serverSharedSecret(rand io.Reader, clientKeyShare []byte) ([]byte, keyShare, error)

	// clientSharedSecret computes the shared secret given the server's key
	// share and the keys generated by keyShares.
	clientSharedSecret(priv *keySharePrivateKeys, serverKeyShare []byte) ([]byte, error)
}

func keyExchangeForCurveID(id CurveID) (keyExchange, error) {
	newMLKEMPrivateKey768 := func(b []byte) (crypto.Decapsulator, error) {
		return mlkem.NewDecapsulationKey768(b)
	}
	newMLKEMPrivateKey1024 := func(b []byte) (crypto.Decapsulator, error) {
		return mlkem.NewDecapsulationKey1024(b)
	}
	newMLKEMPublicKey768 := func(b []byte) (crypto.Encapsulator, error) {
		return mlkem.NewEncapsulationKey768(b)
	}
	newMLKEMPublicKey1024 := func(b []byte) (crypto.Encapsulator, error) {
		return mlkem.NewEncapsulationKey1024(b)
	}
	switch id {
	case X25519:
		return &ecdhKeyExchange{id, ecdh.X25519()}, nil
	case CurveP256:
		return &ecdhKeyExchange{id, ecdh.P256()}, nil
	case CurveP384:
		return &ecdhKeyExchange{id, ecdh.P384()}, nil
	case CurveP521:
		return &ecdhKeyExchange{id, ecdh.P521()}, nil
	case X25519MLKEM768:
		return &hybridKeyExchange{id, ecdhKeyExchange{X25519, ecdh.X25519()},
			32, mlkem.EncapsulationKeySize768, mlkem.CiphertextSize768,
			newMLKEMPrivateKey768, newMLKEMPublicKey768}, nil
	case SecP256r1MLKEM768:
		return &hybridKeyExchange{id, ecdhKeyExchange{CurveP256, ecdh.P256()},
			65, mlkem.EncapsulationKeySize768, mlkem.CiphertextSize768,
			newMLKEMPrivateKey768, newMLKEMPublicKey768}, nil
	case SecP384r1MLKEM1024:
		return &hybridKeyExchange{id, ecdhKeyExchange{CurveP384, ecdh.P384()},
			97, mlkem.EncapsulationKeySize1024, mlkem.CiphertextSize1024,
			newMLKEMPrivateKey1024, newMLKEMPublicKey1024}, nil
	default:
		return nil, errors.New("tls: unsupported key exchange")
	}
}

type ecdhKeyExchange struct {
	id    CurveID
	curve ecdh.Curve
}

func (ke *ecdhKeyExchange) keyShares(rand io.Reader) (*keySharePrivateKeys, []keyShare, error) {
	priv, err := ke.curve.GenerateKey(rand)
	if err != nil {
		return nil, nil, err
	}
	return &keySharePrivateKeys{ecdhe: priv}, []keyShare{{ke.id, priv.PublicKey().Bytes()}}, nil
}

func (ke *ecdhKeyExchange) serverSharedSecret(rand io.Reader, clientKeyShare []byte) ([]byte, keyShare, error) {
	key, err := ke.curve.GenerateKey(rand)
	if err != nil {
		return nil, keyShare{}, err
	}
	peerKey, err := ke.curve.NewPublicKey(clientKeyShare)
	if err != nil {
		return nil, keyShare{}, err
	}
	sharedKey, err := key.ECDH(peerKey)
	if err != nil {
		return nil, keyShare{}, err
	}
	return sharedKey, keyShare{ke.id, key.PublicKey().Bytes()}, nil
}

func (ke *ecdhKeyExchange) clientSharedSecret(priv *keySharePrivateKeys, serverKeyShare []byte) ([]byte, error) {
	peerKey, err := ke.curve.NewPublicKey(serverKeyShare)
	if err != nil {
		return nil, err
	}
	sharedKey, err := priv.ecdhe.ECDH(peerKey)
	if err != nil {
		return nil, err
	}
	return sharedKey, nil
}

type hybridKeyExchange struct {
	id   CurveID
	ecdh ecdhKeyExchange

	ecdhElementSize     int
	mlkemPublicKeySize  int
	mlkemCiphertextSize int

	newMLKEMPrivateKey func([]byte) (crypto.Decapsulator, error)
	newMLKEMPublicKey  func([]byte) (crypto.Encapsulator, error)
}

func (ke *hybridKeyExchange) keyShares(rand io.Reader) (*keySharePrivateKeys, []keyShare, error) {
	var (
		priv       *keySharePrivateKeys
		ecdhShares []keyShare
		err        error
	)
	fips140.WithoutEnforcement(func() { // Hybrid of ML-KEM, which is Approved.
		priv, ecdhShares, err = ke.ecdh.keyShares(rand)
	})
	if err != nil {
		return nil, nil, err
	}
	seed := make([]byte, mlkem.SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, nil, err
	}
	priv.mlkem, err = ke.newMLKEMPrivateKey(seed)
	if err != nil {
		return nil, nil, err
	}
	var shareData []byte
	// For X25519MLKEM768, the ML-KEM-768 encapsulation key comes first.
	// For SecP256r1MLKEM768 and SecP384r1MLKEM1024, the ECDH share comes first.
	// See draft-ietf-tls-ecdhe-mlkem-02, Section 4.1.
	if ke.id == X25519MLKEM768 {
		shareData = append(priv.mlkem.Encapsulator().Bytes(), ecdhShares[0].data...)
	} else {
		shareData = append(ecdhShares[0].data, priv.mlkem.Encapsulator().Bytes()...)
	}
	return priv, []keyShare{{ke.id, shareData}, ecdhShares[0]}, nil
}

func (ke *hybridKeyExchange) serverSharedSecret(rand io.Reader, clientKeyShare []byte) ([]byte, keyShare, error) {
	if len(clientKeyShare) != ke.ecdhElementSize+ke.mlkemPublicKeySize {
		return nil, keyShare{}, errors.New("tls: invalid client key share length for hybrid key exchange")
	}
	var ecdhShareData, mlkemShareData []byte
	if ke.id == X25519MLKEM768 {
		mlkemShareData = clientKeyShare[:ke.mlkemPublicKeySize]
		ecdhShareData = clientKeyShare[ke.mlkemPublicKeySize:]
	} else {
		ecdhShareData = clientKeyShare[:ke.ecdhElementSize]
		mlkemShareData = clientKeyShare[ke.ecdhElementSize:]
	}
	var (
		ecdhSharedSecret []byte
		ks               keyShare
		err              error
	)
	fips140.WithoutEnforcement(func() { // Hybrid of ML-KEM, which is Approved.
		ecdhSharedSecret, ks, err = ke.ecdh.serverSharedSecret(rand, ecdhShareData)
	})
	if err != nil {
		return nil, keyShare{}, err
	}
	mlkemPeerKey, err := ke.newMLKEMPublicKey(mlkemShareData)
	if err != nil {
		return nil, keyShare{}, err
	}
	mlkemSharedSecret, mlkemKeyShare := mlkemPeerKey.Encapsulate()
	var sharedKey []byte
	if ke.id == X25519MLKEM768 {
		sharedKey = append(mlkemSharedSecret, ecdhSharedSecret...)
		ks.data = append(mlkemKeyShare, ks.data...)
	} else {
		sharedKey = append(ecdhSharedSecret, mlkemSharedSecret...)
		ks.data = append(ks.data, mlkemKeyShare...)
	}
	ks.group = ke.id
	return sharedKey, ks, nil
}

func (ke *hybridKeyExchange) clientSharedSecret(priv *keySharePrivateKeys, serverKeyShare []byte) ([]byte, error) {
	if len(serverKeyShare) != ke.ecdhElementSize+ke.mlkemCiphertextSize {
		return nil, errors.New("tls: invalid server key share length for hybrid key exchange")
	}
	var ecdhShareData, mlkemShareData []byte
	if ke.id == X25519MLKEM768 {
		mlkemShareData = serverKeyShare[:ke.mlkemCiphertextSize]
		ecdhShareData = serverKeyShare[ke.mlkemCiphertextSize:]
	} else {
		ecdhShareData = serverKeyShare[:ke.ecdhElementSize]
		mlkemShareData = serverKeyShare[ke.ecdhElementSize:]
	}
	var (
		ecdhSharedSecret []byte
		err              error
	)
	fips140.WithoutEnforcement(func() { // Hybrid of ML-KEM, which is Approved.
		ecdhSharedSecret, err = ke.ecdh.clientSharedSecret(priv, ecdhShareData)
	})
	if err != nil {
		return nil, err
	}
	mlkemSharedSecret, err := priv.mlkem.Decapsulate(mlkemShareData)
	if err != nil {
		return nil, err
	}
	var sharedKey []byte
	if ke.id == X25519MLKEM768 {
		sharedKey = append(mlkemSharedSecret, ecdhSharedSecret...)
	} else {
		sharedKey = append(ecdhSharedSecret, mlkemSharedSecret...)
	}
	return sharedKey, nil
}
