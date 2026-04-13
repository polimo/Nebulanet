package main


import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)


func hkdfSHA256(secret, salt []byte, info string) [32]byte {
	// Extract
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	h := hmac.New(sha256.New, salt)
	h.Write(secret)
	prk := h.Sum(nil)
	// Expand (one 32-byte block is sufficient)
	h2 := hmac.New(sha256.New, prk)
	h2.Write([]byte(info))
	h2.Write([]byte{0x01})
	var out [32]byte
	copy(out[:], h2.Sum(nil))
	return out
}



func deriveKey(passphrase string) [32]byte { return sha256.Sum256([]byte(passphrase)) }

func generatePassphrase() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}



type Session struct {
	gcm         cipher.AEAD
	sendCounter atomic.Uint64
}

func newSession(key [32]byte) (*Session, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	s := &Session{gcm: gcm}
	s.sendCounter.Store(1)
	return s, nil
}

func (s *Session) Seal(plaintext []byte) []byte {
	ctr := s.sendCounter.Add(1) - 1
	var nonce [nonceSize]byte
	binary.LittleEndian.PutUint64(nonce[:8], ctr)
	out := make([]byte, nonceSize, nonceSize+len(plaintext)+gcmTagSize)
	copy(out, nonce[:])
	return s.gcm.Seal(out, nonce[:], plaintext, nil)
}

func (s *Session) Open(sealed []byte) ([]byte, error) {
	if len(sealed) < nonceSize+gcmTagSize {
		return nil, errors.New("crypto: sealed blob too short")
	}
	pt, err := s.gcm.Open(nil, sealed[:nonceSize], sealed[nonceSize:], nil)
	if err != nil {
		return nil, errors.New("crypto: authentication failed — packet corrupt or replayed")
	}
	return pt, nil
}

// ── Per-peer PFS session (PKI mode) ──────────────────────────────────────────

type peerSession struct {
	sendGCM   cipher.AEAD
	recvGCM   cipher.AEAD
	sendNonce atomic.Uint64
	expiresAt time.Time
}

// newPeerSession derives session keys from the ECDH shared secret.

func newPeerSession(sharedSecret, initPub, respPub []byte, initiator bool) (*peerSession, error) {
	
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = initPub[i] ^ respPub[i]
	}
	key1 := hkdfSHA256(sharedSecret, salt, "nebulanet-initiator-send-v2")
	key2 := hkdfSHA256(sharedSecret, salt, "nebulanet-responder-send-v2")

	var sendKey, recvKey [32]byte
	if initiator {
		sendKey, recvKey = key1, key2
	} else {
		sendKey, recvKey = key2, key1
	}

	sb, err := aes.NewCipher(sendKey[:])
	if err != nil {
		return nil, err
	}
	sg, err := cipher.NewGCM(sb)
	if err != nil {
		return nil, err
	}
	rb, err := aes.NewCipher(recvKey[:])
	if err != nil {
		return nil, err
	}
	rg, err := cipher.NewGCM(rb)
	if err != nil {
		return nil, err
	}

	s := &peerSession{
		sendGCM:   sg,
		recvGCM:   rg,
		expiresAt: time.Now().Add(5 * time.Minute),
	}
	s.sendNonce.Store(1)
	return s, nil
}

func (s *peerSession) Seal(plaintext []byte) []byte {
	ctr := s.sendNonce.Add(1) - 1
	var nonce [nonceSize]byte
	binary.LittleEndian.PutUint64(nonce[:8], ctr)
	out := make([]byte, nonceSize, nonceSize+len(plaintext)+gcmTagSize)
	copy(out, nonce[:])
	return s.sendGCM.Seal(out, nonce[:], plaintext, nil)
}

func (s *peerSession) Open(sealed []byte) ([]byte, error) {
	if len(sealed) < nonceSize+gcmTagSize {
		return nil, errors.New("crypto: peer session sealed too short")
	}
	pt, err := s.recvGCM.Open(nil, sealed[:nonceSize], sealed[nonceSize:], nil)
	if err != nil {
		return nil, errors.New("crypto: peer session auth failed")
	}
	return pt, nil
}

// ── node identity keypair ─────────────────────────────────────────────


func generateNodeKeypair() (*ecdh.PrivateKey, string, string, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", "", err
	}
	pubHex := hex.EncodeToString(priv.PublicKey().Bytes())
	privHex := hex.EncodeToString(priv.Bytes())
	return priv, pubHex, privHex, nil
}

func loadNodePrivKey(privHex string) (*ecdh.PrivateKey, error) {
	b, err := hex.DecodeString(strings.TrimSpace(privHex))
	if err != nil {
		return nil, fmt.Errorf("key: decode: %w", err)
	}
	return ecdh.X25519().NewPrivateKey(b)
}
