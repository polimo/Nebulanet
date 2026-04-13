package main

// ══════════════════════════════════════════════════════════════════════════════
// CERTIFICATE AUTHORITY (PKI)
//
// Certificate trust flow:
//   1. Admin starts `nebulanet signal` → CA keypair created, pubkey printed.
//   2. Each operator runs `nebulanet gencert` → server signs, node saves cert.
//   3. At join time, each node sends its cert; peers validate the CA signature
//      before accepting any ECDH handshake from that node.
//   4. No node can claim a VPN IP it was never issued.
// ══════════════════════════════════════════════════════════════════════════════

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// NodeCert is an Ed25519-signed certificate binding a node's X25519 public key
type NodeCert struct {
	PeerID    string `json:"peer_id"`
	NetworkID string `json:"net"`
	VPNIP     string `json:"vpn_ip"` 
	PubKeyHex string `json:"pub"`     
	NotAfter  int64  `json:"exp"`     
	SigHex    string `json:"sig"`    
}

// signedBytes returns the canonical byte slice that the CA signs.
func (c *NodeCert) signedBytes() []byte {
	return []byte(fmt.Sprintf("nebulanet-cert-v1\n%s\n%s\n%s\n%s\n%d",
		c.PeerID, c.NetworkID, c.VPNIP, c.PubKeyHex, c.NotAfter))
}

// Verify checks the CA signature and certificate expiry.
func (c *NodeCert) Verify(caPub ed25519.PublicKey) error {
	sig, err := hex.DecodeString(c.SigHex)
	if err != nil {
		return fmt.Errorf("cert: decode sig: %w", err)
	}
	if !ed25519.Verify(caPub, c.signedBytes(), sig) {
		return errors.New("cert: CA signature invalid")
	}
	if time.Now().Unix() > c.NotAfter {
		return fmt.Errorf("cert: expired at %s",
			time.Unix(c.NotAfter, 0).Format(time.RFC3339))
	}
	return nil
}

// X25519PublicKey decodes the node's long-term X25519 public key from the cert.
func (c *NodeCert) X25519PublicKey() (*ecdh.PublicKey, error) {
	b, err := hex.DecodeString(c.PubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("cert: decode pubkey: %w", err)
	}
	return ecdh.X25519().NewPublicKey(b)
}

// CertRequest is the JSON payload sent by a node to request a signed cert.
type CertRequest struct {
	PeerID    string `json:"peer_id"`
	NetworkID string `json:"net"`
	VPNIP     string `json:"vpn_ip"`
	PubKeyHex string `json:"pub"` // hex X25519 public key
}

// caSignCert creates and signs a NodeCert for req using the CA private key.
func caSignCert(req CertRequest, caPriv ed25519.PrivateKey, certTTL time.Duration) (*NodeCert, error) {
	cert := &NodeCert{
		PeerID:    req.PeerID,
		NetworkID: req.NetworkID,
		VPNIP:     req.VPNIP,
		PubKeyHex: req.PubKeyHex,
		NotAfter:  time.Now().Add(certTTL).Unix(),
	}
	sig := ed25519.Sign(caPriv, cert.signedBytes())
	cert.SigHex = hex.EncodeToString(sig)
	return cert, nil
}

// loadOrCreateCAKey loads an Ed25519 CA key from path, or creates one.
func loadOrCreateCAKey(path string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		b, err := hex.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, nil, fmt.Errorf("ca: decode key file: %w", err)
		}
		priv := ed25519.PrivateKey(b)
		return priv, priv.Public().(ed25519.PublicKey), nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(priv)), 0600); err != nil {
		return nil, nil, fmt.Errorf("ca: write key file: %w", err)
	}
	return priv, pub, nil
}
