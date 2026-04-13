package main

// ══════════════════════════════════════════════════════════════════════════════
// WIRE PROTOCOL
//
// Every UDP datagram begins with a 1-byte message type.
//
// Signaling (to/from signal server):
//   MsgRegister   – join network; carries a cert in PKI mode
//   MsgAck        – server echoes our public NAT endpoint (+ CA public key in PKI mode)
//   MsgPeerList   – server pushes peers (carries their certs in PKI mode)
//   MsgCertReq    – request the CA to sign a new node certificate
//   MsgCertResp   – CA returns the signed cert (or error)
//
// Data-plane (peer-to-peer):
//   MsgPunch / MsgPunchOK – simultaneous NAT hole-punch probes
//   MsgData               – AES-256-GCM encrypted Ethernet / IP frame
//   MsgKeepalive          – NAT mapping heartbeat
//   MsgChat               – encrypted overlay chat message
//   MsgHandshakeInit      – initiates ephemeral ECDH key exchange (PFS)
//   MsgHandshakeResp      – completes the ECDH exchange
//
// Relay (through signal server when direct P2P fails):
//   MsgRelayData  – wrapped packet routed through the signal server
//
// MsgRelayData wire layout:
//   ┌──────┬────────────┬──────────┬────────────┬──────────┬─────────────┐
//   │ Type │ src_id_len │  src_id  │ dst_id_len │  dst_id  │  payload…   │
//   │  1 B │    1 B     │  N bytes │    1 B     │  M bytes │  variable   │
//   └──────┴────────────┴──────────┴────────────┴──────────┴─────────────┘
//
// MsgHandshakeInit/Resp wire layout:
//   ┌──────┬──────────────────┬──────────────┬───────────────────┐
//   │ Type │ ephem_pub(32 B)  │ cert_len(2B) │  cert_json…       │
//   └──────┴──────────────────┴──────────────┴───────────────────┘
// ══════════════════════════════════════════════════════════════════════════════

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
)

const (
	// Signaling
	MsgRegister byte = 0x01
	MsgAck      byte = 0x02
	MsgPeerList byte = 0x03
	MsgCertReq  byte = 0x0C
	MsgCertResp byte = 0x0D
	// Data-plane
	MsgPunch     byte = 0x04
	MsgPunchOK   byte = 0x05
	MsgData      byte = 0x06
	MsgKeepalive byte = 0x07
	MsgChat      byte = 0x08
	// PFS handshake
	MsgHandshakeInit byte = 0x09
	MsgHandshakeResp byte = 0x0A
	// Relay
	MsgRelayData byte = 0x0B
)

const (
	nonceSize  = 12 // AES-GCM nonce length
	gcmTagSize = 16 // AES-GCM authentication tag length
)

// ── Basic protocol types ──────────────────────────────────────────────────────

// RegisterPayload is sent by a client to join an overlay network.

type RegisterPayload struct {
	NetworkID string
	PeerID    string
	VPNIP     net.IP
	Cert      *NodeCert
}

func marshalRegister(p RegisterPayload) ([]byte, error) {
	if len(p.NetworkID) > 64 || len(p.PeerID) > 64 {
		return nil, errors.New("proto: NetworkID/PeerID exceeds 64 bytes")
	}
	ip4 := p.VPNIP.To4()
	if ip4 == nil {
		return nil, errors.New("proto: only IPv4 VPN addresses are supported")
	}
	buf := []byte{MsgRegister}
	buf = append(buf, byte(len(p.NetworkID)))
	buf = append(buf, p.NetworkID...)
	buf = append(buf, byte(len(p.PeerID)))
	buf = append(buf, p.PeerID...)
	buf = append(buf, ip4...)
	// Optional cert.
	if p.Cert != nil {
		certJSON, err := json.Marshal(p.Cert)
		if err != nil {
			return nil, err
		}
		if len(certJSON) > 65535 {
			return nil, errors.New("proto: cert too large")
		}
		clen := make([]byte, 2)
		binary.BigEndian.PutUint16(clen, uint16(len(certJSON)))
		buf = append(buf, clen...)
		buf = append(buf, certJSON...)
	} else {
		buf = append(buf, 0, 0) 
	}
	return buf, nil
}

func unmarshalRegister(b []byte) (RegisterPayload, error) {
	bad := func(s string) (RegisterPayload, error) { return RegisterPayload{}, errors.New("proto: " + s) }
	if len(b) < 3 {
		return bad("register too short")
	}
	off := 1
	nLen := int(b[off])
	off++
	if off+nLen > len(b) {
		return bad("truncated networkID")
	}
	networkID := string(b[off : off+nLen])
	off += nLen
	if off >= len(b) {
		return bad("truncated after networkID")
	}
	pLen := int(b[off])
	off++
	if off+pLen > len(b) {
		return bad("truncated peerID")
	}
	peerID := string(b[off : off+pLen])
	off += pLen
	if off+4 > len(b) {
		return bad("truncated IP")
	}
	vpnIP := net.IP(b[off : off+4]).To16()
	off += 4
	// Optional cert.
	var cert *NodeCert
	if off+2 <= len(b) {
		cLen := int(binary.BigEndian.Uint16(b[off : off+2]))
		off += 2
		if cLen > 0 && off+cLen <= len(b) {
			cert = new(NodeCert)
			if err := json.Unmarshal(b[off:off+cLen], cert); err != nil {
				return bad("cert JSON: " + err.Error())
			}
		}
	}
	return RegisterPayload{NetworkID: networkID, PeerID: peerID, VPNIP: vpnIP, Cert: cert}, nil
}

// PeerEntry describes one peer in the overlay.
type PeerEntry struct {
	PeerID     string
	VPNIP      net.IP
	PublicAddr *net.UDPAddr
	Cert       *NodeCert

// marshalAck encodes the ACK response. caPub may be nil in legacy mode.
func marshalAck(pub *net.UDPAddr, caPub ed25519.PublicKey) []byte {
	b := make([]byte, 7)
	b[0] = MsgAck
	copy(b[1:5], pub.IP.To4())
	binary.BigEndian.PutUint16(b[5:7], uint16(pub.Port))
	if len(caPub) == ed25519.PublicKeySize {
		b = append(b, caPub...)
	}
	return b
}

// unmarshalAck decodes a MsgAck. Returns the endpoint and, in PKI mode, the
func unmarshalAck(b []byte) (*net.UDPAddr, ed25519.PublicKey, error) {
	if len(b) < 7 {
		return nil, nil, errors.New("proto: ack too short")
	}
	addr := &net.UDPAddr{
		IP:   net.IP(b[1:5]).To16(),
		Port: int(binary.BigEndian.Uint16(b[5:7])),
	}
	if len(b) >= 7+ed25519.PublicKeySize {
		return addr, ed25519.PublicKey(b[7 : 7+ed25519.PublicKeySize]), nil
	}
	return addr, nil, nil
}

func marshalPeerList(peers []PeerEntry) ([]byte, error) {
	if len(peers) > 255 {
		return nil, errors.New("proto: too many peers")
	}
	buf := []byte{MsgPeerList, byte(len(peers))}
	for _, p := range peers {
		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, uint16(p.PublicAddr.Port))
		buf = append(buf, byte(len(p.PeerID)))
		buf = append(buf, p.PeerID...)
		buf = append(buf, p.VPNIP.To4()...)
		buf = append(buf, p.PublicAddr.IP.To4()...)
		buf = append(buf, port...)
		// Cert.
		if p.Cert != nil {
			certJSON, err := json.Marshal(p.Cert)
			if err != nil {
				return nil, err
			}
			clen := make([]byte, 2)
			binary.BigEndian.PutUint16(clen, uint16(len(certJSON)))
			buf = append(buf, clen...)
			buf = append(buf, certJSON...)
		} else {
			buf = append(buf, 0, 0)
		}
	}
	return buf, nil
}

func unmarshalPeerList(b []byte) ([]PeerEntry, error) {
	if len(b) < 2 {
		return nil, errors.New("proto: peer list too short")
	}
	count := int(b[1])
	off := 2
	peers := make([]PeerEntry, 0, count)
	for i := 0; i < count; i++ {
		if off >= len(b) {
			return nil, errors.New("proto: truncated peer list")
		}
		pLen := int(b[off])
		off++
		if off+pLen > len(b) {
			return nil, errors.New("proto: truncated peer id")
		}
		peerID := string(b[off : off+pLen])
		off += pLen
		if off+10 > len(b) {
			return nil, errors.New("proto: truncated peer addrs")
		}
		vpnIP := net.IP(b[off : off+4]).To16()
		off += 4
		pubIP := net.IP(b[off : off+4]).To16()
		off += 4
		pubPort := int(binary.BigEndian.Uint16(b[off : off+2]))
		off += 2
		var cert *NodeCert
		if off+2 <= len(b) {
			cLen := int(binary.BigEndian.Uint16(b[off : off+2]))
			off += 2
			if cLen > 0 && off+cLen <= len(b) {
				cert = new(NodeCert)
				if err := json.Unmarshal(b[off:off+cLen], cert); err != nil {
					cert = nil
				}
				off += cLen
			}
		}
		peers = append(peers, PeerEntry{
			PeerID:     peerID,
			VPNIP:      vpnIP,
			PublicAddr: &net.UDPAddr{IP: pubIP, Port: pubPort},
			Cert:       cert,
		})
	}
	return peers, nil
}

// Chat payload helpers.
func marshalChatPayload(sender, text string) ([]byte, error) {
	if len(sender) > 255 {
		return nil, errors.New("chat: sender name exceeds 255 bytes")
	}
	if len(text) > 2048 {
		return nil, errors.New("chat: message exceeds 2048 bytes")
	}
	buf := []byte{byte(len(sender))}
	buf = append(buf, sender...)
	tl := make([]byte, 2)
	binary.BigEndian.PutUint16(tl, uint16(len(text)))
	buf = append(buf, tl...)
	buf = append(buf, text...)
	return buf, nil
}

func unmarshalChatPayload(b []byte) (sender, text string, err error) {
	bad := func(s string) (string, string, error) { return "", "", errors.New("chat: " + s) }
	if len(b) < 3 {
		return bad("payload too short")
	}
	sLen := int(b[0])
	off := 1
	if off+sLen > len(b) {
		return bad("truncated sender")
	}
	sender = string(b[off : off+sLen])
	off += sLen
	if off+2 > len(b) {
		return bad("truncated text length")
	}
	tLen := int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	if off+tLen > len(b) {
		return bad("truncated text")
	}
	text = string(b[off : off+tLen])
	return sender, text, nil
}

// ── Relay helpers ─────────────────────────────────────────────────────────────

// marshalRelayData wraps payload in a MsgRelayData envelope.
// The signal server reads (src, dst) and forwards to the correct UDP endpoint.
func marshalRelayData(srcID, dstID string, payload []byte) ([]byte, error) {
	if len(srcID) > 255 || len(dstID) > 255 {
		return nil, errors.New("relay: peer ID too long")
	}
	buf := make([]byte, 0, 1+1+len(srcID)+1+len(dstID)+len(payload))
	buf = append(buf, MsgRelayData)
	buf = append(buf, byte(len(srcID)))
	buf = append(buf, srcID...)
	buf = append(buf, byte(len(dstID)))
	buf = append(buf, dstID...)
	buf = append(buf, payload...)
	return buf, nil
}

func unmarshalRelayData(b []byte) (srcID, dstID string, payload []byte, err error) {
	bad := func(s string) (string, string, []byte, error) {
		return "", "", nil, errors.New("relay: " + s)
	}
	if len(b) < 3 {
		return bad("too short")
	}
	off := 1
	sLen := int(b[off])
	off++
	if off+sLen > len(b) {
		return bad("truncated src")
	}
	srcID = string(b[off : off+sLen])
	off += sLen
	if off >= len(b) {
		return bad("truncated after src")
	}
	dLen := int(b[off])
	off++
	if off+dLen > len(b) {
		return bad("truncated dst")
	}
	dstID = string(b[off : off+dLen])
	off += dLen
	return srcID, dstID, b[off:], nil
}

// ── Handshake helpers ─────────────────────────────────────────────────────────

func marshalHandshakeInit(ephemPub []byte, cert *NodeCert) ([]byte, error) {
	return marshalHandshakeMsg(MsgHandshakeInit, ephemPub, cert)
}

func marshalHandshakeResp(ephemPub []byte, cert *NodeCert) ([]byte, error) {
	return marshalHandshakeMsg(MsgHandshakeResp, ephemPub, cert)
}

func marshalHandshakeMsg(msgType byte, ephemPub []byte, cert *NodeCert) ([]byte, error) {
	certJSON, err := json.Marshal(cert)
	if err != nil {
		return nil, err
	}
	if len(certJSON) > 65535 {
		return nil, errors.New("hs: cert too large")
	}
	buf := make([]byte, 1+32+2+len(certJSON))
	buf[0] = msgType
	copy(buf[1:33], ephemPub)
	binary.BigEndian.PutUint16(buf[33:35], uint16(len(certJSON)))
	copy(buf[35:], certJSON)
	return buf, nil
}

func unmarshalHandshakeMsg(b []byte) (ephemPub []byte, cert *NodeCert, err error) {
	if len(b) < 35 {
		return nil, nil, errors.New("hs: too short")
	}
	ephemPub = make([]byte, 32)
	copy(ephemPub, b[1:33])
	cLen := int(binary.BigEndian.Uint16(b[33:35]))
	if 35+cLen > len(b) {
		return nil, nil, errors.New("hs: truncated cert")
	}
	cert = new(NodeCert)
	if err := json.Unmarshal(b[35:35+cLen], cert); err != nil {
		return nil, nil, fmt.Errorf("hs: cert JSON: %w", err)
	}
	return ephemPub, cert, nil
}
