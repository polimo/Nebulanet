package main

// ══════════════════════════════════════════════════════════════════════════════
// SIGNALING SERVER  (CA + Relay)
//
// Responsibilities:
//   1. Classic coordination: tell peers each other's NAT endpoints.
//   2. CA (PKI mode): sign NodeCert requests, include CA public key in ACKs.
//   3. Relay: when peers cannot punch directly, forward MsgRelayData packets
//             between them using its peerID→addr routing table.
// ══════════════════════════════════════════════════════════════════════════════

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

const signalTTL = 90 * time.Second

type signalRecord struct {
	entry   PeerEntry
	expires time.Time
}

// SignalServer is the coordination, CA, and relay server.
type SignalServer struct {
	conn         *net.UDPConn
	log          *slog.Logger
	mu           sync.RWMutex
	networks     map[string]map[string]*signalRecord 
	addrToPeerID map[string]string                  

	// CA fields (nil = legacy PSK mode; no cert signing).
	caPrivKey ed25519.PrivateKey
	caPubKey  ed25519.PublicKey
}

func newSignalServer(addr string, log *slog.Logger,
	caPriv ed25519.PrivateKey, caPub ed25519.PublicKey) (*SignalServer, error) {
	ua, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", ua)
	if err != nil {
		return nil, fmt.Errorf("signal: listen %s: %w", addr, err)
	}
	return &SignalServer{
		conn:         conn,
		log:          log,
		networks:     make(map[string]map[string]*signalRecord),
		addrToPeerID: make(map[string]string),
		caPrivKey:    caPriv,
		caPubKey:     caPub,
	}, nil
}

func (s *SignalServer) Serve() {
	go s.reap()
	buf := make([]byte, 2048)
	for {
		n, from, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		go s.handle(append([]byte{}, buf[:n]...), from)
	}
}

func (s *SignalServer) Close() error { return s.conn.Close() }

func (s *SignalServer) handle(pkt []byte, from *net.UDPAddr) {
	if len(pkt) == 0 {
		return
	}
	switch pkt[0] {
	case MsgRegister:
		s.handleRegister(pkt, from)

	case MsgCertReq:
		s.handleCertRequest(pkt, from)

	case MsgKeepalive:
		// Refresh TTL for any peer registered from this address.
		s.mu.Lock()
		if peerID, ok := s.addrToPeerID[from.String()]; ok {
			for _, peers := range s.networks {
				if r, ok2 := peers[peerID]; ok2 {
					r.expires = time.Now().Add(signalTTL)
				}
			}
		}
		s.mu.Unlock()

	case MsgRelayData:
		s.handleRelay(pkt, from)
	}
}

func (s *SignalServer) handleRegister(pkt []byte, from *net.UDPAddr) {
	reg, err := unmarshalRegister(pkt)
	if err != nil {
		s.log.Warn("signal: bad register", "err", err)
		return
	}

	// In PKI mode, validate the incoming cert against our CA public key.
	if s.caPubKey != nil && reg.Cert != nil {
		if err := reg.Cert.Verify(s.caPubKey); err != nil {
			s.log.Warn("signal: cert rejected", "peer", reg.PeerID, "err", err)
			return
		}
		// Ensure the cert's VPN IP matches the claimed registration IP.
		if reg.Cert.VPNIP != reg.VPNIP.String() {
			s.log.Warn("signal: cert VPN IP mismatch",
				"cert", reg.Cert.VPNIP, "claimed", reg.VPNIP)
			return
		}
	}

	s.log.Info("peer joined",
		"network", reg.NetworkID, "peer", reg.PeerID,
		"vpn", reg.VPNIP, "public", from)

	entry := PeerEntry{
		PeerID:     reg.PeerID,
		VPNIP:      reg.VPNIP,
		PublicAddr: from,
		Cert:       reg.Cert,
	}

	s.mu.Lock()
	if s.networks[reg.NetworkID] == nil {
		s.networks[reg.NetworkID] = make(map[string]*signalRecord)
	}
	s.networks[reg.NetworkID][reg.PeerID] = &signalRecord{
		entry:   entry,
		expires: time.Now().Add(signalTTL),
	}
	s.addrToPeerID[from.String()] = reg.PeerID
	others := s.peersExcept(reg.NetworkID, reg.PeerID)
	s.mu.Unlock()

	// Tell the newcomer its own public NAT address (+ CA pub key if PKI mode).
	s.conn.WriteToUDP(marshalAck(from, s.caPubKey), from)

	// Send the newcomer the existing peer list.
	if len(others) > 0 {
		if pl, err := marshalPeerList(others); err == nil {
			s.conn.WriteToUDP(pl, from) 
		}
	}
	// Notify existing peers about the newcomer.
	if pl, err := marshalPeerList([]PeerEntry{entry}); err == nil {
		for _, p := range others {
			s.conn.WriteToUDP(pl, p.PublicAddr)
		}
	}
}

// handleCertRequest signs a certificate for the requesting node.
func (s *SignalServer) handleCertRequest(pkt []byte, from *net.UDPAddr) {
	if s.caPrivKey == nil {
		reply := append([]byte{MsgCertResp, 0x01}, "CA not configured on this server"...)
		s.conn.WriteToUDP(reply, from)
		return
	}
	if len(pkt) < 2 {
		return
	}
	var req CertRequest
	if err := json.Unmarshal(pkt[1:], &req); err != nil {
		s.log.Warn("certreq: bad JSON", "err", err)
		return
	}
	s.log.Info("cert request", "peer", req.PeerID, "net", req.NetworkID, "vpn", req.VPNIP)

	cert, err := caSignCert(req, s.caPrivKey, 24*time.Hour)
	if err != nil {
		reply := append([]byte{MsgCertResp, 0x01}, err.Error()...)
		s.conn.WriteToUDP(reply, from) 
		return
	}
	certJSON, _ := json.Marshal(cert)
	reply := append([]byte{MsgCertResp, 0x00}, certJSON...)
	s.conn.WriteToUDP(reply, from) 
	s.log.Info("cert issued", "peer", req.PeerID, "exp", time.Unix(cert.NotAfter, 0).Format(time.RFC3339))
}

// handleRelay forwards a MsgRelayData packet to the destination peer.
func (s *SignalServer) handleRelay(pkt []byte, from *net.UDPAddr) {
	srcID, dstID, payload, err := unmarshalRelayData(pkt)
	if err != nil {
		s.log.Debug("relay: bad packet", "err", err)
		return
	}

	s.mu.RLock()
	var dstAddr *net.UDPAddr
	for _, peers := range s.networks {
		if r, ok := peers[dstID]; ok {
			dstAddr = r.entry.PublicAddr
			break
		}
	}
	s.mu.RUnlock()

	if dstAddr == nil {
		s.log.Debug("relay: destination not found", "dst", dstID)
		return
	}

	// Rebuild the relay envelope so the receiver knows who sent it.
	outPkt, err := marshalRelayData(srcID, dstID, payload)
	if err != nil {
		return
	}
	s.conn.WriteToUDP(outPkt, dstAddr) //nolint:errcheck
	s.log.Debug("relay: forwarded", "src", srcID, "dst", dstID, "bytes", len(payload))
}

func (s *SignalServer) peersExcept(netID, excludeID string) []PeerEntry {
	out := []PeerEntry{}
	for id, r := range s.networks[netID] {
		if id != excludeID {
			out = append(out, r.entry)
		}
	}
	return out
}

func (s *SignalServer) reap() {
	for range time.NewTicker(30 * time.Second).C {
		now := time.Now()
		s.mu.Lock()
		for netID, peers := range s.networks {
			for peerID, r := range peers {
				if now.After(r.expires) {
					s.log.Info("peer expired", "network", netID, "peer", peerID)
					delete(s.addrToPeerID, r.entry.PublicAddr.String())
					delete(peers, peerID)
				}
			}
			if len(peers) == 0 {
				delete(s.networks, netID)
			}
		}
		s.mu.Unlock()
	}
}
