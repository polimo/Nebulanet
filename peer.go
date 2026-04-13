package main

// ══════════════════════════════════════════════════════════════════════════════
// PEER STATE & HANDSHAKE STATE
// ══════════════════════════════════════════════════════════════════════════════

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// handshakeState holds ephemeral key material during an in-progress ECDH exchange.
type handshakeState struct {
	myEphem    *ecdh.PrivateKey 
	initiating bool             
	done       bool           
}

// peerState tracks everything we know about a remote peer.
type peerState struct {
	entry PeerEntry


	confirmedAddr *net.UDPAddr 
	relayMode     bool         
	nextRetryP2P  time.Time    

	// Security.
	cert    *NodeCert      
	hsState *handshakeState 
	session *peerSession    
}

// ══════════════════════════════════════════════════════════════════════════════
// PEER MANAGER
//
// PeerManager coordinates all per-peer state: NAT punch / relay, ECDH handshake,
// session rotation, MAC learning, frame encryption/decryption, and chat.
//
// PKI mode  (myCert != nil):  uses per-peer peerSession keys (PFS).
// Legacy mode (myCert == nil): uses a shared Session derived from the PSK.
// ══════════════════════════════════════════════════════════════════════════════

// PeerManager manages all known peers and the data plane.
type PeerManager struct {
	mu     sync.RWMutex
	peers  map[string]*peerState
	conn   *net.UDPConn
	tap    VirtualDevice
	macTbl *MACTable
	ctx    context.Context
	log    *slog.Logger
	selfID string


	legacySession *Session


	myCert    *NodeCert
	myPrivKey *ecdh.PrivateKey   
	caPubKey  ed25519.PublicKey  
	relayAddr *net.UDPAddr      
}

func newPeerManager(
	ctx context.Context,
	conn *net.UDPConn,
	tap VirtualDevice,
	mac *MACTable,
	log *slog.Logger,
	selfID string,
	legacySess *Session,
	myCert *NodeCert,
	myPrivKey *ecdh.PrivateKey,
	caPubKey ed25519.PublicKey,
	relayAddr *net.UDPAddr,
) *PeerManager {
	pm := &PeerManager{
		peers:         make(map[string]*peerState),
		conn:          conn,
		tap:           tap,
		macTbl:        mac,
		ctx:           ctx,
		log:           log,
		selfID:        selfID,
		legacySession: legacySess,
		myCert:        myCert,
		myPrivKey:     myPrivKey,
		caPubKey:      caPubKey,
		relayAddr:     relayAddr,
	}
	// Background maintenance: session rotation + relay→P2P upgrade attempts.
	go pm.maintenanceLoop()
	return pm
}

// shouldInitiate returns true if we are responsible for sending the first
// MsgHandshakeInit to the given peer. Exactly one side initiates (the node

func (pm *PeerManager) shouldInitiate(peerID string) bool {
	return pm.selfID < peerID
}

// maintenanceLoop runs periodic background tasks:
func (pm *PeerManager) maintenanceLoop() {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-tick.C:
			if pm.myCert != nil {
				pm.checkSessionRotation()
			}
			pm.checkRelayRetry()
		}
	}
}

func (pm *PeerManager) checkSessionRotation() {
	pm.mu.RLock()
	var toRotate []string
	for id, ps := range pm.peers {
		if ps.session != nil && time.Now().After(ps.session.expiresAt) {
			if pm.shouldInitiate(id) {
				toRotate = append(toRotate, id)
			}
		}
	}
	pm.mu.RUnlock()
	for _, id := range toRotate {
		pm.log.Info("PFS session expiring — rotating keys", "peer", id)
		pm.initiateHandshake(id)
	}
}

func (pm *PeerManager) checkRelayRetry() {
	pm.mu.RLock()
	var toRetry []PeerEntry
	for _, ps := range pm.peers {
		if ps.relayMode && time.Now().After(ps.nextRetryP2P) {
			toRetry = append(toRetry, ps.entry)
		}
	}
	pm.mu.RUnlock()
	for _, entry := range toRetry {
		go pm.retryDirectConnect(entry)
	}
}

// retryDirectConnect attempts to upgrade a relayed connection to direct P2P.
// On success it sets confirmedAddr and clears relayMode seamlessly.
func (pm *PeerManager) retryDirectConnect(entry PeerEntry) {
	pm.log.Info("retrying direct P2P connection", "peer", entry.PeerID, "remote", entry.PublicAddr)
	addr, err := doPunch(pm.ctx, pm.conn, entry.PublicAddr, pm.log)

	pm.mu.Lock()
	ps, ok := pm.peers[entry.PeerID]
	if !ok {
		pm.mu.Unlock()
		return
	}
	if err != nil {
		ps.nextRetryP2P = time.Now().Add(60 * time.Second)
		pm.mu.Unlock()
		pm.log.Debug("relay retry punch failed", "peer", entry.PeerID, "err", err)
		return
	}
	// Upgrade!
	pm.log.Info("✓ relay → direct P2P upgraded", "peer", entry.PeerID, "via", addr)
	ps.confirmedAddr = addr
	ps.relayMode = false
	ps.nextRetryP2P = time.Time{}
	pm.mu.Unlock()

	go pm.keepalive(entry.PeerID, addr)
}

// AddPeer registers a peer and begins NAT hole-punching + ECDH handshake in the background.
func (pm *PeerManager) AddPeer(entry PeerEntry) {
	pm.mu.Lock()
	if _, exists := pm.peers[entry.PeerID]; exists {
		pm.mu.Unlock()
		return
	}
	ps := &peerState{entry: entry, cert: entry.Cert}
	pm.peers[entry.PeerID] = ps
	pm.mu.Unlock()

	go func() {
		pm.log.Info("new peer — punching NAT hole",
			"peer", entry.PeerID, "vpn", entry.VPNIP, "public", entry.PublicAddr)
		addr, err := doPunch(pm.ctx, pm.conn, entry.PublicAddr, pm.log)

		pm.mu.Lock()
		if err != nil {
			pm.log.Warn("hole punch failed — entering relay mode",
				"peer", entry.PeerID, "err", err)
			ps.relayMode = true
			ps.nextRetryP2P = time.Now().Add(60 * time.Second)
		} else {
			ps.confirmedAddr = addr
		}
		pm.mu.Unlock()

		if addr != nil {
			go pm.keepalive(entry.PeerID, addr)
			pm.log.Info("✓ direct path established",
				"peer", entry.PeerID, "vpn", entry.VPNIP, "via", addr)
		}

		// Initiate the ECDH handshake if we're the designated initiator.
		if pm.myCert != nil && pm.shouldInitiate(entry.PeerID) {
			pm.initiateHandshake(entry.PeerID)
		}
	}()
}

func (pm *PeerManager) keepalive(peerID string, addr *net.UDPAddr) {
	tick := time.NewTicker(25 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-tick.C:
			// Stop if peer switched to relay mode (addr no longer valid).
			pm.mu.RLock()
			ps, ok := pm.peers[peerID]
			relay := ok && ps.relayMode
			pm.mu.RUnlock()
			if !ok || relay {
				return
			}
			pm.conn.WriteToUDP([]byte{MsgKeepalive}, addr) 
		}
	}
}

// ── ECDH Handshake ────────────────────────────────────────────────────────────


func (pm *PeerManager) initiateHandshake(peerID string) {
	ephem, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		pm.log.Error("hs: keygen failed", "err", err)
		return
	}

	pm.mu.Lock()
	ps, ok := pm.peers[peerID]
	if !ok {
		pm.mu.Unlock()
		return
	}
	ps.hsState = &handshakeState{myEphem: ephem, initiating: true}
	pm.mu.Unlock()

	pkt, err := marshalHandshakeInit(ephem.PublicKey().Bytes(), pm.myCert)
	if err != nil {
		pm.log.Error("hs: marshal init", "err", err)
		return
	}
	pm.sendToPeer(peerID, pkt)
	pm.log.Debug("hs: sent HandshakeInit", "to", peerID)
}

// HandleHandshakeInit processes an incoming MsgHandshakeInit.
func (pm *PeerManager) HandleHandshakeInit(pkt []byte, from *net.UDPAddr, fromPeerID string) {
	if pm.myCert == nil {
		return
	}
	ephemPubBytes, theirCert, err := unmarshalHandshakeMsg(pkt)
	if err != nil {
		pm.log.Warn("hs: bad init", "err", err)
		return
	}
	if pm.caPubKey != nil {
		if err := theirCert.Verify(pm.caPubKey); err != nil {
			pm.log.Warn("hs: cert rejected", "peer", theirCert.PeerID, "err", err)
			return
		}
	}

	// Generate our ephemeral keypair.
	myEphem, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	theirEphemPub, err := ecdh.X25519().NewPublicKey(ephemPubBytes)
	if err != nil {
		return
	}
	shared, err := myEphem.ECDH(theirEphemPub)
	if err != nil {
		return
	}
	// Responder: their ephem is the initiator's pubkey.
	sess, err := newPeerSession(shared, ephemPubBytes, myEphem.PublicKey().Bytes(), false)
	if err != nil {
		return
	}

	// Identify the peer: prefer the fromPeerID provided by relay unwrapping,
	pm.mu.Lock()
	var ps *peerState
	if fromPeerID != "" {
		ps = pm.peers[fromPeerID]
	}
	if ps == nil {
		for _, p := range pm.peers {
			if p.confirmedAddr != nil && p.confirmedAddr.String() == from.String() {
				ps = p
				break
			}
		}
	}
	if ps == nil {
		pm.mu.Unlock()
		pm.log.Warn("hs: init from unrecognised peer", "from", from, "peerID", fromPeerID)
		return
	}
	ps.session = sess
	ps.cert = theirCert
	ps.hsState = &handshakeState{myEphem: myEphem, done: true}
	targetPeerID := ps.entry.PeerID
	pm.mu.Unlock()

	// Send our response.
	respPkt, err := marshalHandshakeResp(myEphem.PublicKey().Bytes(), pm.myCert)
	if err != nil {
		return
	}
	pm.sendToPeer(targetPeerID, respPkt)
	pm.log.Info("✓ PFS session established (responder)", "peer", targetPeerID)
}

// HandleHandshakeResp processes an incoming MsgHandshakeResp (initiator side).
func (pm *PeerManager) HandleHandshakeResp(pkt []byte, from *net.UDPAddr, fromPeerID string) {
	if pm.myCert == nil {
		return
	}
	ephemPubBytes, theirCert, err := unmarshalHandshakeMsg(pkt)
	if err != nil {
		pm.log.Warn("hs: bad resp", "err", err)
		return
	}
	if pm.caPubKey != nil {
		if err := theirCert.Verify(pm.caPubKey); err != nil {
			pm.log.Warn("hs: resp cert rejected", "err", err)
			return
		}
	}

	pm.mu.Lock()
	var ps *peerState
	if fromPeerID != "" {
		ps = pm.peers[fromPeerID]
	}
	if ps == nil {
		for _, p := range pm.peers {
			if p.confirmedAddr != nil && p.confirmedAddr.String() == from.String() {
				ps = p
				break
			}
		}
	}
	if ps == nil || ps.hsState == nil || !ps.hsState.initiating {
		pm.mu.Unlock()
		pm.log.Warn("hs: unexpected resp", "from", from, "peerID", fromPeerID)
		return
	}
	myEphem := ps.hsState.myEphem
	peerID := ps.entry.PeerID
	pm.mu.Unlock()

	theirEphemPub, err := ecdh.X25519().NewPublicKey(ephemPubBytes)
	if err != nil {
		return
	}
	shared, err := myEphem.ECDH(theirEphemPub)
	if err != nil {
		return
	}
	// Initiator: our ephem is the initiator's pubkey.
	sess, err := newPeerSession(shared, myEphem.PublicKey().Bytes(), ephemPubBytes, true)
	if err != nil {
		return
	}

	pm.mu.Lock()
	if ps2, ok := pm.peers[peerID]; ok {
		ps2.session = sess
		ps2.cert = theirCert
		ps2.hsState.done = true
	}
	pm.mu.Unlock()
	pm.log.Info("✓ PFS session established (initiator)", "peer", peerID)
}

// ── Data plane ────────────────────────────────────────────────────────────────

// SendFrame encrypts a TAP/TUN frame and delivers it to the correct peer(s).
func (pm *PeerManager) SendFrame(frame []byte) {
	if len(frame) < 12 {
		return
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if pm.myCert != nil {
		pm.sendFramePKI(frame) 
	} else {
		pm.sendFrameLegacy(frame)
	}
}

// sendFrameLegacy: original MAC-table-based routing with shared PSK encryption.
func (pm *PeerManager) sendFrameLegacy(frame []byte) {
	dst := net.HardwareAddr(frame[0:6])
	pkt := append([]byte{MsgData}, pm.legacySession.Seal(frame)...)

	if !isBroadcast(dst) {
		if targetID, ok := pm.macTbl.Lookup(dst); ok {
			if ps, ok2 := pm.peers[targetID]; ok2 && ps.confirmedAddr != nil {
				pm.conn.WriteToUDP(pkt, ps.confirmedAddr) //nolint:errcheck
				return
			}
		}
	}
	for _, ps := range pm.peers {
		if ps.confirmedAddr != nil {
			pm.conn.WriteToUDP(pkt, ps.confirmedAddr) //nolint:errcheck
		}
	}
}

// sendFramePKI: PKI mode — per-peer session keys, relay-aware delivery.
func (pm *PeerManager) sendFramePKI(frame []byte) {
	var targets []*peerState

	if pm.tap.IsL2() && len(frame) >= 14 {

		dst := net.HardwareAddr(frame[0:6])
		if !isBroadcast(dst) {
			if targetID, ok := pm.macTbl.Lookup(dst); ok {
				if ps, ok2 := pm.peers[targetID]; ok2 {
					targets = []*peerState{ps}
				}
			}
		}
	} else if !pm.tap.IsL2() {

		dstIP := extractDstIP(frame, false)
		if dstIP != nil {
			for _, ps := range pm.peers {
				if ps.entry.VPNIP.Equal(dstIP) {
					targets = []*peerState{ps}
					break
				}
			}
		}
	}

	// Flood on broadcast / unknown destination.
	if len(targets) == 0 {
		for _, ps := range pm.peers {
			if ps.session != nil {
				targets = append(targets, ps)
			}
		}
	}

	for _, ps := range targets {
		if ps.session == nil {
			continue 
		}
		pkt := append([]byte{MsgData}, ps.session.Seal(frame)...)
		pm.sendToPeerLocked(ps, pkt)
	}
}

// HandleDataPacket decrypts and delivers an incoming MsgData packet.

func (pm *PeerManager) HandleDataPacket(pkt []byte, from *net.UDPAddr, fromPeerID string) {
	if len(pkt) < 1+nonceSize+gcmTagSize {
		return
	}

	var frame []byte
	var err error
	var srcPeerID string

	if pm.myCert != nil {
		// PKI mode: find the correct per-peer session.
		pm.mu.RLock()
		var sess *peerSession
		if fromPeerID != "" {
			if ps, ok := pm.peers[fromPeerID]; ok && ps.session != nil {
				sess = ps.session
				srcPeerID = fromPeerID
			}
		} else {
			for id, ps := range pm.peers {
				if ps.confirmedAddr != nil && ps.confirmedAddr.String() == from.String() {
					if ps.session != nil {
						sess = ps.session
						srcPeerID = id
					}
					break
				}
			}
		}
		pm.mu.RUnlock()

		if sess == nil {
			pm.log.Debug("data: no session yet for peer", "from", from, "peerID", fromPeerID)
			return
		}
		frame, err = sess.Open(pkt[1:])
	} else {
		// Legacy PSK mode.
		frame, err = pm.legacySession.Open(pkt[1:])
		// Find srcPeerID by address for MAC learning.
		pm.mu.RLock()
		for id, ps := range pm.peers {
			if ps.confirmedAddr != nil && ps.confirmedAddr.String() == from.String() {
				srcPeerID = id
				break
			}
		}
		pm.mu.RUnlock()
	}

	if err != nil {
		pm.log.Warn("decryption failed", "from", from, "err", err)
		return
	}

	// MAC learning (L2 only).
	if pm.tap.IsL2() && len(frame) >= 12 && srcPeerID != "" {
		pm.macTbl.Learn(net.HardwareAddr(frame[6:12]), srcPeerID)
	}

	pm.tap.Write(frame) 
}

// sendToPeer delivers pkt to peerID, via relay if no direct path is confirmed.
func (pm *PeerManager) sendToPeer(peerID string, pkt []byte) {
	pm.mu.RLock()
	ps, ok := pm.peers[peerID]
	if !ok {
		pm.mu.RUnlock()
		return
	}
	pm.sendToPeerLocked(ps, pkt)
	pm.mu.RUnlock()
}

// sendToPeerLocked is like sendToPeer but requires the caller to hold pm.mu
func (pm *PeerManager) sendToPeerLocked(ps *peerState, pkt []byte) {
	if !ps.relayMode && ps.confirmedAddr != nil {
		pm.conn.WriteToUDP(pkt, ps.confirmedAddr) //nolint:errcheck
		return
	}
	// Relay path via signal server.
	if pm.relayAddr == nil {
		pm.log.Warn("relay needed but no relay address configured")
		return
	}
	wrapped, err := marshalRelayData(pm.selfID, ps.entry.PeerID, pkt)
	if err != nil {
		return
	}
	pm.conn.WriteToUDP(wrapped, pm.relayAddr) //nolint:errcheck
}

// ── Chat ──────────────────────────────────────────────────────────────────────

// ListPeers returns all peers that have an active direct or relay path.
func (pm *PeerManager) ListPeers() []PeerEntry {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	out := make([]PeerEntry, 0, len(pm.peers))
	for _, ps := range pm.peers {
		if ps.confirmedAddr != nil || ps.relayMode {
			out = append(out, ps.entry)
		}
	}
	return out
}

func (pm *PeerManager) SendChat(toPeerID, text string) error {
	payload, err := marshalChatPayload(pm.selfID, text)
	if err != nil {
		return err
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()
	ps, ok := pm.peers[toPeerID]
	if !ok {
		return fmt.Errorf("chat: unknown peer %q — try /list", toPeerID)
	}
	if !ps.relayMode && ps.confirmedAddr == nil {
		return fmt.Errorf("chat: no path to %q yet", toPeerID)
	}

	var pkt []byte
	if pm.myCert != nil && ps.session != nil {
		pkt = append([]byte{MsgChat}, ps.session.Seal(payload)...)
	} else if pm.legacySession != nil {
		pkt = append([]byte{MsgChat}, pm.legacySession.Seal(payload)...)
	} else {
		return fmt.Errorf("chat: no crypto session for %q", toPeerID)
	}
	pm.sendToPeerLocked(ps, pkt)
	return nil
}

func (pm *PeerManager) BroadcastChat(text string) {
	payload, err := marshalChatPayload(pm.selfID, text)
	if err != nil {
		pm.log.Warn("chat: marshal failed", "err", err)
		return
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()
	for _, ps := range pm.peers {
		if ps.confirmedAddr == nil && !ps.relayMode {
			continue
		}
		var pkt []byte
		if pm.myCert != nil && ps.session != nil {
			pkt = append([]byte{MsgChat}, ps.session.Seal(payload)...)
		} else if pm.legacySession != nil {
			pkt = append([]byte{MsgChat}, pm.legacySession.Seal(payload)...)
		} else {
			continue
		}
		pm.sendToPeerLocked(ps, pkt)
	}
}

func (pm *PeerManager) HandleChatPacket(pkt []byte, from *net.UDPAddr, fromPeerID string) {
	if len(pkt) < 1+nonceSize+gcmTagSize {
		return
	}
	var payload []byte
	var err error

	if pm.myCert != nil {
		pm.mu.RLock()
		var sess *peerSession
		if fromPeerID != "" {
			if ps, ok := pm.peers[fromPeerID]; ok {
				sess = ps.session
			}
		} else {
			for _, ps := range pm.peers {
				if ps.confirmedAddr != nil && ps.confirmedAddr.String() == from.String() {
					sess = ps.session
					break
				}
			}
		}
		pm.mu.RUnlock()
		if sess == nil {
			return
		}
		payload, err = sess.Open(pkt[1:])
	} else {
		payload, err = pm.legacySession.Open(pkt[1:])
	}

	if err != nil {
		pm.log.Warn("chat: decryption failed", "from", from)
		return
	}
	sender, text, err := unmarshalChatPayload(payload)
	if err != nil {
		pm.log.Warn("chat: bad payload", "err", err)
		return
	}
	ts := time.Now().Format("15:04:05")
	fmt.Printf("\r\033[K[%s] \033[36m<%s>\033[0m %s\n> ", ts, sender, text)
}

// DispatchPacket routes an inner packet (after relay unwrapping) to the

func (pm *PeerManager) DispatchPacket(pkt []byte, from *net.UDPAddr, fromPeerID string) {
	if len(pkt) == 0 {
		return
	}
	switch pkt[0] {
	case MsgPunch:
		pm.conn.WriteToUDP([]byte{MsgPunchOK}, from)
	case MsgHandshakeInit:
		pm.HandleHandshakeInit(pkt, from, fromPeerID)
	case MsgHandshakeResp:
		pm.HandleHandshakeResp(pkt, from, fromPeerID)
	case MsgData:
		pm.HandleDataPacket(pkt, from, fromPeerID)
	case MsgChat:
		pm.HandleChatPacket(pkt, from, fromPeerID)
	}
}
