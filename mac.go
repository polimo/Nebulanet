package main

// ══════════════════════════════════════════════════════════════════════════════
//  MAC LEARNING TABLE — Layer-2 switch logic
// ══════════════════════════════════════════════════════════════════════════════

import (
	"net"
	"sync"
	"time"
)

const macTTL = 5 * time.Minute

type macEntry struct {
	peerID  string
	expires time.Time
}

// MACTable maps source MAC addresses to the peer that last sent a frame with

type MACTable struct {
	mu      sync.RWMutex
	entries map[[6]byte]macEntry
}

func newMACTable() *MACTable {
	t := &MACTable{entries: make(map[[6]byte]macEntry)}
	go func() {
		for range time.NewTicker(macTTL / 2).C {
			now := time.Now()
			t.mu.Lock()
			for k, e := range t.entries {
				if now.After(e.expires) {
					delete(t.entries, k)
				}
			}
			t.mu.Unlock()
		}
	}()
	return t
}

func (t *MACTable) Learn(mac net.HardwareAddr, peerID string) {
	var k [6]byte
	copy(k[:], mac)
	t.mu.Lock()
	t.entries[k] = macEntry{peerID: peerID, expires: time.Now().Add(macTTL)}
	t.mu.Unlock()
}

func (t *MACTable) Lookup(mac net.HardwareAddr) (string, bool) {
	var k [6]byte
	copy(k[:], mac)
	t.mu.RLock()
	e, ok := t.entries[k]
	t.mu.RUnlock()
	if !ok || time.Now().After(e.expires) {
		return "", false
	}
	return e.peerID, true
}

func (t *MACTable) Remove(peerID string) {
	t.mu.Lock()
	for k, e := range t.entries {
		if e.peerID == peerID {
			delete(t.entries, k)
		}
	}
	t.mu.Unlock()
}

func isBroadcast(mac net.HardwareAddr) bool {
	return len(mac) >= 1 && mac[0]&0x01 == 1
}
