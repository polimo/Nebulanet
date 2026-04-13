package main

// ══════════════════════════════════════════════════════════════════════════════
// PACKET ROUTING HELPER
//
// extractDstIP returns the destination IP embedded in an IP packet (TUN / L3)
// or an Ethernet frame (TAP / L2).  Returns nil for unsupported/short packets.
// ══════════════════════════════════════════════════════════════════════════════

import (
	"encoding/binary"
	"net"
)

func extractDstIP(frame []byte, isL2 bool) net.IP {
	if isL2 {
		// Ethernet frame: dst-MAC(6) + src-MAC(6) + EtherType(2) + IP-header…
		if len(frame) < 34 {
			return nil
		}
		etherType := binary.BigEndian.Uint16(frame[12:14])
		switch etherType {
		case 0x0800: // IPv4
			return net.IP(frame[30:34]).To16()
		case 0x86DD: // IPv6
			if len(frame) < 54 {
				return nil
			}
			return net.IP(frame[38:54])
		}
		return nil
	}

	// TUN / raw IP packet — version in the high nibble of byte 0.
	if len(frame) < 20 {
		return nil
	}
	switch frame[0] >> 4 {
	case 4: // IPv4: dst at bytes 16–20
		return net.IP(frame[16:20]).To16()
	case 6: // IPv6: dst at bytes 24–40
		if len(frame) < 40 {
			return nil
		}
		return net.IP(frame[24:40])
	}
	return nil
}
