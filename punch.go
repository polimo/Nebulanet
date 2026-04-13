package main

// ══════════════════════════════════════════════════════════════════════════════
// UDP HOLE PUNCHING (NAT traversal, RFC 5128 §3.3)
//
// doPunch fires 12 probes over 2.4 seconds and returns the confirmed remote
// address on success, or a non-nil error on timeout.
// The caller interprets a timeout as a signal to enter relay mode.
// ══════════════════════════════════════════════════════════════════════════════

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"
)

func doPunch(ctx context.Context, conn *net.UDPConn, remote *net.UDPAddr, log *slog.Logger) (*net.UDPAddr, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	okCh := make(chan *net.UDPAddr, 1)

	go func() {
		buf := make([]byte, 64)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			if n < 1 {
				continue
			}
			switch buf[0] {
			case MsgPunch:
				log.Debug("punch: received probe, replying", "from", addr)
				conn.WriteToUDP([]byte{MsgPunchOK}, addr) 
			case MsgPunchOK:
				log.Info("punch: NAT hole opened!", "via", addr)
				select {
				case okCh <- addr:
				default:
				}
				return
			}
		}
	}()

	go func() {
		for i := 0; i < 12; i++ {
			select {
			case <-ctx.Done():
				return
			case <-okCh:
				return
			default:
			}
			log.Debug("punch: sending probe", "to", remote, "attempt", i+1)
			conn.WriteToUDP([]byte{MsgPunch}, remote) 
			time.Sleep(200 * time.Millisecond)
		}
	}()

	select {
	case addr := <-okCh:
		conn.SetReadDeadline(time.Time{})
		return addr, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("punch timed out — peer may be behind symmetric NAT")
	}
}
