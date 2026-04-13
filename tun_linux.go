package main

// ══════════════════════════════════════════════════════════════════════════════
// PLATFORM: LINUX TUN DRIVER  (single-file, no CGo)
//
// newVirtualDevice opens /dev/net/tun, configures the kernel interface with
// the given CIDR, and returns a VirtualDevice backed by a TUN (L3) adapter.
//
// Requires CAP_NET_ADMIN (run as root or with the capability).
// Uses standard iproute2 (`ip`) for address/link management.
// ══════════════════════════════════════════════════════════════════════════════

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

const (
	tunSetIff = 0x400454ca 
	iffTUN    = 0x0001    
	iffNOPI   = 0x1000     
)

// linuxTUN is the Linux TUN implementation of VirtualDevice.
type linuxTUN struct {
	file *os.File
	name string
	cidr string
}

// newVirtualDevice opens or creates a Linux TUN interface, assigns vpnCIDR,
func newVirtualDevice(devName, vpnCIDR string) (VirtualDevice, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("tun: open /dev/net/tun: %w (are you root / CAP_NET_ADMIN?)", err)
	}

	// struct ifreq layout on Linux:  name[IFNAMSIZ=16] + flags[2] + pad[22]
	ifr := make([]byte, 40)
	copy(ifr, devName) // null-padded automatically
	flags := uint16(iffTUN | iffNOPI)
	ifr[16] = byte(flags)
	ifr[17] = byte(flags >> 8) // little-endian

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL, f.Fd(),
		tunSetIff,
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		f.Close()
		return nil, fmt.Errorf("tun: TUNSETIFF: %w", errno)
	}

	// Read back the actual interface name assigned by the kernel.
	actualName := strings.TrimRight(string(ifr[:16]), "\x00")

	// Assign VPN IP / prefix and bring the link up.
	if out, err := exec.Command("ip", "addr", "add", vpnCIDR, "dev", actualName).CombinedOutput(); err != nil {
		f.Close()
		return nil, fmt.Errorf("tun: ip addr add: %w — %s", err, out)
	}
	if out, err := exec.Command("ip", "link", "set", "dev", actualName, "up").CombinedOutput(); err != nil {
		f.Close()
		return nil, fmt.Errorf("tun: ip link set up: %w — %s", err, out)
	}

	return &linuxTUN{file: f, name: actualName, cidr: vpnCIDR}, nil
}

func (t *linuxTUN) Read(b []byte) (int, error)  { return t.file.Read(b) }
func (t *linuxTUN) Write(b []byte) (int, error) { return t.file.Write(b) }
func (t *linuxTUN) Close() error                { return t.file.Close() }
func (t *linuxTUN) Name() string                { return t.name }
func (t *linuxTUN) IsL2() bool                  { return false }

// Deconfigure removes the VPN address and brings the link down gracefully.
func (t *linuxTUN) Deconfigure() {
	exec.Command("ip", "addr", "del", t.cidr, "dev", t.name).Run() 
	exec.Command("ip", "link", "set", t.name, "down").Run()        
}
