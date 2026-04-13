package main

// ══════════════════════════════════════════════════════════════════════════════
//
// VirtualDevice abstracts the kernel tunnel driver across platforms
// Implemented by:
//   Linux   →  linuxTUN  (tun_linux.go)   IsL2=false (IP packets)
//   macOS   →  d arwinTUN (tun_darwin.go)  IsL2=false (IP packets)
//   Windows →    windowsTUN(tun_windows.go) IsL2=false (IP packets)
// ══════════════════════════════════════════════════════════════════════════════

type VirtualDevice interface {

	Read([]byte) (int, error)
	// Write injects a packet/frame into the OS network stack.
	Write([]byte) (int, error)
	// Close tears down the tunnel file descriptor.
	Close() error
	// Deconfigure removes the IP address and brings the interface down.
	Deconfigure()
	// Name returns the OS interface name (e.g. "nebula0", "utun3").
	Name() string
	// IsL2 reports whether the device delivers Ethernet frames (TAP, Layer 2).
	// False means raw IP packets (TUN, Layer 3).
	IsL2() bool
}
