package main

// ══════════════════════════════════════════════════════════════════════════════
// CLI
// ══════════════════════════════════════════════════════════════════════════════

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		printBanner()
		printUsage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "signal":
		cmdSignal(os.Args[2:])
	case "join":
		cmdJoin(os.Args[2:])
	case "gencert":
		cmdGencert(os.Args[2:])
	case "genkey":
		cmdGenkey()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage:  nebulanet <command> [flags]")
	fmt.Fprintln(os.Stderr, "  signal   Run the CA + coordination server (public IP required)")
	fmt.Fprintln(os.Stderr, "  gencert  Request a signed certificate from the CA server")
	fmt.Fprintln(os.Stderr, "  join     Join an overlay network (requires root / CAP_NET_ADMIN)")
	fmt.Fprintln(os.Stderr, "  genkey   Print a random 128-bit legacy PSK secret")
}

func cmdGenkey() {
	k, err := generatePassphrase()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(k)
}

// cmdSignal starts the coordination server. In PKI mode it also acts as CA.
func cmdSignal(args []string) {
	fs := flag.NewFlagSet("signal", flag.ExitOnError)
	listen  := fs.String("listen",  ":7878",  "UDP address to listen on")
	caKey   := fs.String("ca-key",  "ca.key", "path to CA Ed25519 private key (created if absent)")
	noCA    := fs.Bool("no-ca",     false,     "disable CA; run in legacy PSK-only mode")
	verbose := fs.Bool("v",         false,     "verbose logging")
	fs.Parse(args) //nolint:errcheck

	log := makeLogger(*verbose)
	printBanner()
	fmt.Printf("  Mode: SIGNAL SERVER   Listening on %s\n\n", *listen)

	var caPriv ed25519.PrivateKey
	var caPub  ed25519.PublicKey

	if !*noCA {
		var err error
		caPriv, caPub, err = loadOrCreateCAKey(*caKey)
		if err != nil {
			log.Error("CA key", "err", err)
			os.Exit(1)
		}
		fmt.Printf("  CA public key : %s\n", hex.EncodeToString(caPub))
		fmt.Printf("  CA key file   : %s\n\n", *caKey)
		fmt.Printf("  ⚠  Share the CA public key with all nodes so they can validate certs.\n\n")
	}

	srv, err := newSignalServer(*listen, log, caPriv, caPub)
	if err != nil {
		log.Error("start server", "err", err)
		os.Exit(1)
	}
	go srv.Serve()
	log.Info("ready — waiting for peers to register")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Info("shutting down")
	srv.Close()
}

// cmdGencert generates an X25519 keypair and requests a signed certificate

func cmdGencert(args []string) {
	fs := flag.NewFlagSet("gencert", flag.ExitOnError)
	serverAddr := fs.String("server",  "",    "signal server host:port [required]")
	networkID  := fs.String("network", "",    "overlay network name    [required]")
	peerID     := fs.String("peer-id", "",    "peer name               [required]")
	vpnCIDR    := fs.String("vpn-ip",  "",    "VPN IP, e.g. 10.0.0.1/24 [required]")
	out        := fs.String("out",     "",    "output file prefix (writes <out>.key and <out>.cert) [required]")
	verbose    := fs.Bool("v",         false, "verbose logging")
	fs.Parse(args) 

	if *serverAddr == "" || *networkID == "" || *peerID == "" || *vpnCIDR == "" || *out == "" {
		fs.Usage()
		fmt.Fprintln(os.Stderr, "\n--server, --network, --peer-id, --vpn-ip, --out are all required.")
		os.Exit(1)
	}

	log := makeLogger(*verbose)

	vpnIP, _, err := net.ParseCIDR(*vpnCIDR)
	if err != nil {
		log.Error("invalid --vpn-ip", "err", err)
		os.Exit(1)
	}

	// 1. Generate long-term X25519 keypair.
	_, pubHex, privHex, err := generateNodeKeypair()
	if err != nil {
		log.Error("keygen", "err", err)
		os.Exit(1)
	}

	// 2. Send CertRequest to the CA.
	req := CertRequest{
		PeerID:    *peerID,
		NetworkID: *networkID,
		VPNIP:     vpnIP.String(),
		PubKeyHex: pubHex,
	}
	reqJSON, _ := json.Marshal(req)
	pkt := append([]byte{MsgCertReq}, reqJSON...)

	srvAddr, err := net.ResolveUDPAddr("udp4", *serverAddr)
	if err != nil {
		log.Error("resolve server", "err", err)
		os.Exit(1)
	}

	conn, err := net.DialUDP("udp4", nil, srvAddr)
	if err != nil {
		log.Error("dial server", "err", err)
		os.Exit(1)
	}
	defer conn.Close()

	if _, err := conn.Write(pkt); err != nil {
		log.Error("send cert request", "err", err)
		os.Exit(1)
	}

	// 3. Wait for response from CA.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		log.Error("read cert response", "err", err)
		os.Exit(1)
	}

	if buf[0] != MsgCertResp {
		log.Error("unexpected response type", "type", buf[0])
		os.Exit(1)
	}

	status := buf[1]
	payload := buf[2:n]
	if status != 0x00 {
		log.Error("CA rejected request", "reason", string(payload))
		os.Exit(1)
	}

	// 4. Save keys to disk.
	keyFile := *out + ".key"
	certFile := *out + ".cert"

	if err := os.WriteFile(keyFile, []byte(privHex+"\n"), 0600); err != nil {
		log.Error("write key", "err", err)
		os.Exit(1)
	}
	if err := os.WriteFile(certFile, payload, 0644); err != nil {
		log.Error("write cert", "err", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Certificate and key generated successfully.\n")
	fmt.Printf("  Key  : %s\n", keyFile)
	fmt.Printf("  Cert : %s\n", certFile)
}

// cmdJoin connects to the overlay network using either PKI or legacy PSK.
func cmdJoin(args []string) {
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	serverAddr := fs.String("server",  "",       "signaling server host:port [required]")
	networkID  := fs.String("network", "",       "overlay network name [required]")
	vpnCIDR    := fs.String("vpn-ip",  "",       "VPN IP, e.g. 10.0.0.1/24 [required]")
	peerID     := fs.String("peer-id", "",       "peer name (default: hostname)")
	ifaceName  := fs.String("iface",   "nebula0","interface name")
	secret     := fs.String("secret",  "",       "legacy PSK secret (use instead of cert/key)")
	certPath   := fs.String("cert",    "",       "path to node certificate (PKI mode)")
	keyPath    := fs.String("key",     "",       "path to node private key (PKI mode)")
	verbose    := fs.Bool("v",         false,    "verbose logging")
	fs.Parse(args) //nolint:errcheck

	if *serverAddr == "" || *networkID == "" || *vpnCIDR == "" {
		fs.Usage()
		fmt.Fprintln(os.Stderr, "\n--server, --network, and --vpn-ip are required.")
		os.Exit(1)
	}
	if *peerID == "" {
		h, _ := os.Hostname()
		*peerID = h
	}
	log := makeLogger(*verbose)

	vpnIP, _, err := net.ParseCIDR(*vpnCIDR)
	if err != nil {
		log.Error("invalid --vpn-ip", "err", err)
		os.Exit(1)
	}

	var legacySess *Session
	var myCert *NodeCert
	var myPrivKey *ecdh.PrivateKey

	// Determine security mode.
	if *secret != "" {
		log.Info("running in legacy PSK mode")
		legacySess, err = newSession(deriveKey(*secret))
		if err != nil {
			log.Error("init crypto", "err", err)
			os.Exit(1)
		}
	} else if *certPath != "" && *keyPath != "" {
		log.Info("running in PKI mode")
		certData, err := os.ReadFile(*certPath)
		if err != nil {
			log.Error("read cert", "err", err)
			os.Exit(1)
		}
		myCert = new(NodeCert)
		if err := json.Unmarshal(certData, myCert); err != nil {
			log.Error("parse cert", "err", err)
			os.Exit(1)
		}
		keyData, err := os.ReadFile(*keyPath)
		if err != nil {
			log.Error("read key", "err", err)
			os.Exit(1)
		}
		myPrivKey, err = loadNodePrivKey(string(keyData))
		if err != nil {
			log.Error("parse key", "err", err)
			os.Exit(1)
		}
		// Enforce the identity bound to the certificate.
		if myCert.PeerID != *peerID {
			log.Warn("overriding --peer-id with cert identity", "cert_peer_id", myCert.PeerID)
			*peerID = myCert.PeerID
		}
	} else {
		fmt.Fprintln(os.Stderr, "Error: Must provide either --secret (Legacy) OR both --cert and --key (PKI)")
		os.Exit(1)
	}

	// 1. Open virtual network device.
	log.Info("opening virtual network device", "name", *ifaceName)
	dev, err := newVirtualDevice(*ifaceName, *vpnCIDR)
	if err != nil {
		log.Error("open device", "err", err)
		os.Exit(1)
	}
	defer dev.Close()
	defer dev.Deconfigure()

	// 2. Bind UDP.
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		log.Error("bind UDP", "err", err)
		os.Exit(1)
	}
	defer conn.Close()

	// 3. Resolve signal server.
	srvAddr, err := net.ResolveUDPAddr("udp4", *serverAddr)
	if err != nil {
		log.Error("resolve signal server", "err", err)
		os.Exit(1)
	}

	// 4. Register with signal server.
	regMsg, err := marshalRegister(RegisterPayload{
		NetworkID: *networkID, PeerID: *peerID, VPNIP: vpnIP, Cert: myCert,
	})
	if err != nil {
		log.Error("marshal register", "err", err)
		os.Exit(1)
	}
	if _, err := conn.WriteToUDP(regMsg, srvAddr); err != nil {
		log.Error("send register", "err", err)
		os.Exit(1)
	}

	// 5. Wait for ACK and CA public key.
	myPublic, caPub, err := waitForAck(conn, srvAddr, log)
	if err != nil {
		log.Error("ACK timeout", "err", err)
		os.Exit(1)
	}

	printBanner()
	fmt.Printf("  Mode      : CLIENT\n")
	fmt.Printf("  VPN IP    : %s\n", *vpnCIDR)
	fmt.Printf("  Public    : %s\n", myPublic)
	fmt.Printf("  Network   : %s\n", *networkID)
	fmt.Printf("  Peer ID   : %s\n", *peerID)
	fmt.Printf("  Interface : %s\n", dev.Name())
	if myCert != nil {
		fmt.Printf("  Security  : PKI + PFS (Session key rotation active)\n")
	} else {
		fmt.Printf("  Security  : Legacy PSK\n")
	}
	fmt.Printf("\n  Waiting for peers…   (Ctrl-C to quit)\n")
	fmt.Printf("  Chat: /list  /msg <peer> <text>  /broadcast <text>  /quit\n\n")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pm := newPeerManager(ctx, conn, dev, newMACTable(), log, *peerID, legacySess, myCert, myPrivKey, caPub, srvAddr)

	// Keep NAT hole alive and refresh registration.
	go func() {
		for range time.NewTicker(25 * time.Second).C {
			select {
			case <-ctx.Done():
				return
			default:
				conn.WriteToUDP(regMsg, srvAddr) //nolint:errcheck
			}
		}
	}()


	go func() {
		frame := make([]byte, 2048)
		for {
			n, err := dev.Read(frame)
			if err != nil {
				return
			}
			pm.SendFrame(frame[:n])
		}
	}()

	// Overlay chat interface.
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Print("> ")
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
			}
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				fmt.Print("> ")
				continue
			}

			switch {
			case line == "/quit":
				fmt.Println("  goodbye.")
				cancel()
				return
			case line == "/list":
				peers := pm.ListPeers()
				if len(peers) == 0 {
					fmt.Println("  (no active peers)")
				} else {
					fmt.Printf("  %-20s %-15s %s\n", "PEER ID", "VPN IP", "PUBLIC ADDR")
					fmt.Printf("  %-20s %-15s %s\n", strings.Repeat("─", 20), strings.Repeat("─", 15), strings.Repeat("─", 20))
					for _, p := range peers {
						fmt.Printf("  %-20s %-15s %s\n", p.PeerID, p.VPNIP.String(), p.PublicAddr)
					}
				}
			case strings.HasPrefix(line, "/msg "):
				rest := strings.TrimPrefix(line, "/msg ")
				parts := strings.SplitN(rest, " ", 2)
				if len(parts) < 2 {
					fmt.Println("  Usage: /msg <peer> <text>")
				} else {
					if err := pm.SendChat(parts[0], parts[1]); err != nil {
						fmt.Printf("  \033[31merror:\033[0m %v\n", err)
					} else {
						ts := time.Now().Format("15:04:05")
						fmt.Printf("[%s] \033[33m<you → %s>\033[0m %s\n", ts, parts[0], parts[1])
					}
				}
			case strings.HasPrefix(line, "/broadcast "):
				text := strings.TrimPrefix(line, "/broadcast ")
				pm.BroadcastChat(text)
				ts := time.Now().Format("15:04:05")
				fmt.Printf("[%s] \033[33m<you → all>\033[0m %s\n", ts, text)
			default:
				fmt.Println("  unknown command. try: /list, /msg <peer> <text>, /broadcast <text>, /quit")
			}
			fmt.Print("> ")
		}
	}()

	// Read UDP → Decrypt → Write to Virtual Device.
	buf := make([]byte, 4096)
	for {
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		if n == 0 {
			continue
		}
		pkt := buf[:n]

		switch pkt[0] {
		case MsgAck:
			// Duplicate ack from re-registration; safe to ignore.
		case MsgPeerList:
			peers, err := unmarshalPeerList(pkt)
			if err != nil {
				log.Warn("bad peer list", "err", err)
				continue
			}
			for _, p := range peers {
				pm.AddPeer(p)
			}
		case MsgRelayData:

			srcID, _, payload, err := unmarshalRelayData(pkt)
			if err == nil {
				pm.DispatchPacket(payload, from, srcID)
			}
		default:
			pm.DispatchPacket(pkt, from, "")
		}
	}
}

func waitForAck(conn *net.UDPConn, srvAddr *net.UDPAddr, log *slog.Logger) (*net.UDPAddr, ed25519.PublicKey, error) {
	buf := make([]byte, 2048)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if from.String() != srvAddr.String() {
			continue
		}
		if n > 0 && buf[0] == MsgAck {
			addr, caPub, err := unmarshalAck(buf[:n])
			if err != nil {
				return nil, nil, err
			}
			log.Info("public endpoint confirmed", "addr", addr)
			conn.SetReadDeadline(time.Time{})
			return addr, caPub, nil
		}
	}
	return nil, nil, fmt.Errorf("timeout waiting for ACK from signaling server at %s", srvAddr)
}

func makeLogger(verbose bool) *slog.Logger {
	lvl := slog.LevelInfo
	if verbose {
		lvl = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

func printBanner() {
	fmt.Print(`
  ███╗   ██╗███████╗██████╗ ██╗   ██╗██╗      █████╗
  ████╗  ██║██╔════╝██╔══██╗██║   ██║██║     ██╔══██╗
  ██╔██╗ ██║█████╗  ██████╔╝██║   ██║██║     ███████║
  ██║╚██╗██║██╔══╝  ██╔══██╗██║   ██║██║     ██╔══██║
  ██║ ╚████║███████╗██████╔╝╚██████╔╝███████╗██║  ██║
  ╚═╝  ╚═══╝╚══════╝╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝

  ██╗   ██╗███╗   ██╗███████╗██╗  ██╗████████╗
  ██║   ██║████╗  ██║██╔════╝╚██╗██╔╝╚══██╔══╝
  ██║   ██║██╔██╗ ██║█████╗   ╚███╔╝    ██║
  ╚██╗ ██╔╝██║╚██╗██║██╔══╝   ██╔██╗    ██║
   ╚████╔╝ ██║ ╚████║███████╗██╔╝ ██╗   ██║
    ╚═══╝  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝   ╚═╝
             Hardened P2P Virtual Network
`)
}
