# NebulaNet

NebulaNet is a peer-to-peer overlay network that makes a bunch of machines act like they are sitting on the same local network, even when they are not.

The idea is simple: your machine joins a shared network, gets a virtual interface, and starts sending packets through it. NebulaNet takes those packets, encrypts them, finds the right peer, and pushes them across the internet. If direct peer-to-peer does not work, it can fall back to a signal server relay so the network still stays usable.

## What this tool is for

This is not just a random packet toy. It is meant for:

* building private overlays between machines
* experimenting with TUN/TAP networking
* learning NAT traversal and hole punching
* testing encrypted peer-to-peer traffic
* carrying normal network traffic plus a small built-in chat layer

So yeah, it is basically a small encrypted virtual LAN with extra brain cells.

## How it works

NebulaNet has three main parts:

### 1. Signal server

The signal server is the coordinator. It does a few jobs:

* receives registration from peers
* shares peer connection info
* helps with NAT hole punching
* acts as a relay when direct peer-to-peer fails
* in PKI mode, signs node certificates like a lightweight CA

It is not the part that carries all your traffic. It mostly helps peers find each other and stay connected.

### 2. Virtual network device

Each client opens a virtual interface:

* Linux uses TAP for Ethernet frames
* macOS and Windows use TUN for IP packets

Once the interface is up, the operating system thinks it is a real network card. Anything you send through it gets intercepted by NebulaNet, encrypted, and forwarded to the right peer.

### 3. Encryption and trust

NebulaNet supports two security modes:

#### Legacy PSK mode

This is the simple mode.

* everyone shares one secret
* traffic is encrypted with AES-256-GCM
* it is quick to set up, but every peer trusts the same shared key

#### PKI + PFS mode

This is the stronger mode.

* each node has its own X25519 keypair
* the signal server can issue signed node certificates
* peers verify certificates before trusting each other
* every peer pair gets its own short-lived session keys
* sessions rotate every 5 minutes
* packets are encrypted with AES-256-GCM

This is the mode that actually feels like a proper network instead of a shared password club.

## Packet flow

When a packet leaves your machine, this is what happens:

1. the OS writes the packet into the virtual device
2. NebulaNet reads it
3. it decides which peer should get it
4. it encrypts the packet
5. it tries direct UDP delivery
6. if direct delivery fails, it uses the signal server relay
7. the remote peer decrypts it and writes it back into its own virtual interface

For Layer 2 traffic, NebulaNet also keeps a small MAC learning table so it can forward frames more intelligently instead of flooding everything forever.

## Peer chat

NebulaNet also includes a tiny built-in chat system.

You can use:

* `/list` to show peers
* `/msg <peer> <text>` to send a direct message
* `/broadcast <text>` to send to everyone
* `/quit` to exit

That part is not the main feature, but honestly it is useful for checking that the overlay is alive without opening another app.

## Commands

### `signal`

Run the signal server.

It listens for peers, coordinates discovery, and optionally enables certificate authority mode.

### `gencert`

Generate a node keypair and ask the CA for a signed certificate.

This is for PKI mode.

### `join`

Join an overlay network as a client.

This opens the virtual interface, registers with the signal server, discovers peers, and starts handling encrypted traffic.

### `genkey`

Print a random 128-bit legacy shared secret for PSK mode.

## Example setup

### 1. Start the signal server

```bash
nebulanet signal --listen :7878
```

### 2. Create a certificate for a node

```bash
nebulanet gencert \
  --server 1.2.3.4:7878 \
  --network mynet \
  --peer-id node1 \
  --vpn-ip 10.0.0.1/24 \
  --out node1
```

That gives you:

* `node1.key`
* `node1.cert`

### 3. Join the network

```bash
sudo nebulanet join \
  --server 1.2.3.4:7878 \
  --network mynet \
  --vpn-ip 10.0.0.1/24 \
  --peer-id node1 \
  --cert node1.cert \
  --key node1.key
```

Or, in legacy mode:

```bash
sudo nebulanet join \
  --server 1.2.3.4:7878 \
  --network mynet \
  --vpn-ip 10.0.0.1/24 \
  --secret your-psk-here
```

## Requirements

* Go toolchain
* UDP access between peers and the signal server
* root or `CAP_NET_ADMIN` for the client, since it needs to create a tunnel interface
* Linux/macOS/Windows support depends on the platform tunnel files

## Design choices

A few things were clearly done on purpose:

* direct peer-to-peer is tried first
* relay is only a fallback
* packet contents stay encrypted from the signal server
* PKI mode avoids the whole “everyone shares one password forever” problem
* short-lived sessions reduce the damage if a key ever gets exposed


## Final note

NebulaNet is basically a private encrypted network with a signal server, NAT traversal, and a fallback relay path. It tries to behave like a real switch or VPN-like overlay, but with a cleaner trust model in PKI mode.



