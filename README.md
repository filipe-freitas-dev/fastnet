```
╔═╗╔═╗╔═╗╔╦╗╔╗╔╔═╗╔╦╗
╠╣ ╠═╣╚═╗ ║ ║║║║╣  ║   Ultra-low latency encrypted networking
╚  ╩ ╩╚═╝ ╩ ╝╚╝╚═╝ ╩   for real-time games
```

[![Crates.io](https://img.shields.io/crates/v/fastnet.svg)](https://crates.io/crates/fastnet)
[![Documentation](https://docs.rs/fastnet/badge.svg)](https://docs.rs/fastnet)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**FastNet** is a high-performance networking library designed for real-time multiplayer games. It provides encrypted UDP communication with latencies as low as **15 microseconds** while maintaining strong security through TLS 1.3 and ChaCha20-Poly1305 encryption.

---

## Features

### Core
- **Ultra-Low Latency**: ~14µs average RTT on localhost, only 80% overhead vs raw UDP
- **Built-in Encryption**: TLS 1.3 handshake + ChaCha20-Poly1305 AEAD
- **Zero-Alloc Hot Path**: In-place encryption/decryption, O(1) ACK lookups
- **Key Rotation**: Automatic key rotation for forward secrecy
- **Game Engine Ready**: C/C++ FFI for Unreal Engine, Unity, Godot

### v0.2 New Modules
- **BBR Congestion Control**: Google's algorithm - 2.3x better throughput under packet loss
- **FEC**: XOR parity for single packet recovery without retransmission
- **Delta Compression**: 80-95% bandwidth reduction for game state updates
- **Priority Queues**: Critical packets first with weighted fair scheduling
- **Jitter Buffer**: Adaptive delay for smooth voice/video streaming
- **Metrics**: Real-time RTT, jitter, throughput, packet loss tracking
- **0-RTT Reconnect**: Session resumption with encrypted tickets
- **Connection Migration**: Seamless IP/network changes with HMAC proof
- **Interest Management**: Spatial hash grid for MMO entity filtering

### Infrastructure
- **Linux Tuning**: SO_BUSY_POLL, IP_TOS, sendmmsg/recvmmsg batching
- **Async/Await**: Built on Tokio for efficient I/O
- **Reliable & Unreliable Channels**: Choose the right mode for your data
- **P2P Networking**: Direct peer-to-peer connections with NAT traversal
- **TCP Fallback**: Automatic fallback when UDP is blocked
- **Asset Distribution**: Large file transfers with LZ4 compression and BLAKE3 verification

---

## Benchmarks

Tested with 10,000 RTT measurements on localhost (64-byte payload):

| Metric | Raw UDP | FastNet v0.2 | QUIC | ENet | RakNet |
|--------|---------|--------------|------|------|--------|
| **Avg Latency** | ~8 µs | **14.5 µs** | ~150 µs | ~60 µs | ~80 µs |
| **P99 Latency** | ~15 µs | **27 µs** | ~400 µs | ~180 µs | ~250 µs |
| **P99.9 Latency** | ~30 µs | **76 µs** | ~800 µs | ~300 µs | ~400 µs |
| **Encryption** | None | ChaCha20-Poly1305 | TLS 1.3 | None | Optional |

```
Average RTT Latency (lower is better)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Raw UDP      █ 8 µs (baseline)
FastNet      ██ 14.5 µs ⚡ (encrypted!)
ENet         ████████ 60 µs (unencrypted)
RakNet       ██████████ 80 µs (unencrypted)
QUIC         ███████████████████ 150 µs
```

> **FastNet is ~4x faster than ENet** while providing full ChaCha20-Poly1305 encryption
>
> **Only ~80% overhead vs raw UDP** despite TLS 1.3 key exchange + encryption
>
> *Benchmarks: v0.2.0 with zero-allocation hot path, O(1) ACK lookups*

---

## Quick Start

### Rust

Add to your `Cargo.toml`:

```toml
[dependencies]
fastnet = "0.2"
tokio = { version = "1", features = ["rt-multi-thread"] }
```

**Server:**

```rust
use fastnet::net::SecureSocket;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Load TLS certificates
    let certs = load_certs("cert.pem")?;
    let key = load_key("key.pem")?;
    
    let udp_addr: SocketAddr = "0.0.0.0:7777".parse().unwrap();
    let tcp_addr: SocketAddr = "0.0.0.0:7778".parse().unwrap();
    
    let mut socket = SecureSocket::bind_server(udp_addr, tcp_addr, certs, key).await?;
    println!("Server listening on {}", udp_addr);
    
    loop {
        for event in socket.poll().await? {
            match event {
                SecureEvent::Connected(peer_id) => {
                    println!("Peer {} connected", peer_id);
                }
                SecureEvent::Data(peer_id, channel, data) => {
                    // Echo back
                    socket.send(peer_id, channel, data).await?;
                }
                SecureEvent::Disconnected(peer_id) => {
                    println!("Peer {} disconnected", peer_id);
                }
            }
        }
    }
}
```

**Client:**

```rust
use fastnet::net::SecureSocket;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let server_addr = "127.0.0.1:7778".parse().unwrap();
    let mut socket = SecureSocket::connect(server_addr).await?;
    
    // Send data on channel 0
    socket.send(1, 0, b"Hello, server!".to_vec()).await?;
    
    // Receive events
    for event in socket.poll().await? {
        if let SecureEvent::Data(_, _, data) = event {
            println!("Received: {:?}", data);
        }
    }
    
    Ok(())
}
```

---

## C/C++ Integration

### Building the Library

Add the crate into your project:

```toml
fastnet = { version = "0.2", features = ["ffi"] }
```

or clone the repo into your machine:

```fish
git clone https://github.com/filipe-freitas-dev/fastnet.git
```

then build the C/C++ wrapper with:

```fish
cargo build --release --features ffi
```

This produces:
- Linux: `target/release/libfastnet.so`
- Windows: `target/release/fastnet.dll`
- macOS: `target/release/libfastnet.dylib`

### C Example

```c
#include "fastnet.h"

int main() {
    // Connect to server
    FastNetClient client = fastnet_client_connect("127.0.0.1", 7778);
    if (!client) {
        printf("Failed to connect\n");
        return 1;
    }
    
    // Send data
    uint8_t data[] = {1, 2, 3, 4};
    fastnet_client_send(client, 0, data, sizeof(data));
    
    // Process events
    FastNetEvent event;
    while (fastnet_client_poll(client, &event)) {
        switch (event.type) {
            case FASTNET_EVENT_CONNECTED:
                printf("Connected as peer %d\n", event.peer_id);
                break;
            case FASTNET_EVENT_DATA:
                printf("Received %d bytes\n", event.data_len);
                break;
            case FASTNET_EVENT_DISCONNECTED:
                printf("Disconnected\n");
                break;
        }
    }
    
    fastnet_client_disconnect(client);
    return 0;
}
```

---

## Unreal Engine Integration

1. Copy the library to your project:
   ```
   YourProject/
   ├── Binaries/
   │   └── Win64/
   │       └── fastnet.dll
   └── Source/
       └── YourGame/
           ├── fastnet.h
           └── FastNet.h (C++ wrapper)
   ```

2. Update your `Build.cs`:
   ```csharp
   PublicAdditionalLibraries.Add(
       Path.Combine(ModuleDirectory, "..", "..", "Binaries", "Win64", "fastnet.dll")
   );
   ```

3. Use in your code:
   ```cpp
   #include "FastNet.h"

   // In your GameInstance
   TUniquePtr<FFastNetClient> NetworkClient;

   void UMyGameInstance::Init()
   {
       NetworkClient = MakeUnique<FFastNetClient>();
       if (NetworkClient->Connect("127.0.0.1", 7778))
       {
           UE_LOG(LogTemp, Log, TEXT("Connected to server!"));
       }
   }

   void UMyGameInstance::Tick(float DeltaTime)
   {
       FFastNetEvent Event;
       while (NetworkClient->Poll(Event))
       {
           switch (Event.Type)
           {
               case EFastNetEventType::Data:
                   ProcessNetworkData(Event.Data);
                   break;
           }
       }
   }
   ```

---

## P2P Networking

Direct peer-to-peer connections with NAT traversal, eliminating the need for a dedicated relay server.

```rust
use fastnet::p2p::{P2PSocket, P2PEvent};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Connect to signaling server
    let mut socket = P2PSocket::connect("signaling.example.com:9000").await?;
    
    // Join a room to discover peers
    socket.join_room("game-room-123").await?;
    
    loop {
        for event in socket.poll().await? {
            match event {
                P2PEvent::PeerConnected(peer_id) => {
                    println!("Direct connection to peer {}", peer_id);
                    socket.send(peer_id, b"Hello!".to_vec()).await?;
                }
                P2PEvent::Data(peer_id, data) => {
                    println!("From {}: {:?}", peer_id, data);
                }
                P2PEvent::PeerRelayed(peer_id) => {
                    println!("Peer {} using relay (NAT traversal failed)", peer_id);
                }
                _ => {}
            }
        }
    }
}
```

**Features:**
- UDP hole-punching for NAT traversal
- Automatic relay fallback when direct connection fails
- Room-based peer discovery
- End-to-end encryption (ChaCha20-Poly1305)

---

## TCP Fallback

Automatic fallback to TCP when UDP is blocked (corporate firewalls, some mobile networks).

```rust
use fastnet::tcp::{HybridSocket, TransportMode};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Automatically tries UDP, falls back to TCP if blocked
    let mut socket = HybridSocket::connect("game.example.com:7778").await?;
    
    match socket.transport_mode() {
        TransportMode::Udp => println!("Using UDP (optimal)"),
        TransportMode::Tcp => println!("Using TCP (fallback)"),
    }
    
    // API is identical regardless of transport
    socket.send(1, 0, b"Hello!".to_vec()).await?;
    
    Ok(())
}
```

---

## Asset Distribution

Efficient large file transfers with chunking, compression, and integrity verification.

```rust
use fastnet::assets::{AssetServer, AssetClient, AssetEvent};

// Server: Register and serve assets
let mut server = AssetServer::new(Default::default());
server.register("map.pak", "/game/maps/forest.pak").await?;

// Handle requests
if let Some((transfer_id, info)) = server.handle_request(peer_id, "map.pak") {
    // Send chunks
    while let Some(chunk) = server.get_next_chunk(transfer_id)? {
        send_to_peer(peer_id, chunk);
    }
}

// Client: Download assets
let mut client = AssetClient::new();
client.start_download(transfer_id, info, "/local/maps/forest.pak")?;

// Process chunks
client.receive_chunk(chunk)?;

for event in client.poll_events() {
    match event {
        AssetEvent::Progress { received, total, .. } => {
            println!("Download: {:.1}%", (received as f64 / total as f64) * 100.0);
        }
        AssetEvent::Completed { path, .. } => {
            println!("Downloaded: {:?}", path);
        }
        _ => {}
    }
}
```

**Features:**
- 64KB chunked transfers
- LZ4 compression for faster transfers
- BLAKE3 hash verification (per-chunk and per-file)
- Resumable downloads with `resume_download()`
- Pause/cancel with `pause_transfer()`, `cancel_transfer()`
- Transfer statistics with `get_transfer_stats()`
- Retry tracking for failed chunks

---

## Performance Tuning

FastNet includes OS-level optimizations for minimal jitter:

```rust
use fastnet::net::fast::{SocketConfig, batch};

// Apply low-latency configuration
let config = SocketConfig::low_latency();
// - SO_RCVBUF/SO_SNDBUF: 8MB
// - SO_BUSY_POLL: 100µs
// - IP_TOS: 0xB8 (DSCP EF)
// - SO_PRIORITY: 6

// Batch sending (Linux only)
let mut send_batch = batch::SendBatch::new();
send_batch.push(&packet_data, peer_addr);
send_batch.push(&packet_data2, peer_addr2);
batch::sendmmsg(&socket, &send_batch)?;
```

**Linux Tuning Options:**
- `SO_RCVBUF`/`SO_SNDBUF`: 4-8MB buffers
- `SO_BUSY_POLL`: CPU polling for ~10µs latency reduction
- `IP_TOS`: DSCP EF (Expedited Forwarding) for QoS
- `sendmmsg`/`recvmmsg`: Batch multiple packets per syscall

---

## How It Works

### Zero-Allocation Encryption

```rust
// Traditional (slow): allocates new Vec for each packet
let encrypted = cipher.encrypt(data); // creates new Vec

// FastNet (fast): encrypts in-place, no allocation
cipher.encrypt_in_place(&mut buffer); // reuses same buffer
```

### Delta Compression

Instead of sending complete game state every frame, send only what changed:

```
Frame 1: {x: 100, y: 200, health: 100, ammo: 30, ...} → 500 bytes
Frame 2: {x: 101, y: 200, health: 100, ammo: 30, ...} → only x changed!

Without Delta: send 500 bytes
With Delta:    send {offset: 0, value: 101} → 8 bytes (98% smaller!)
```

**Typical savings: 80-95% bandwidth reduction** for game state updates.

### FEC (Forward Error Correction)

Recover lost packets without waiting for retransmission:

```
Send:    [Pkt1] [Pkt2] [Pkt3] [Parity]
Lost:    [Pkt1] [ X  ] [Pkt3] [Parity]
Recover: Pkt2 = Pkt1 XOR Pkt3 XOR Parity ✓
```

Saves 1 RTT (~30ms) on packet loss - critical for fast-paced games.

### Priority Queues

When bandwidth is limited, send important packets first:

```
[CRITICAL] Player death, hit detection  → always sent
[HIGH]     Position updates             → sent next
[NORMAL]   Animations                   → sent if bandwidth allows
[LOW]      Cosmetic effects             → sent when possible
```

### Jitter Buffer

Smooths out network timing variations for voice/video:

```
Packets arrive: [1]...[2][3]...[4][5][6]  (variable timing)
                 ↑       ↑
              delays vary

Jitter Buffer output: [1][2][3][4][5][6]  (constant timing)
```

### 0-RTT Reconnect

Instant reconnection after network change:

```
Normal connection:  Client → "Hello" → Server → "Hello" → ready (1 RTT)
0-RTT reconnect:    Client → "I have ticket" + data → ready instantly!
```

### Connection Migration

Seamless handoff when IP changes (WiFi → 4G):

```
Player on WiFi: IP 192.168.1.50
Switches to 4G: IP 189.45.23.100

Without Migration: disconnected, loses progress
With Migration:    client proves identity with HMAC, keeps playing
```

### Interest Management

For MMOs - only send updates about nearby entities:

```
Game World:
┌─────────────────────────────┐
│  [A]                 [B]    │  A, B, C = far away
│        [You]                │
│                      [C]    │  D, E = nearby
│  [D]   [E]                  │
└─────────────────────────────┘

Without Interest: receive updates from A,B,C,D,E (5 players)
With Interest:    receive only D,E (nearby) → 60% less bandwidth
```

### BBR Congestion Control

Google's BBR algorithm estimates bandwidth and RTT for optimal throughput:

```
Traditional AIMD (TCP Reno):
  ↗ Slowly increase speed
  ↘ Packet lost? Cut speed in half!
  ↗ Slowly increase again...
  Result: Sawtooth pattern, wastes 50% bandwidth on recovery

BBR (FastNet):
  📊 Continuously estimates: bottleneck bandwidth + min RTT
  🎯 Sends at exactly the optimal rate
  📉 Packet lost? No panic - maintains steady rate
  Result: 2.3x higher throughput under 5% packet loss!
```

**Key benefits:**
- **Resilient to loss**: Doesn't collapse like AIMD under packet loss
- **Low latency**: Keeps queues nearly empty
- **Fast adaptation**: Quickly adjusts to bandwidth changes
- **Better WiFi performance**: Handles variable conditions gracefully

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Application                              │
├─────────────────────────────────────────────────────────────────┤
│                        SecureSocket                              │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   TLS 1.3       │  │  ChaCha20       │  │    Channels     │ │
│  │   Handshake     │──│  Poly1305       │──│   (Reliable/    │ │
│  │   (~40ms)       │  │  Encryption     │  │   Unreliable)   │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│                              │                                   │
│                    ┌─────────┴─────────┐                        │
│                    │   UDP Transport   │                        │
│                    │   (Zero-copy)     │                        │
│                    └───────────────────┘                        │
└─────────────────────────────────────────────────────────────────┘
```

### Security Model

1. **Connection**: Client connects via TCP for TLS 1.3 handshake
2. **Key Exchange**: Server generates unique ChaCha20 keys per client
3. **Data Transfer**: All UDP packets encrypted with AEAD
4. **Authentication**: Each packet includes authentication tag

---

## Channels

| Channel | Use Case | Properties |
|---------|----------|------------|
| `0` - Reliable Ordered | Chat, Commands | Guaranteed delivery & order |
| `1` - Unreliable | Position updates | Fast, may drop |
| `2` - Reliable Unordered | Item pickups | Guaranteed, any order |
| `3` - Sequenced | Input, Voice | Latest packet only |

---

## Generating Certificates

For development:

```bash
# Generate self-signed certificate (valid for 365 days)
openssl req -x509 -newkey rsa:4096 \
    -keyout key.pem -out cert.pem \
    -days 365 -nodes \
    -subj "/CN=localhost"
```

For production, use certificates from Let's Encrypt or your CA.

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

Licensed under the MIT license. See [LICENSE](LICENSE) for details.

---

<p align="center">
  Made with ⚡ for game developers who demand speed and security
</p>
