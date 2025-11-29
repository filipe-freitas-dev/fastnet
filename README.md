```
╔═╗╔═╗╔═╗╔╦╗╔╗╔╔═╗╔╦╗
╠╣ ╠═╣╚═╗ ║ ║║║║╣  ║   Ultra-low latency encrypted networking
╚  ╩ ╩╚═╝ ╩ ╝╚╝╚═╝ ╩   for real-time games
```

[![Crates.io](https://img.shields.io/crates/v/fastnet.svg)](https://crates.io/crates/fastnet)
[![Documentation](https://docs.rs/fastnet/badge.svg)](https://docs.rs/fastnet)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

**FastNet** is a high-performance networking library designed for real-time multiplayer games. It provides encrypted UDP communication with latencies as low as **15 microseconds** while maintaining strong security through TLS 1.3 and ChaCha20-Poly1305 encryption.

---

## Features

- **Ultra-Low Latency**: ~15µs average RTT on localhost, competitive with raw UDP
- **Built-in Encryption**: TLS 1.3 handshake + ChaCha20-Poly1305 AEAD
- **Zero Configuration Security**: No need to understand cryptography
- **Game Engine Ready**: C/C++ FFI for Unreal Engine, Unity, Godot
- **Async/Await**: Built on Tokio for efficient I/O
- **Reliable & Unreliable Channels**: Choose the right mode for your data

---

## Benchmarks

Tested with 50,000 packets at 10,000 packets/second on localhost:

| Metric | ENet | FastNet | QUIC |
|--------|------|---------|------|
| **Avg Latency** | 112.7 µs | **15.6 µs** | 64.0 µs |
| **P99 Latency** | 143.0 µs | **69.6 µs** | 170.0 µs |
| **Max Latency** | 323 µs | **103.6 µs** | 1868 µs |
| **Encryption** | None | ChaCha20 | TLS |

```
Average Latency (lower is better)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

FastNet      ██ 15.6 µs ⚡
QUIC         ████████ 64.0 µs
ENet         ██████████████ 112.7 µs
```

> **7x faster** than ENet with full encryption enabled
>
> *Note: Max latency spikes in FastNet/QUIC are due to TLS overhead during handshake*

---

## Quick Start

### Rust

Add to your `Cargo.toml`:

```toml
[dependencies]
fastnet = "0.1"
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

```Cargo.toml
fastnet = {version = "0.1.3", features = ["ffi"]}
```
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

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

---

<p align="center">
  Made with ⚡ for game developers who demand speed and security
</p>
