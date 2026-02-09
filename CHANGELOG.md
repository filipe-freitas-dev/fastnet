# Changelog

All notable changes to FastNet will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.7] - 2026-02-09

### Added
- **Automatic Disconnect Detection**: Server now detects client disconnections via timeout
  - `SecureSocket::poll()` now checks for timed-out peers (30s default)
  - Generates `SecureEvent::Disconnected` events automatically
- **Graceful Disconnect Method**: New `SecureSocket::disconnect()` method
  - Allows clients to disconnect gracefully
  - Properly cleans up peer state and generates disconnect events

### Fixed
- **Server Not Receiving Disconnect Events**: Fixed issue where server would never detect when clients disconnected
  - Added `check_timeouts()` method to periodically verify peer connectivity
  - Peers that haven't sent data for more than the timeout period are now properly removed
- **Echo Client Example**: Updated to demonstrate graceful disconnection

## [0.2.5] - 2025-12-08

### Added
- **BBR Congestion Control** (`bbr` module)
  - Google's BBR (Bottleneck Bandwidth and RTT) algorithm
  - 2.3x better throughput under 5% packet loss vs AIMD
  - Estimates bottleneck bandwidth with windowed max filter
  - Tracks minimum RTT with windowed min filter
  - State machine: Startup → Drain → ProbeBW → ProbeRTT
  - Keeps queues nearly empty for minimal latency
  - Adapts quickly to bandwidth changes
  - FFI Delta Compression API for C/C++ applications
  - FFI tests and benchmarks

## [0.2.0] - 2025-12-03

### Performance Improvements
- **Zero-Allocation Encryption**: `encrypt_in_place_detached` eliminates Vec allocation
- **Zero-Allocation Decryption**: `decrypt_in_place_detached` eliminates Vec allocation
- **O(1) ACK Lookups**: Channel pending messages use HashMap instead of VecDeque
- **Zero-Alloc Iterator**: `get_retransmissions()` returns iterator instead of Vec

### Added
- **Forward Error Correction** (`fec` module)
  - XOR parity for single packet recovery per group
  - Configurable group size (default 4 packets)
  - `FecEncoder`/`FecDecoder` with zero-alloc design
- **Delta Compression** (`delta` module)
  - Send only changed bytes between states
  - 80-95% bandwidth reduction for game state
  - Run-length encoding of differences
- **Priority Queues** (`priority` module)
  - 4 priority levels: Critical, High, Normal, Low
  - Critical packets bypass capacity limits
  - `WeightedQueue` for fair bandwidth allocation
- **Jitter Buffer** (`jitter` module)
  - Adaptive delay based on measured jitter
  - Packet reordering and concealment
  - RFC 3550 jitter calculation
- **Connection Metrics** (`metrics` module)
  - Real-time RTT, jitter, loss percentage
  - Throughput monitoring (bytes/sec)
  - Sliding window statistics
- **0-RTT Session Resumption** (`reconnect` module)
  - Encrypted session tickets with BLAKE3 HMAC
  - Replay protection via ticket ID tracking
  - Configurable ticket lifetime
- **Connection Migration** (`migration` module)
  - Seamless IP/network changes without disconnect
  - HMAC-based migration proof
  - Rate limiting for DoS protection
- **Interest Management** (`interest` module)
  - Spatial hash grid for O(1) entity queries
  - Player visibility tracking with enter/leave events
  - Priority calculation based on distance

## [0.1.9] - 2025-12-03

### Added
- **Zero-Allocation Hot Path**
  - Fixed-size buffers for send/recv (`packet_buf`, `recv_buf`, `send_buf`)
  - New `send_bytes()` method for zero-copy sending
  - `process_decrypted_len()` processes directly from buffers
- **Linux Socket Tuning** (`tuning` module)
  - `SocketConfig` with SO_RCVBUF, SO_SNDBUF (4MB default)
  - SO_BUSY_POLL for reduced latency (50µs default)
  - IP_TOS/DSCP marking (EF - Expedited Forwarding)
  - SO_PRIORITY for QoS
  - `low_latency()` and `high_throughput()` presets
- **Batch I/O** (`tuning::batch`)
  - `sendmmsg()`/`recvmmsg()` for multiple packets per syscall
  - `SendBatch`/`RecvBatch` with up to 64 packets
  - Linux-only with no-op fallback for other OS
- **Key Rotation**
  - Automatic key rotation every 1M packets or 1 hour
  - BLAKE3-based key derivation
  - Forward secrecy for long-lived connections
- **Signaling Server Configuration**
  - `SignalingConfig` with `max_peers_per_room` (default 64)
  - Increased message buffer from 32 to 256
  - Room capacity enforcement with error response
- **Asset Transfer Improvements**
  - Real LZ4 compression (`lz4_flex` crate)
  - Resumable downloads with `resume_download()`
  - Pause/cancel transfers (`pause_transfer()`, `cancel_transfer()`)
  - `TransferStats` with speed, elapsed time, progress
  - Retry tracking (`record_chunk_failure()`, `chunk_exceeded_retries()`)

### Changed
- `Cipher` now stores keys for rotation
- `SecureSocket` buffers increased to `MAX_ENCRYPTED_SIZE`
- Assets use real LZ4 compression instead of stub
- Signaling server uses configurable buffer sizes

### Dependencies
- Added `lz4_flex = "0.11"` for LZ4 compression
- Added `libc = "0.2"` for socket tuning syscalls

## [0.1.8] - 2025-12-03

### Added
- **P2P Networking** (`p2p` module)
  - Direct peer-to-peer connections with NAT traversal
  - UDP hole-punching for direct connectivity
  - Automatic relay fallback when direct connection fails
  - Room-based peer discovery
  - Signaling server and client implementation
- **TCP Fallback** (`tcp` module)
  - Automatic fallback to TCP when UDP is blocked
  - `HybridSocket` with transparent transport switching
  - Works through corporate firewalls and restrictive networks
- **Asset Distribution** (`assets` module)
  - Large file transfers with 64KB chunking
  - BLAKE3 hash verification per-chunk and per-file
  - Resumable downloads
  - Progress callbacks
- Added `blake3` dependency for secure hashing

### Changed
- Updated documentation with new feature examples
- Re-exported new types at crate root for convenience

## [0.1.3] - 2025-12-02

### Fixed
- Fixed benchmark hanging at the end
- Updated benchmark results with new measurements

### Changed
- Max latency improved from 1216µs to 103.6µs

## [0.1.2] - 2025-11-29

### Added
- Comprehensive documentation for all public APIs
- C/C++ header documentation with examples
- Latency benchmark example (`examples/benchmark.rs`)

### Changed
- Renamed crate from `rift` to `fastnet`

## [0.1.1] - 2025-11-28

### Added
- FFI module for C/C++ integration
- Unreal Engine C++ wrapper header
- `dev-certs` feature for development certificate generation

### Fixed
- Fixed tokio macros feature requirement

## [0.1.0] - 2025-11-28

### Added
- Initial release
- `SecureSocket` for encrypted UDP communication
- TLS 1.3 handshake for key exchange
- ChaCha20-Poly1305 AEAD encryption
- Multiple channel types:
  - Reliable Ordered
  - Reliable Unordered
  - Unreliable
  - Unreliable Sequenced
- C FFI bindings
- Benchmark comparing with ENet and QUIC

## Performance

Benchmarked on localhost with 10,000 packets:

| Metric | FastNet | ENet | QUIC |
|--------|---------|------|------|
| Avg Latency | 15.6 µs | 112.7 µs | 64.0 µs |
| P99 Latency | 69.6 µs | 143.0 µs | 170.0 µs |
| Max Latency | 103.6 µs | 323 µs | 1868 µs |
| Encryption | ✅ ChaCha20 | ❌ None | ✅ TLS |
