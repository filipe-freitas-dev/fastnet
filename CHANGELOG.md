# Changelog

All notable changes to FastNet will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
