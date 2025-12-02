# Contributing to FastNet

Thank you for your interest in contributing to FastNet! This document provides guidelines and information for contributors.

## Getting Started

### Prerequisites

- Rust 1.70+ (stable)
- OpenSSL (for certificate generation in tests)

### Setup

```bash
# Clone the repository
git clone https://github.com/filipe-freitas-dev/fastnet.git
cd fastnet

# Build the project
cargo build

# Run tests
cargo test
```

## Development Workflow

### Branch Naming

- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation updates
- `perf/description` - Performance improvements

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `perf`, `refactor`, `test`, `chore`

Examples:
```
feat(channel): add unreliable sequenced channel type
fix(secure): handle connection timeout correctly
docs(readme): add Unreal Engine integration guide
perf(cipher): optimize ChaCha20 encryption path
```

## Code Style

### Rust Guidelines

- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Run `cargo fmt` before committing
- Run `cargo clippy` and address warnings
- Document all public items with doc comments

### Documentation

- Use `//!` for module-level documentation
- Use `///` for item-level documentation
- Include examples in doc comments when helpful
- Keep documentation in sync with code changes

Example:
```rust
/// Sends data to a connected peer.
///
/// # Parameters
///
/// - `peer_id`: Target peer ID
/// - `channel`: Channel to send on (0-255)
/// - `data`: Payload to send
///
/// # Example
///
/// ```rust,no_run
/// socket.send(peer_id, 0, b"Hello!".to_vec()).await?;
/// ```
pub async fn send(&mut self, peer_id: u16, channel: u8, data: Vec<u8>) -> io::Result<()>
```

## Testing

### Running Tests

```bash
# All tests
cargo test

# Specific test
cargo test test_name

# With output
cargo test -- --nocapture
```

### Writing Tests

- Place unit tests in the same file as the code
- Place integration tests in `tests/`
- Use descriptive test names

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect_and_send_receives_echo() {
        // Test implementation
    }
}
```

## Pull Request Process

1. **Fork** the repository
2. **Create** a feature branch from `main`
3. **Make** your changes
4. **Test** thoroughly
5. **Update** documentation if needed
6. **Submit** a pull request

### PR Checklist

- [ ] Code compiles without warnings (`cargo build`)
- [ ] All tests pass (`cargo test`)
- [ ] Code is formatted (`cargo fmt`)
- [ ] No clippy warnings (`cargo clippy`)
- [ ] Documentation is updated
- [ ] CHANGELOG.md is updated (for notable changes)

## Performance Considerations

FastNet is designed for ultra-low latency. When contributing:

- **Avoid allocations** in hot paths
- **Use zero-copy** techniques where possible
- **Benchmark** changes that affect performance
- **Profile** before and after optimizations

Run benchmarks:
```bash
cargo run --example benchmark --release --features dev-certs
```

## Areas for Contribution

### High Priority

- [ ] Connection timeout handling
- [ ] Graceful disconnection protocol
- [ ] Packet retransmission for reliable channels
- [ ] Unity C# bindings

### Nice to Have

- [ ] WebRTC transport option
- [ ] Built-in compression (LZ4)
- [ ] Connection migration
- [ ] Metrics/telemetry hooks

## Questions?

- Open an issue for bugs or feature requests
- Start a discussion for questions
- Email: filipe.freitas@filipefreitas.dev

## License

By contributing, you agree that your contributions will be licensed under the MIT OR Apache-2.0 license.
