# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in FastNet, please report it by sending an email to **security@filipefreitas.dev**.

Please include:

1. **Description** of the vulnerability
2. **Steps to reproduce** the issue
3. **Potential impact** assessment
4. **Suggested fix** (if any)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity (critical: 24-48h, high: 7 days, medium: 30 days)

## Security Model

FastNet uses a layered security approach:

### 1. Key Exchange (TLS 1.3)

- Initial connection uses TLS 1.3 over TCP
- Server authenticates with X.509 certificate
- Ephemeral keys generated per session
- Forward secrecy guaranteed

### 2. Packet Encryption (ChaCha20-Poly1305)

- All UDP packets encrypted with AEAD
- 256-bit keys derived from TLS handshake
- 64-bit nonces (counter-based, no reuse)
- 128-bit authentication tags

### 3. Protocol Security

- Per-peer encryption keys (compromise isolation)
- Sequence numbers prevent replay attacks
- No plaintext metadata exposure

## Known Limitations

1. **Certificate Validation**: Client currently accepts self-signed certificates for development convenience. In production, implement proper certificate validation.

2. **DoS Protection**: No built-in rate limiting. Implement at application layer.

3. **Key Rotation**: Keys are session-bound. For long sessions, consider reconnecting periodically.

## Best Practices

### For Server Operators

```bash
# Generate production certificates
openssl req -x509 -newkey rsa:4096 \
    -keyout key.pem -out cert.pem \
    -days 365 -nodes \
    -subj "/CN=your-game-server.com"

# Use Let's Encrypt for public servers
certbot certonly --standalone -d your-game-server.com
```

### For Developers

- Never commit certificates to version control
- Use environment variables for certificate paths
- Implement connection timeouts
- Log security events (failed handshakes, invalid packets)

## Cryptographic Dependencies

FastNet relies on well-audited cryptographic libraries:

- **rustls** (v0.23) - TLS implementation
- **chacha20poly1305** (v0.10) - AEAD cipher
- **rand** (v0.9) - Secure random number generation

All dependencies are pure Rust with no C bindings, reducing attack surface.
