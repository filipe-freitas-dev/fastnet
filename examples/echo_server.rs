//! Simple echo server example
//!
//! Requires dev-certs feature for certificate generation:
//! ```bash
//! cargo run --example echo_server --features dev-certs
//! ```

#[cfg(feature = "dev-certs")]
use {
    std::net::SocketAddr,
    fastnet::{SecureSocket, SecureEvent},
};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    #[cfg(not(feature = "dev-certs"))]
    {
        eprintln!("This example requires the 'dev-certs' feature.");
        eprintln!("Run with: cargo run --example echo_server --features dev-certs");
        return Ok(());
    }
    
    #[cfg(feature = "dev-certs")]
    {
        use rcgen::generate_simple_self_signed;
        use rustls::pki_types::PrivateKeyDer;
        
        // Generate self-signed certificate for development
        let cert = generate_simple_self_signed(vec!["localhost".into()])
            .expect("Failed to generate certificate");
        
        let certs = vec![cert.cert.der().clone()];
        let key = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
        
        let udp_addr: SocketAddr = "127.0.0.1:7777".parse().unwrap();
        let tcp_addr: SocketAddr = "127.0.0.1:7778".parse().unwrap();
        
        println!("Starting echo server...");
        println!("  UDP: {}", udp_addr);
        println!("  TCP: {}", tcp_addr);
        
        let mut socket = SecureSocket::bind_server(udp_addr, tcp_addr, certs, key).await?;
        println!("Server ready! Waiting for connections...\n");
        
        loop {
            for event in socket.poll().await? {
                match event {
                    SecureEvent::Connected(peer_id) => {
                        println!("[+] Peer {} connected", peer_id);
                    }
                    SecureEvent::Data(peer_id, channel, data) => {
                        println!("[<] Peer {}: {} bytes on channel {}", peer_id, data.len(), channel);
                        // Echo back
                        if let Err(e) = socket.send(peer_id, channel, data).await {
                            eprintln!("[!] Send error: {}", e);
                        }
                    }
                    SecureEvent::Disconnected(peer_id) => {
                        println!("[-] Peer {} disconnected", peer_id);
                    }
                }
            }
        }
    }
}
