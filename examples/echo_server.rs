//! Echo Server Example
//!
//! A simple echo server that demonstrates FastNet's server capabilities.
//! It accepts connections and echoes back any data received.
//!
//! # Running
//!
//! ```bash
//! cargo run --example echo_server --features dev-certs
//! ```
//!
//! Then connect with:
//! ```bash
//! cargo run --example echo_client --features dev-certs
//! ```

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
        use std::net::SocketAddr;
        use fastnet::{SecureSocket, SecureEvent};
        use rcgen::generate_simple_self_signed;
        use rustls::pki_types::PrivateKeyDer;

        println!("╔═══════════════════════════════════════╗");
        println!("║       FastNet Echo Server             ║");
        println!("╚═══════════════════════════════════════╝");
        println!();

        // Generate self-signed certificate for development
        let cert = generate_simple_self_signed(vec!["localhost".into()])
            .expect("Failed to generate certificate");
        let certs = vec![cert.cert.der().clone()];
        let key = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());

        let udp_addr: SocketAddr = "127.0.0.1:7777".parse().unwrap();
        let tcp_addr: SocketAddr = "127.0.0.1:7778".parse().unwrap();

        let mut server = SecureSocket::bind_server(udp_addr, tcp_addr, certs, key).await?;

        println!("Server listening:");
        println!("  UDP (data):      {}", udp_addr);
        println!("  TCP (handshake): {}", tcp_addr);
        println!();
        println!("Waiting for connections...");
        println!();

        loop {
            for event in server.poll().await? {
                match event {
                    SecureEvent::Connected(peer_id) => {
                        println!("[+] Peer {} connected", peer_id);
                        println!("    Total peers: {}", server.peer_count());
                    }
                    SecureEvent::Data(peer_id, channel, data) => {
                        println!(
                            "[<] Peer {} sent {} bytes on channel {}",
                            peer_id,
                            data.len(),
                            channel
                        );
                        
                        // Echo back
                        if let Err(e) = server.send(peer_id, channel, data).await {
                            eprintln!("[!] Failed to echo to peer {}: {}", peer_id, e);
                        } else {
                            println!("[>] Echoed back to peer {}", peer_id);
                        }
                    }
                    SecureEvent::Disconnected(peer_id) => {
                        println!("[-] Peer {} disconnected", peer_id);
                        println!("    Total peers: {}", server.peer_count());
                    }
                }
            }
        }
    }
}
