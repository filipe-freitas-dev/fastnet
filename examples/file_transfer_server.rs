//! File Transfer Server Template
//!
//! An encrypted file transfer server using FastNet.
//! Receives file uploads and serves file downloads over reliable channels.
//!
//! # Protocol (binary)
//! - UPLOAD:   [0x01][filename_len:2][filename][file_size:8][data...]
//! - DOWNLOAD: [0x02][filename_len:2][filename]
//! - LIST:     [0x03]
//! - Response: [0x10]=OK, [0x11]=ERROR, [0x12]=FILE_DATA, [0x13]=FILE_LIST
//!
//! # Running
//!
//! ```bash
//! cargo run --example file_transfer_server --features dev-certs
//! ```

#[tokio::main]
async fn main() -> std::io::Result<()> {
    #[cfg(not(feature = "dev-certs"))]
    {
        eprintln!("Run with: cargo run --example file_transfer_server --features dev-certs");
        return Ok(());
    }

    #[cfg(feature = "dev-certs")]
    {
        use std::collections::HashMap;
        use std::net::SocketAddr;
        use fastnet::{SecureSocket, SecureEvent};
        use rcgen::generate_simple_self_signed;
        use rustls::pki_types::PrivateKeyDer;

        const CMD_UPLOAD: u8 = 0x01;
        const CMD_DOWNLOAD: u8 = 0x02;
        const CMD_LIST: u8 = 0x03;
        const RESP_OK: u8 = 0x10;
        const RESP_ERROR: u8 = 0x11;
        const RESP_FILE_DATA: u8 = 0x12;
        const RESP_FILE_LIST: u8 = 0x13;

        println!("╔═══════════════════════════════════════╗");
        println!("║    FastNet File Transfer Server       ║");
        println!("╚═══════════════════════════════════════╝");
        println!();

        let cert = generate_simple_self_signed(vec!["localhost".into()])
            .expect("Failed to generate certificate");
        let certs = vec![cert.cert.der().clone()];
        let key = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());

        let udp_addr: SocketAddr = "127.0.0.1:9101".parse().unwrap();
        let tcp_addr: SocketAddr = "127.0.0.1:9102".parse().unwrap();

        let mut server = SecureSocket::bind_server(udp_addr, tcp_addr, certs, key).await?;

        println!("File transfer server listening:");
        println!("  UDP: {}  |  TCP: {}", udp_addr, tcp_addr);
        println!();

        // In-memory file storage (template: use filesystem in production)
        let mut files: HashMap<String, Vec<u8>> = HashMap::new();

        loop {
            let events = server.poll().await?;
            let mut responses: Vec<(u16, Vec<u8>)> = Vec::new();

            for event in &events {
                match event {
                    SecureEvent::Connected(peer_id) => {
                        println!("[+] Peer {} connected", peer_id);
                    }
                    SecureEvent::Data(peer_id, _channel, data) => {
                        if data.is_empty() { continue; }

                        match data[0] {
                            CMD_UPLOAD => {
                                // Parse: [0x01][name_len:2][name][file_size:8][data]
                                if data.len() < 4 { continue; }
                                let name_len = u16::from_le_bytes([data[1], data[2]]) as usize;
                                if data.len() < 3 + name_len + 8 { continue; }

                                let filename = String::from_utf8_lossy(&data[3..3 + name_len]).to_string();
                                let file_size = u64::from_le_bytes(
                                    data[3 + name_len..3 + name_len + 8].try_into().unwrap()
                                ) as usize;
                                let file_data_start = 3 + name_len + 8;
                                let file_data = data[file_data_start..].to_vec();

                                println!("[↑] Peer {} uploading '{}' ({} bytes, received {})",
                                         peer_id, filename, file_size, file_data.len());

                                files.insert(filename.clone(), file_data);

                                let mut resp = vec![RESP_OK];
                                resp.extend_from_slice(
                                    format!("Uploaded '{}' ({} bytes)", filename, file_size).as_bytes()
                                );
                                responses.push((*peer_id, resp));
                            }
                            CMD_DOWNLOAD => {
                                if data.len() < 4 { continue; }
                                let name_len = u16::from_le_bytes([data[1], data[2]]) as usize;
                                if data.len() < 3 + name_len { continue; }

                                let filename = String::from_utf8_lossy(&data[3..3 + name_len]).to_string();
                                println!("[↓] Peer {} requesting '{}'", peer_id, filename);

                                if let Some(file_data) = files.get(&filename) {
                                    let name_bytes = filename.as_bytes();
                                    let mut resp = Vec::with_capacity(3 + name_bytes.len() + 8 + file_data.len());
                                    resp.push(RESP_FILE_DATA);
                                    resp.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
                                    resp.extend_from_slice(name_bytes);
                                    resp.extend_from_slice(&(file_data.len() as u64).to_le_bytes());
                                    resp.extend_from_slice(file_data);
                                    responses.push((*peer_id, resp));
                                    println!("  Sending {} bytes", file_data.len());
                                } else {
                                    let mut resp = vec![RESP_ERROR];
                                    resp.extend_from_slice(
                                        format!("File '{}' not found", filename).as_bytes()
                                    );
                                    responses.push((*peer_id, resp));
                                }
                            }
                            CMD_LIST => {
                                println!("[?] Peer {} listing files", peer_id);
                                let mut resp = vec![RESP_FILE_LIST];
                                let listing: Vec<String> = files.iter()
                                    .map(|(name, data)| format!("{}:{}", name, data.len()))
                                    .collect();
                                resp.extend_from_slice(listing.join("\n").as_bytes());
                                responses.push((*peer_id, resp));
                            }
                            _ => {
                                let mut resp = vec![RESP_ERROR];
                                resp.extend_from_slice(b"Unknown command");
                                responses.push((*peer_id, resp));
                            }
                        }
                    }
                    SecureEvent::Disconnected(peer_id) => {
                        println!("[-] Peer {} disconnected", peer_id);
                    }
                }
            }

            // Channel 0 (ReliableOrdered) for file transfers
            for (peer_id, data) in responses {
                let _ = server.send(peer_id, 0, data).await;
            }
        }
    }
}
