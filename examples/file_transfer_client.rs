//! File Transfer Client Template
//!
//! An encrypted file transfer client using FastNet.
//! Can upload files, download files, and list available files on the server.
//!
//! # Running
//!
//! First, start the server:
//! ```bash
//! cargo run --example file_transfer_server --features dev-certs
//! ```
//!
//! Then run this client:
//! ```bash
//! cargo run --example file_transfer_client --features dev-certs
//! ```

#[tokio::main]
async fn main() -> std::io::Result<()> {
    #[cfg(not(feature = "dev-certs"))]
    {
        eprintln!("Run with: cargo run --example file_transfer_client --features dev-certs");
        return Ok(());
    }

    #[cfg(feature = "dev-certs")]
    {
        use std::time::Duration;
        use fastnet::{SecureSocket, SecureEvent};

        const CMD_UPLOAD: u8 = 0x01;
        const CMD_DOWNLOAD: u8 = 0x02;
        const CMD_LIST: u8 = 0x03;
        const RESP_OK: u8 = 0x10;
        const RESP_ERROR: u8 = 0x11;
        const RESP_FILE_DATA: u8 = 0x12;
        const RESP_FILE_LIST: u8 = 0x13;

        fn build_upload(filename: &str, data: &[u8]) -> Vec<u8> {
            let name_bytes = filename.as_bytes();
            let mut buf = Vec::with_capacity(3 + name_bytes.len() + 8 + data.len());
            buf.push(CMD_UPLOAD);
            buf.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            buf.extend_from_slice(name_bytes);
            buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
            buf.extend_from_slice(data);
            buf
        }

        fn build_download(filename: &str) -> Vec<u8> {
            let name_bytes = filename.as_bytes();
            let mut buf = Vec::with_capacity(3 + name_bytes.len());
            buf.push(CMD_DOWNLOAD);
            buf.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            buf.extend_from_slice(name_bytes);
            buf
        }

        fn wait_response(text: &str) -> String {
            match text.first().copied() {
                Some(b) if b == RESP_OK => format!("[OK] {}", String::from_utf8_lossy(&text.as_bytes()[1..])),
                Some(b) if b == RESP_ERROR => format!("[ERROR] {}", String::from_utf8_lossy(&text.as_bytes()[1..])),
                Some(b) if b == RESP_FILE_LIST => format!("[FILES]\n{}", String::from_utf8_lossy(&text.as_bytes()[1..])),
                Some(b) if b == RESP_FILE_DATA => {
                    let data = text.as_bytes();
                    if data.len() >= 4 {
                        let name_len = u16::from_le_bytes([data[1], data[2]]) as usize;
                        if data.len() >= 3 + name_len + 8 {
                            let filename = String::from_utf8_lossy(&data[3..3 + name_len]);
                            let file_size = u64::from_le_bytes(
                                data[3 + name_len..3 + name_len + 8].try_into().unwrap()
                            );
                            return format!("[FILE] '{}' ({} bytes received)", filename, file_size);
                        }
                    }
                    "[FILE] Received".to_string()
                }
                _ => format!("[?] {}", text),
            }
        }

        println!("╔═══════════════════════════════════════╗");
        println!("║    FastNet File Transfer Client       ║");
        println!("╚═══════════════════════════════════════╝");
        println!();

        let server_addr = "127.0.0.1:9102".parse().unwrap();
        println!("Connecting to {}...", server_addr);

        let mut client = SecureSocket::connect(server_addr).await?;

        let peer_id = 'wait: loop {
            for event in client.poll().await? {
                if let SecureEvent::Connected(id) = event {
                    break 'wait id;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        println!("Connected as peer {}\n", peer_id);

        // Demo: Upload some files
        println!("--- Uploading files ---");

        let files_to_upload = [
            ("hello.txt", b"Hello, World! This is an encrypted file transfer.".as_slice()),
            ("config.json", br#"{"server": "localhost", "port": 9102, "encrypted": true}"#.as_slice()),
            ("data.bin", &[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03]),
        ];

        for (name, data) in &files_to_upload {
            let upload_msg = build_upload(name, data);
            client.send(peer_id, 0, upload_msg).await?;
            println!("  Uploaded '{}' ({} bytes)", name, data.len());

            // Wait for server response
            tokio::time::sleep(Duration::from_millis(50)).await;
            for event in client.poll().await? {
                if let SecureEvent::Data(_, _, resp) = event {
                    let text = String::from_utf8_lossy(&resp);
                    println!("  Server: {}", wait_response(&text));
                }
            }
        }

        // Demo: List files
        println!("\n--- Listing files ---");
        client.send(peer_id, 0, vec![CMD_LIST]).await?;
        tokio::time::sleep(Duration::from_millis(50)).await;
        for event in client.poll().await? {
            if let SecureEvent::Data(_, _, resp) = event {
                if !resp.is_empty() && resp[0] == RESP_FILE_LIST {
                    let listing = String::from_utf8_lossy(&resp[1..]);
                    println!("  Available files:");
                    for entry in listing.split('\n') {
                        if let Some((name, size)) = entry.split_once(':') {
                            println!("    {} ({} bytes)", name, size);
                        }
                    }
                }
            }
        }

        // Demo: Download a file
        println!("\n--- Downloading 'hello.txt' ---");
        let download_msg = build_download("hello.txt");
        client.send(peer_id, 0, download_msg).await?;
        tokio::time::sleep(Duration::from_millis(50)).await;
        for event in client.poll().await? {
            if let SecureEvent::Data(_, _, resp) = event {
                if !resp.is_empty() && resp[0] == RESP_FILE_DATA && resp.len() >= 4 {
                    let name_len = u16::from_le_bytes([resp[1], resp[2]]) as usize;
                    if resp.len() >= 3 + name_len + 8 {
                        let filename = String::from_utf8_lossy(&resp[3..3 + name_len]);
                        let data_start = 3 + name_len + 8;
                        let content = String::from_utf8_lossy(&resp[data_start..]);
                        println!("  Downloaded '{}': \"{}\"", filename, content);
                    }
                }
            }
        }

        // Graceful disconnect
        println!("\nDisconnecting...");
        client.disconnect(peer_id).await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        println!("Done!");

        Ok(())
    }
}
