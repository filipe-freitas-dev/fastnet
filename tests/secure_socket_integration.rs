//! Integration tests for SecureSocket: connection, send/recv, serialization, and disconnection.
//!
//! Run with:
//! ```bash
//! cargo test --test secure_socket_integration --features dev-certs -- --nocapture
//! ```

#[cfg(feature = "dev-certs")]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use fastnet::{SecureSocket, SecureEvent};
    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::PrivateKeyDer;
    use tokio::sync::Mutex;

    /// Helper: generate self-signed TLS cert + key for tests.
    fn gen_certs() -> (Vec<rustls::pki_types::CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let cert = generate_simple_self_signed(vec!["localhost".into()])
            .expect("Failed to generate certificate");
        let certs = vec![cert.cert.der().clone()];
        let key = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
        (certs, key)
    }

    /// Helper: start server, connect client concurrently, return both with peer IDs.
    /// The server's poll() must run concurrently with the client's connect() for TLS to complete.
    async fn setup_connected_pair() -> (SecureSocket, SecureSocket, u16, u16) {
        let (certs, key) = gen_certs();

        let udp_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let tcp_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let mut server = SecureSocket::bind_server(udp_addr, tcp_addr, certs, key)
            .await
            .expect("Failed to bind server");

        let actual_tcp = server.local_tcp_addr().unwrap().unwrap();

        // Run server accept and client connect concurrently
        let server_handle = tokio::spawn(async move {
            // Server poll will accept the TLS connection
            let events = server.poll().await.expect("Server poll failed");
            let server_peer_id = events.iter().find_map(|e| {
                if let SecureEvent::Connected(id) = e { Some(*id) } else { None }
            }).expect("Server should get Connected event");
            (server, server_peer_id)
        });

        // Client connects (TLS handshake happens here)
        let mut client = SecureSocket::connect(actual_tcp)
            .await
            .expect("Client failed to connect");

        // Client should already have Connected event from connect()
        let client_events = client.poll().await.expect("Client poll failed");
        let client_peer_id = client_events.iter().find_map(|e| {
            if let SecureEvent::Connected(id) = e { Some(*id) } else { None }
        }).expect("Client should get Connected event");

        let (server, server_peer_id) = server_handle.await.unwrap();

        (server, client, server_peer_id, client_peer_id)
    }

    // ==================== TEST 1: Basic Connection ====================

    #[tokio::test]
    async fn test_connection() {
        println!("\n=== TEST: Basic Connection ===");

        let (server, _client, server_peer_id, client_peer_id) = setup_connected_pair().await;

        println!("[client] Connected as peer {}", client_peer_id);
        println!("[server] Peer {} connected", server_peer_id);
        assert_eq!(server.peer_count(), 1, "Server should have 1 peer");

        println!("[OK] Connection test passed\n");
    }

    // ==================== TEST 2: Send and Receive Data ====================

    #[tokio::test]
    async fn test_send_receive() {
        println!("\n=== TEST: Send and Receive ===");

        let (mut server, mut client, server_peer_id, client_peer_id) =
            setup_connected_pair().await;

        // Client sends data
        let test_data = b"Hello, FastNet!".to_vec();
        client.send(client_peer_id, 0, test_data.clone()).await
            .expect("Client send failed");
        println!("[client] Sent: {:?}", String::from_utf8_lossy(&test_data));

        // Server receives data
        let mut received = false;
        for _ in 0..50 {
            let events = server.poll().await.unwrap();
            for event in &events {
                if let SecureEvent::Data(peer_id, channel, data) = event {
                    println!("[server] Received from peer {}, channel {}: {:?}",
                             peer_id, channel, String::from_utf8_lossy(data));
                    assert_eq!(*peer_id, server_peer_id);
                    assert_eq!(data, &test_data);
                    assert_eq!(*channel, 0);
                    received = true;

                    // Echo back
                    server.send(*peer_id, *channel, data.clone()).await
                        .expect("Server echo failed");
                    println!("[server] Echoed back");
                }
            }
            if received { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(received, "Server should have received data");

        // Client receives echo
        let mut echo_received = false;
        for _ in 0..50 {
            let events = client.poll().await.unwrap();
            for event in &events {
                if let SecureEvent::Data(_, _, data) = event {
                    println!("[client] Echo received: {:?}", String::from_utf8_lossy(data));
                    assert_eq!(data, &test_data);
                    echo_received = true;
                }
            }
            if echo_received { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(echo_received, "Client should have received echo");

        println!("[OK] Send/Receive test passed\n");
    }

    // ==================== TEST 3: Data Serialization ====================

    #[tokio::test]
    async fn test_data_serialization() {
        println!("\n=== TEST: Data Serialization ===");

        let (mut server, mut client, _server_peer_id, client_peer_id) =
            setup_connected_pair().await;

        // Test various data types serialized as bytes
        let test_cases: Vec<(&str, Vec<u8>)> = vec![
            ("Single byte", vec![0xFF]),
            ("Binary zeros", vec![0, 0, 0, 0]),
            ("UTF-8 string", "Olá, mundo! 🌍".as_bytes().to_vec()),
            ("u32 LE", 42u32.to_le_bytes().to_vec()),
            ("f64 LE", std::f64::consts::PI.to_le_bytes().to_vec()),
            ("Mixed struct", {
                let mut buf = Vec::new();
                buf.extend_from_slice(&100.5f32.to_le_bytes());
                buf.extend_from_slice(&200.75f32.to_le_bytes());
                buf.extend_from_slice(&95u16.to_le_bytes());
                buf.push(0b1010_0101);
                buf
            }),
            ("Large payload", vec![0xAB; 1000]),
        ];

        for (name, data) in &test_cases {
            println!("[test] Sending: {} ({} bytes)", name, data.len());
            client.send(client_peer_id, 0, data.clone()).await
                .expect("Send failed");

            let mut received = false;
            for _ in 0..50 {
                let events = server.poll().await.unwrap();
                for event in &events {
                    if let SecureEvent::Data(_, _, recv_data) = event {
                        assert_eq!(recv_data, data,
                                   "Data mismatch for test case: {}", name);
                        println!("[  ok] Received correctly: {} ({} bytes)", name, recv_data.len());
                        received = true;
                    }
                }
                if received { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(received, "Failed to receive data for: {}", name);
        }

        println!("[OK] Serialization test passed\n");
    }

    // ==================== TEST 4: Client Disconnection ====================

    #[tokio::test]
    async fn test_client_disconnect() {
        println!("\n=== TEST: Client Disconnection ===");

        let (mut server, mut client, server_peer_id, client_peer_id) =
            setup_connected_pair().await;

        println!("[client] peer_id={}, [server] sees peer_id={}", client_peer_id, server_peer_id);
        assert_eq!(server.peer_count(), 1);

        // Client sends data first to ensure UDP address is resolved on server
        client.send(client_peer_id, 0, b"pre-disconnect data".to_vec()).await.unwrap();
        println!("[client] Sent pre-disconnect data");

        // Server receives to resolve the client's UDP address
        let mut data_received = false;
        for _ in 0..50 {
            let events = server.poll().await.unwrap();
            for event in &events {
                if let SecureEvent::Data(_, _, _) = event {
                    data_received = true;
                }
            }
            if data_received { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(data_received, "Server should have received pre-disconnect data");

        // Client disconnects
        println!("[client] Calling disconnect({})...", client_peer_id);
        let disconnect_result = client.disconnect(client_peer_id).await;
        println!("[client] disconnect() returned: {:?}", disconnect_result);
        assert!(disconnect_result.is_ok(), "Client disconnect should succeed");

        assert_eq!(client.peer_count(), 0, "Client should have 0 peers after disconnect");
        println!("[client] peer_count={}", client.peer_count());

        // Server should receive disconnect notification
        let mut server_got_disconnect = false;
        for attempt in 0..100 {
            let events = server.poll().await.unwrap();
            for event in &events {
                match event {
                    SecureEvent::Disconnected(id) => {
                        println!("[server] Peer {} disconnected (attempt {})", id, attempt);
                        assert_eq!(*id, server_peer_id);
                        server_got_disconnect = true;
                    }
                    other => {
                        println!("[server] Got other event: {:?}", other);
                    }
                }
            }
            if server_got_disconnect { break; }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        assert!(server_got_disconnect, "Server should receive Disconnected event for the client");
        assert_eq!(server.peer_count(), 0, "Server should have 0 peers after client disconnect");
        println!("[OK] Client disconnection test passed\n");
    }

    // ==================== TEST 5: Server Disconnects Client ====================

    #[tokio::test]
    async fn test_server_disconnect() {
        println!("\n=== TEST: Server Disconnects Client ===");

        let (mut server, mut client, server_peer_id, client_peer_id) =
            setup_connected_pair().await;

        // Client sends data first so server knows client's UDP address
        client.send(client_peer_id, 0, b"hello from client".to_vec()).await.unwrap();

        // Server receives the data (resolves client UDP addr)
        let mut data_received = false;
        for _ in 0..50 {
            let events = server.poll().await.unwrap();
            for event in &events {
                if let SecureEvent::Data(_, _, _) = event {
                    data_received = true;
                }
            }
            if data_received { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(data_received);

        // Server disconnects the client
        println!("[server] Calling disconnect({})...", server_peer_id);
        let result = server.disconnect(server_peer_id).await;
        println!("[server] disconnect() returned: {:?}", result);
        assert!(result.is_ok(), "Server disconnect should succeed");

        assert_eq!(server.peer_count(), 0, "Server should have 0 peers");

        // Client should receive disconnect notification
        let mut client_got_disconnect = false;
        for attempt in 0..100 {
            let events = client.poll().await.unwrap();
            for event in &events {
                match event {
                    SecureEvent::Disconnected(id) => {
                        println!("[client] Disconnected by server, peer_id={} (attempt {})", id, attempt);
                        client_got_disconnect = true;
                    }
                    other => {
                        println!("[client] Got other event: {:?}", other);
                    }
                }
            }
            if client_got_disconnect { break; }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        assert!(client_got_disconnect, "Client should receive Disconnected event from server");
        assert_eq!(client.peer_count(), 0, "Client should have 0 peers after server disconnect");

        println!("[OK] Server disconnection test passed\n");
    }

    // ==================== TEST 6: Multiple Clients ====================

    #[tokio::test]
    async fn test_multiple_clients() {
        println!("\n=== TEST: Multiple Clients ===");

        let (certs, key) = gen_certs();
        let udp_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let tcp_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let server = Arc::new(Mutex::new(
            SecureSocket::bind_server(udp_addr, tcp_addr, certs, key).await.unwrap()
        ));
        let actual_tcp = server.lock().await.local_tcp_addr().unwrap().unwrap();

        // Connect 3 clients sequentially, each with concurrent server poll
        let mut clients = Vec::new();
        let mut client_peer_ids = Vec::new();
        let mut server_peer_ids = Vec::new();

        for i in 0..3 {
            let server_clone = server.clone();
            let server_handle = tokio::spawn(async move {
                let mut srv = server_clone.lock().await;
                let events = srv.poll().await.expect("Server poll failed");
                events.iter().find_map(|e| {
                    if let SecureEvent::Connected(id) = e { Some(*id) } else { None }
                })
            });

            let mut client = SecureSocket::connect(actual_tcp).await.unwrap();
            let cpid = client.poll().await.unwrap().iter().find_map(|e| {
                if let SecureEvent::Connected(id) = e { Some(*id) } else { None }
            }).unwrap();

            let spid = server_handle.await.unwrap().expect("Server should accept");
            println!("[client {}] peer_id={}, [server] sees peer_id={}", i, cpid, spid);

            client_peer_ids.push(cpid);
            server_peer_ids.push(spid);
            clients.push(client);
        }

        {
            let srv = server.lock().await;
            assert_eq!(srv.peer_count(), 3, "Server should have 3 peers");
            println!("[server] peer_count={}", srv.peer_count());
        }

        // Each client sends data to establish UDP address
        for (i, client) in clients.iter_mut().enumerate() {
            let msg = format!("Hello from client {}", i);
            client.send(client_peer_ids[i], 0, msg.into_bytes()).await.unwrap();
        }

        // Server receives all messages
        {
            let mut srv = server.lock().await;
            let mut messages_received = 0;
            for _ in 0..100 {
                let events = srv.poll().await.unwrap();
                for event in &events {
                    if let SecureEvent::Data(_, _, _) = event {
                        messages_received += 1;
                    }
                }
                if messages_received >= 3 { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(messages_received, 3, "Server should receive 3 messages");
        }

        // Disconnect first client
        println!("[client 0] Disconnecting...");
        clients[0].disconnect(client_peer_ids[0]).await.unwrap();

        // Wait for server to see disconnection
        {
            let mut srv = server.lock().await;
            let mut disconnect_count = 0;
            for _ in 0..100 {
                let events = srv.poll().await.unwrap();
                for event in &events {
                    if let SecureEvent::Disconnected(_) = event {
                        disconnect_count += 1;
                    }
                }
                if disconnect_count >= 1 { break; }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert!(disconnect_count >= 1, "Server should see at least 1 disconnection");
            assert_eq!(srv.peer_count(), 2, "Server should have 2 peers remaining");
            println!("[server] peer_count={} after disconnect", srv.peer_count());
        }

        println!("[OK] Multiple clients test passed\n");
    }

    // ==================== TEST 7: Send After Disconnect (should fail) ====================

    #[tokio::test]
    async fn test_send_after_disconnect() {
        println!("\n=== TEST: Send After Disconnect ===");

        let (_server, mut client, _server_peer_id, client_peer_id) =
            setup_connected_pair().await;

        // Disconnect
        client.disconnect(client_peer_id).await.unwrap();

        // Try to send after disconnect - should fail
        let result = client.send(client_peer_id, 0, b"should fail".to_vec()).await;
        println!("[client] Send after disconnect: {:?}", result);
        assert!(result.is_err(), "Send after disconnect should fail with error");

        println!("[OK] Send after disconnect test passed\n");
    }

    // ==================== TEST 8: Crash detection via timeout ====================

    /// This test exposes the disconnection bug: when a client drops without
    /// calling disconnect(), the server should eventually detect it via timeout.
    /// BUG: PeerConfig::default() has timeout=None, so the server NEVER detects
    /// crashed clients. The fix is to set a reasonable default timeout.
    #[tokio::test]
    async fn test_crash_detection_timeout() {
        println!("\n=== TEST: Crash Detection via Timeout ===");

        let (mut server, mut client, server_peer_id, client_peer_id) =
            setup_connected_pair().await;

        // Client sends data so server resolves its UDP address
        client.send(client_peer_id, 0, b"I will crash soon".to_vec()).await.unwrap();

        let mut data_received = false;
        for _ in 0..50 {
            let events = server.poll().await.unwrap();
            for event in &events {
                if let SecureEvent::Data(_, _, _) = event {
                    data_received = true;
                }
            }
            if data_received { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(data_received);

        println!("[client] Dropping client WITHOUT calling disconnect (simulating crash)...");
        assert_eq!(server.peer_count(), 1, "Server should have 1 peer before crash");

        // Drop the client without disconnect - simulates a crash
        drop(client);

        // Server should detect the crashed client via timeout
        // With the fix: default timeout should be set (e.g. 10 seconds)
        // We use a shorter timeout for the test by polling repeatedly
        let mut server_detected_disconnect = false;
        let start = std::time::Instant::now();
        let max_wait = Duration::from_secs(15);

        while start.elapsed() < max_wait {
            let events = server.poll().await.unwrap();
            for event in &events {
                if let SecureEvent::Disconnected(id) = event {
                    println!("[server] Detected crashed peer {} after {:?}", id, start.elapsed());
                    assert_eq!(*id, server_peer_id);
                    server_detected_disconnect = true;
                }
            }
            if server_detected_disconnect { break; }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        assert!(server_detected_disconnect,
            "BUG: Server should detect crashed client via timeout, but timeout is None by default!");
        assert_eq!(server.peer_count(), 0, "Server should have 0 peers after timeout");

        println!("[OK] Crash detection test passed\n");
    }

    // ==================== TEST 9: Server crash detection from client side ====================

    /// Tests that the CLIENT detects when the SERVER crashes without sending disconnect.
    /// This is the mirror of test_crash_detection_timeout (which tests server detecting crashed client).
    #[tokio::test]
    async fn test_server_crash_detection() {
        println!("\n=== TEST: Server Crash Detection (client side) ===");

        let (mut server, mut client, server_peer_id, client_peer_id) =
            setup_connected_pair().await;

        // Exchange data so both sides have resolved UDP addresses
        client.send(client_peer_id, 0, b"hello server".to_vec()).await.unwrap();

        let mut data_received = false;
        for _ in 0..50 {
            let events = server.poll().await.unwrap();
            for event in &events {
                if let SecureEvent::Data(_, _, _) = event {
                    data_received = true;
                }
            }
            if data_received { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(data_received);

        // Server sends data back so client updates last_recv
        server.send(server_peer_id, 0, b"hello client".to_vec()).await.unwrap();

        let mut echo_received = false;
        for _ in 0..50 {
            let events = client.poll().await.unwrap();
            for event in &events {
                if let SecureEvent::Data(_, _, _) = event {
                    echo_received = true;
                }
            }
            if echo_received { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(echo_received);

        println!("[server] Dropping server WITHOUT calling disconnect (simulating crash)...");
        assert_eq!(client.peer_count(), 1, "Client should have 1 peer before server crash");

        // Drop server - simulates a crash
        drop(server);

        // Client should detect the crashed server via timeout
        let mut client_detected_disconnect = false;
        let start = std::time::Instant::now();
        let max_wait = Duration::from_secs(15);

        while start.elapsed() < max_wait {
            let events = client.poll().await.unwrap();
            for event in &events {
                if let SecureEvent::Disconnected(id) = event {
                    println!("[client] Detected crashed server (peer {}) after {:?}", id, start.elapsed());
                    assert_eq!(*id, client_peer_id);
                    client_detected_disconnect = true;
                }
            }
            if client_detected_disconnect { break; }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        assert!(client_detected_disconnect,
            "Client should detect crashed server via timeout!");
        assert_eq!(client.peer_count(), 0, "Client should have 0 peers after server crash");

        println!("[OK] Server crash detection test passed\n");
    }

    // ==================== TEST 10: Disconnect twice (should fail gracefully) ====================

    #[tokio::test]
    async fn test_double_disconnect() {
        println!("\n=== TEST: Double Disconnect ===");

        let (_server, mut client, _server_peer_id, client_peer_id) =
            setup_connected_pair().await;

        // First disconnect
        client.disconnect(client_peer_id).await.unwrap();
        println!("[client] First disconnect succeeded");

        // Second disconnect - should return error (peer not found)
        let result = client.disconnect(client_peer_id).await;
        println!("[client] Second disconnect result: {:?}", result);
        assert!(result.is_err(), "Double disconnect should return error");

        println!("[OK] Double disconnect test passed\n");
    }
}

#[cfg(not(feature = "dev-certs"))]
#[test]
fn test_requires_dev_certs_feature() {
    eprintln!("Integration tests require the 'dev-certs' feature.");
    eprintln!("Run with: cargo test --test secure_socket_integration --features dev-certs -- --nocapture");
}
