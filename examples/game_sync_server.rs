//! Game State Sync Server Template
//!
//! A real-time game state synchronization server using FastNet.
//! Demonstrates the core use case: broadcasting player positions and actions
//! at high frequency with minimal latency.
//!
//! # Channel Strategy
//! - Channel 0 (ReliableOrdered): Game events (spawn, death, score, chat)
//! - Channel 1 (Unreliable): Position updates at 60Hz (drop-tolerant)
//! - Channel 3 (UnreliableSequenced): Input/action state (only latest matters)
//!
//! # Data Format (binary, LE)
//! - Position: [0x01][player_id:2][x:f32][y:f32][z:f32][rotation:f32] = 19 bytes
//! - Action:   [0x02][player_id:2][action_id:1][param:4] = 8 bytes
//! - Event:    [0x03][event_type:1][payload...]
//! - Snapshot: [0x04][tick:4][num_players:2][...positions...]
//!
//! # Running
//!
//! ```bash
//! cargo run --example game_sync_server --features dev-certs
//! ```

#[tokio::main]
async fn main() -> std::io::Result<()> {
    #[cfg(not(feature = "dev-certs"))]
    {
        eprintln!("Run with: cargo run --example game_sync_server --features dev-certs");
        return Ok(());
    }

    #[cfg(feature = "dev-certs")]
    {
        use std::collections::HashMap;
        use std::net::SocketAddr;
        use fastnet::{SecureSocket, SecureEvent};
        use rcgen::generate_simple_self_signed;
        use rustls::pki_types::PrivateKeyDer;

        const MSG_POSITION: u8 = 0x01;
        const MSG_ACTION: u8 = 0x02;
        const MSG_EVENT: u8 = 0x03;
        const MSG_SNAPSHOT: u8 = 0x04;

        const EVT_PLAYER_JOIN: u8 = 0x01;
        const EVT_PLAYER_LEAVE: u8 = 0x02;
        const EVT_CHAT: u8 = 0x03;

        #[derive(Clone, Debug)]
        struct PlayerState {
            x: f32,
            y: f32,
            z: f32,
            rotation: f32,
        }

        impl PlayerState {
            fn new() -> Self {
                Self { x: 0.0, y: 0.0, z: 0.0, rotation: 0.0 }
            }

            #[allow(dead_code)]
            fn to_bytes(&self, player_id: u16) -> Vec<u8> {
                let mut buf = Vec::with_capacity(19);
                buf.push(MSG_POSITION);
                buf.extend_from_slice(&player_id.to_le_bytes());
                buf.extend_from_slice(&self.x.to_le_bytes());
                buf.extend_from_slice(&self.y.to_le_bytes());
                buf.extend_from_slice(&self.z.to_le_bytes());
                buf.extend_from_slice(&self.rotation.to_le_bytes());
                buf
            }

            fn from_bytes(data: &[u8]) -> Option<(u16, Self)> {
                if data.len() < 19 || data[0] != MSG_POSITION { return None; }
                let player_id = u16::from_le_bytes([data[1], data[2]]);
                let x = f32::from_le_bytes(data[3..7].try_into().ok()?);
                let y = f32::from_le_bytes(data[7..11].try_into().ok()?);
                let z = f32::from_le_bytes(data[11..15].try_into().ok()?);
                let rotation = f32::from_le_bytes(data[15..19].try_into().ok()?);
                Some((player_id, Self { x, y, z, rotation }))
            }
        }

        fn build_event(event_type: u8, payload: &[u8]) -> Vec<u8> {
            let mut buf = Vec::with_capacity(2 + payload.len());
            buf.push(MSG_EVENT);
            buf.push(event_type);
            buf.extend_from_slice(payload);
            buf
        }

        fn build_snapshot(tick: u32, players: &HashMap<u16, PlayerState>) -> Vec<u8> {
            let mut buf = Vec::with_capacity(7 + players.len() * 18);
            buf.push(MSG_SNAPSHOT);
            buf.extend_from_slice(&tick.to_le_bytes());
            buf.extend_from_slice(&(players.len() as u16).to_le_bytes());
            for (&id, state) in players {
                buf.extend_from_slice(&id.to_le_bytes());
                buf.extend_from_slice(&state.x.to_le_bytes());
                buf.extend_from_slice(&state.y.to_le_bytes());
                buf.extend_from_slice(&state.z.to_le_bytes());
                buf.extend_from_slice(&state.rotation.to_le_bytes());
            }
            buf
        }

        println!("╔═══════════════════════════════════════╗");
        println!("║     FastNet Game Sync Server          ║");
        println!("╚═══════════════════════════════════════╝");
        println!();

        let cert = generate_simple_self_signed(vec!["localhost".into()])
            .expect("Failed to generate certificate");
        let certs = vec![cert.cert.der().clone()];
        let key = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());

        let udp_addr: SocketAddr = "127.0.0.1:9201".parse().unwrap();
        let tcp_addr: SocketAddr = "127.0.0.1:9202".parse().unwrap();

        let mut server = SecureSocket::bind_server(udp_addr, tcp_addr, certs, key).await?;

        println!("Game server listening:");
        println!("  UDP: {}  |  TCP: {}", udp_addr, tcp_addr);
        println!("  Ch0=Events(reliable) | Ch1=Position(unreliable) | Ch3=Actions(sequenced)");
        println!();

        let mut players: HashMap<u16, PlayerState> = HashMap::new();
        let mut tick: u32 = 0;
        let mut last_snapshot = std::time::Instant::now();

        loop {
            let events = server.poll().await?;
            let mut outgoing: Vec<(u16, u8, Vec<u8>)> = Vec::new();

            for event in &events {
                match event {
                    SecureEvent::Connected(peer_id) => {
                        println!("[+] Player {} joined", peer_id);
                        players.insert(*peer_id, PlayerState::new());

                        // Send full snapshot to new player
                        let snapshot = build_snapshot(tick, &players);
                        outgoing.push((*peer_id, 0, snapshot));

                        // Notify all other players
                        let join_evt = build_event(EVT_PLAYER_JOIN, &peer_id.to_le_bytes());
                        for &other in players.keys() {
                            if other != *peer_id {
                                outgoing.push((other, 0, join_evt.clone()));
                            }
                        }
                    }
                    SecureEvent::Data(peer_id, channel, data) => {
                        if data.is_empty() { continue; }

                        match data[0] {
                            MSG_POSITION => {
                                // Update player position and broadcast to others
                                if let Some((_, state)) = PlayerState::from_bytes(data) {
                                    players.insert(*peer_id, state);
                                    // Broadcast position on unreliable channel (ch 1)
                                    for &other in players.keys() {
                                        if other != *peer_id {
                                            outgoing.push((other, 1, data.clone()));
                                        }
                                    }
                                }
                            }
                            MSG_ACTION => {
                                // Broadcast action to all other players
                                if data.len() >= 8 {
                                    let action_id = data[3];
                                    println!("[*] Player {} action {} (ch={})",
                                             peer_id, action_id, channel);
                                    for &other in players.keys() {
                                        if other != *peer_id {
                                            // Actions on sequenced channel (ch 3)
                                            outgoing.push((other, 3, data.clone()));
                                        }
                                    }
                                }
                            }
                            MSG_EVENT if data.len() >= 2 => {
                                if data[1] == EVT_CHAT {
                                    let chat_text = String::from_utf8_lossy(&data[2..]);
                                    println!("[chat] Player {}: {}", peer_id, chat_text);
                                    // Broadcast chat on reliable channel
                                    for &other in players.keys() {
                                        if other != *peer_id {
                                            outgoing.push((other, 0, data.clone()));
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    SecureEvent::Disconnected(peer_id) => {
                        println!("[-] Player {} left", peer_id);
                        players.remove(peer_id);

                        let leave_evt = build_event(EVT_PLAYER_LEAVE, &peer_id.to_le_bytes());
                        for &other in players.keys() {
                            outgoing.push((other, 0, leave_evt.clone()));
                        }
                    }
                }
            }

            // Send periodic full snapshots (every 1 second as fallback)
            if last_snapshot.elapsed() > std::time::Duration::from_secs(1) && !players.is_empty() {
                tick += 1;
                let snapshot = build_snapshot(tick, &players);
                for &id in players.keys() {
                    outgoing.push((id, 0, snapshot.clone()));
                }
                last_snapshot = std::time::Instant::now();
                if tick % 10 == 0 {
                    println!("[tick {}] {} players connected", tick, players.len());
                }
            }

            for (peer_id, channel, data) in outgoing {
                let _ = server.send(peer_id, channel, data).await;
            }
        }
    }
}
