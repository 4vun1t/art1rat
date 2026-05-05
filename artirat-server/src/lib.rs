// src/main.rs (or lib.rs)

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, RwLock};

use arti_client::{TorClient, TorClientConfig};
use tor_rtcompat::PreferredRuntime;

use futures_util::StreamExt;

pub struct ServerConfig {
    pub data_dir: PathBuf,
    pub nickname: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", content = "data")]
enum Message {
    Hello { name: String },
    Chat { text: String },
    Ping,
    Pong,
    ServerNotice { text: String },
    Error { text: String },
}

#[derive(Clone)]
struct ClientInfo {
    id: u64,
    peer: String,
    last_seen: u64,
    tx: mpsc::UnboundedSender<Message>,
}

type Clients = Arc<RwLock<HashMap<u64, ClientInfo>>>;

pub async fn run_server(cfg: ServerConfig) -> Result<()> {
    let mut tor_cfg = TorClientConfig::default();
    tor_cfg.storage.state_dir = Some(cfg.data_dir.clone());

    let tor = TorClient::create_bootstrapped(tor_cfg).await?;

    let (onion_addr, mut incoming) = create_onion_service(&tor, &cfg).await?;

    println!("Onion service ready: {}", onion_addr);

    let clients: Clients = Arc::new(RwLock::new(HashMap::new()));

    // Spawn host/admin shell
    {
        let clients = clients.clone();
        tokio::spawn(async move {
            if let Err(e) = host_shell(clients).await {
                eprintln!("host shell error: {e}");
            }
        });
    }

    let mut next_id: u64 = 1;

    while let Some(stream) = incoming.next().await {
        match stream {
            Ok(s) => {
                let id = next_id;
                next_id += 1;

                let clients = clients.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_client(id, s, clients).await {
                        eprintln!("client {id} error: {e}");
                    }
                });
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }

    Ok(())
}

// ---- Replace with actual tor-hsservice usage ----
type Incoming = futures_util::stream::BoxStream<'static, Result<TcpStream>>;

async fn create_onion_service(
    _tor: &TorClient<PreferredRuntime>,
    _cfg: &ServerConfig,
) -> Result<(String, Incoming)> {
    let onion = "exampleonionaddress.onion:12345".to_string();
    let empty = futures_util::stream::empty::<Result<TcpStream>>().boxed();
    Ok((onion, empty))
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn handle_client(id: u64, stream: TcpStream, clients: Clients) -> Result<()> {
    let peer = stream
        .peer_addr()
        .map(|p| p.to_string())
        .unwrap_or_else(|_| "unknown".into());

    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r).lines();

    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    // Register client
    {
        let mut map = clients.write().await;
        map.insert(
            id,
            ClientInfo {
                id,
                peer: peer.clone(),
                last_seen: now_ts(),
                tx: tx.clone(),
            },
        );
    }

    w.write_all(b"Welcome. Send JSON messages.\n").await?;

    // Writer task: sends server-initiated messages to the client
    let mut writer = w;
    let writer_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Ok(line) = serde_json::to_string(&msg) {
                if writer.write_all(line.as_bytes()).await.is_err() {
                    break;
                }
                if writer.write_all(b"\n").await.is_err() {
                    break;
                }
            }
        }
    });

    // Reader loop
    while let Some(line) = reader.next_line().await? {
        // update last_seen
        {
            let mut map = clients.write().await;
            if let Some(c) = map.get_mut(&id) {
                c.last_seen = now_ts();
            }
        }

        let msg: Message = match serde_json::from_str(&line) {
            Ok(m) => m,
            Err(_) => {
                let _ = tx.send(Message::Error {
                    text: "invalid json".into(),
                });
                continue;
            }
        };

        match msg {
            Message::Hello { name } => {
                let _ = tx.send(Message::Chat {
                    text: format!("hello, {name}!"),
                });
            }
            Message::Chat { text } => {
                // echo example
                let _ = tx.send(Message::Chat { text });
            }
            Message::Ping => {
                let _ = tx.send(Message::Pong);
            }
            Message::Pong => {}
            Message::ServerNotice { .. } | Message::Error { .. } => {}
        }
    }

    // Cleanup on disconnect
    {
        let mut map = clients.write().await;
        map.remove(&id);
    }

    writer_task.abort();

    Ok(())
}

/// Admin/host shell (server-side only, no remote command execution)
async fn host_shell(clients: Clients) -> Result<()> {
    let stdin = io::stdin();
    let mut lines = BufReader::new(stdin).lines();

    println!("Host shell ready. Type 'help'.");

    while let Some(line) = lines.next_line().await? {
        let mut parts = line.trim().split_whitespace();
        let cmd = parts.next().unwrap_or("");

        match cmd {
            "help" => {
                println!("Commands:");
                println!("  list");
                println!("  select <id>");
                println!("  quit");
            }
            "list" => {
                let map = clients.read().await;
                if map.is_empty() {
                    println!("No clients connected.");
                } else {
                    for (id, c) in map.iter() {
                        println!(
                            "#{id}  peer={}  last_seen={}",
                            c.peer, c.last_seen
                        );
                    }
                }
            }
            "select" => {
                let id: u64 = match parts.next().and_then(|s| s.parse().ok()) {
                    Some(v) => v,
                    None => {
                        println!("usage: select <id>");
                        continue;
                    }
                };
                let map = clients.read().await;
                if let Some(c) = map.get(&id) {
                    println!(
                        "Client #{id}\n  peer={}\n  last_seen={}",
                        c.peer, c.last_seen
                    );
                    println!("(info-only; no remote shell)");
                } else {
                    println!("Client #{id} not found");
                }
            }
            "quit" | "exit" => break,
            "" => {}
            _ => println!("Unknown command. Type 'help'."),
        }
    }

    Ok(())
}

