use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};

use arti_client::config::{TorClientConfigBuilder, CfgPath};
use arti_client::TorClient;
use tor_rtcompat::PreferredRuntime;

use tor_hsservice::OnionServiceConfig;

use futures_util::StreamExt;
use tokio::io::copy_bidirectional;

use std::fs;

#[derive(Clone)]
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

async fn local_server(clients: Clients) -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:1337").await?;
    println!("[*] Local listener on 127.0.0.1:1337");

    let mut next_id: u64 = 1;

    loop {
        let (stream, addr) = listener.accept().await?;
        println!("[*] Incoming connection from {}", addr);

        let id = next_id;
        next_id += 1;

        let clients_clone = clients.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_client(id, stream, clients_clone).await {
                eprintln!("client {id} error: {e}");
            }
        });
    }
}

pub async fn run_server(cfg: ServerConfig) -> Result<()> {
    let clients: Clients = Arc::new(RwLock::new(HashMap::new()));

    // Local TCP listener
    {
        let clients = clients.clone();
        tokio::spawn(async move {
            if let Err(e) = local_server(clients).await {
                eprintln!("local server error: {e}");
            }
        });
    }

    // Host shell
    {
        let clients = clients.clone();
        tokio::spawn(async move {
            if let Err(e) = host_shell(clients).await {
                eprintln!("host shell error: {e}");
            }
        });
    }

    // --- Tor setup ---
    let mut tor_cfg_builder = TorClientConfigBuilder::default();
    tor_cfg_builder
        .storage()
        .state_dir(CfgPath::new_literal("/etc/artirat_config"));

    let tor_cfg = tor_cfg_builder.build()?;
    let tor = TorClient::create_bootstrapped(tor_cfg).await?;

    let onion_addr = create_onion_service(&tor, &cfg).await?;
    println!("[*] Onion service ready: {}", onion_addr);

    futures_util::future::pending::<()>().await;
    Ok(())
}

async fn create_onion_service(
    tor: &TorClient<PreferredRuntime>,
    cfg: &ServerConfig,
) -> Result<String> {
    // 🔑 Persist identity → stable onion address
    let hs_config = OnionServiceConfig::builder()
        .nickname(cfg.nickname.clone())
        .key_dir(cfg.data_dir.join("onion_keys"))
        .build()?;

    let service = tor.launch_onion_service(hs_config).await?;

    let onion = service.onion_name()?.to_string();

    // Save hostname for client
    let hostname_path = PathBuf::from("../artirat-client/config/hostname");
    fs::create_dir_all(hostname_path.parent().unwrap())?;
    fs::write(&hostname_path, &onion)?;

    println!("[*] Onion service created: {}", onion);

    // 🔁 Accept incoming onion connections
    let mut incoming = service.accept();

    tokio::spawn(async move {
        while let Some(stream_res) = incoming.next().await {
            match stream_res {
                Ok(mut onion_stream) => {
                    println!("[*] Incoming onion connection");

                    tokio::spawn(async move {
                        match TcpStream::connect("127.0.0.1:1337").await {
                            Ok(mut local) => {
                                if let Err(e) =
                                    copy_bidirectional(&mut onion_stream, &mut local).await
                                {
                                    eprintln!("proxy error: {e}");
                                }
                            }
                            Err(e) => {
                                eprintln!("local connect failed: {e}");
                            }
                        }
                    });
                }
                Err(e) => {
                    eprintln!("onion accept error: {e}");
                }
            }
        }
    });

    Ok(onion)
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

    while let Some(line) = reader.next_line().await? {
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
                let _ = tx.send(Message::Chat { text });
            }
            Message::Ping => {
                let _ = tx.send(Message::Pong);
            }
            _ => {}
        }
    }

    {
        let mut map = clients.write().await;
        map.remove(&id);
    }

    writer_task.abort();
    Ok(())
}

pub async fn host_shell(clients: Clients) -> Result<()> {
    let stdin = io::stdin();
    let mut lines = BufReader::new(stdin).lines();

    println!("Host shell ready. Type 'help'.");

    while let Some(line) = lines.next_line().await? {
        let mut parts = line.trim().split_whitespace();
        let cmd = parts.next().unwrap_or("");

        match cmd {
            "help" => {
                println!("Commands: list | select <id> | quit");
            }
            "list" => {
                let map = clients.read().await;
                for (id, c) in map.iter() {
                    println!("#{id} peer={} last_seen={}", c.peer, c.last_seen);
                }
            }
            "select" => {
                println!("(selection logic not wired yet)");
            }
            "quit" | "exit" => break,
            _ => println!("Unknown command"),
        }
    }

    Ok(())
}