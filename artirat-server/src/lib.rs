use tor_hsservice::{HsServiceBuilder, OnionServiceConfig};
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::fs;

pub async fn run_hidden_service(cfg: &ServerConfig) -> Result<()> {
    // --- Tor config with persistent state ---
    let mut tor_cfg_builder = TorClientConfigBuilder::default();

    tor_cfg_builder
        .storage()
        .state_dir(CfgPath::new_literal(cfg.data_dir.clone()));

    let tor_cfg = tor_cfg_builder.build()?;
    let tor = TorClient::create_bootstrapped(tor_cfg).await?;

    // --- Hidden service config ---
    let hs_config = OnionServiceConfig::builder()
        .nickname(cfg.nickname.clone())
        .build()?;

    let service = HsServiceBuilder::new(tor.clone())
        .config(hs_config)
        .build()?;

    let onion = service.onion_name()?.to_string();

    println!("[*] Onion service: {}", onion);

    // --- Persist hostname to client config file ---
    let hostname_path = PathBuf::from("../artirat-client/config/hostname");
    fs::create_dir_all(hostname_path.parent().unwrap())?;
    fs::write(&hostname_path, &onion)?;

    println!("[*] Wrote hostname to {:?}", hostname_path);

    // --- Backend listener ---
    let listener = TcpListener::bind("127.0.0.1:1337").await?;

    println!("[*] Listening locally on 127.0.0.1:1337");

    // Accept connections
    tokio::spawn(async move {
        loop {
            let (mut socket, addr) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("accept error: {e}");
                    continue;
                }
            };

            println!("[*] Incoming connection from {}", addr);

            tokio::spawn(async move {
                let mut buf = [0u8; 1024];

                loop {
                    let n = match socket.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(_) => break,
                    };

                    // simple echo (replace with safe protocol logic)
                    if socket.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    // --- Launch hidden service ---
    service.launch().await?;

    Ok(())
}