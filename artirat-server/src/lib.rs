use tor_hsservice::{ *};
use arti_client::{*}
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

pub async fn interactive_client(mut stream: TcpStream) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.split();

    let mut socket_reader = BufReader::new(reader);
    let mut stdin_reader = BufReader::new(io::stdin());

    let mut stdin_buf = String::new();
    let mut socket_buf = String::new();

    loop {
        tokio::select! {

            // ---- READ FROM KEYBOARD ----
            n = stdin_reader.read_line(&mut stdin_buf) => {
                if n? == 0 {
                    break;
                }

                writer.write_all(stdin_buf.as_bytes()).await?;
                writer.flush().await?;

                stdin_buf.clear();
            }

            // ---- READ FROM SOCKET ----
            n = socket_reader.read_line(&mut socket_buf) => {
                if n? == 0 {
                    break;
                }

                print!("{}", socket_buf);
                socket_buf.clear();
            }
        }
    }

    Ok(())
}
pub async fn run_hidden_service() -> Result<()> {
    let state_dir = PathBuf::from("./config/tor");
    fs::create_dir_all(&state_dir)?;

    // ---- Tor client ----
    let mut tor_cfg = TorClientConfigBuilder::default();
    tor_cfg.storage().state_dir(CfgPath::new_literal(
        state_dir.to_str().unwrap(),
    ));

    let tor = TorClient::create_bootstrapped(tor_cfg.build()?).await?;

    // ---- Onion service config ----
    let hs_config = OnionServiceConfig::builder()
        .build()?;

    // ---- Build service ----
    let service = OnionService::builder()
        .config(hs_config)
        .state_dir(CfgPath::new_literal(state_dir.to_str().unwrap()))
        .build()?;

    // ---- Launch service (CORRECT) ----
    let (running, rend_stream) = service
        .launch(
            tor.runtime().clone(),
            tor.netdir_provider(),
            tor.hs_circ_pool(),
            tor.path_resolver(),
        )?
        .ok_or_else(|| anyhow!("Service disabled"))?;

    println!(
        "[+] Onion address: {:?}",
        running.onion_address()
    );

     Convert RendRequest → StreamRequest ----
    Ok(())
}