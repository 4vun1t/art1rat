use std::path::Path;

use rand::RngCore;
use sha3::Digest;

fn main() {
    let cargo_manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let manifest_path = Path::new(&cargo_manifest);

    let client_config = manifest_path.parent().unwrap().join("artirat-client").join("config");
    let server_config = manifest_path.join("config");

    let hostname_path = client_config.join("hostname");
    let seed_path = server_config.join("onion_seed");

    std::fs::create_dir_all(&client_config).unwrap();
    std::fs::create_dir_all(&server_config).unwrap();

    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    seed[0] &= 248;
    seed[31] &= 127;
    seed[31] |= 64;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let pubkey_bytes = verifying_key.to_bytes();
    let version: u8 = 0x03;

    let mut hasher = sha3::Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(&pubkey_bytes);
    hasher.update(&[version]);
    let hash = hasher.finalize();

    let mut address_bytes = Vec::with_capacity(35);
    address_bytes.extend_from_slice(&pubkey_bytes);
    address_bytes.extend_from_slice(&hash[..2]);
    address_bytes.push(version);

    let mut encoded = data_encoding::BASE32_NOPAD.encode(&address_bytes);
    encoded.make_ascii_lowercase();
    let hostname = format!("{}.onion", encoded);

    std::fs::write(&hostname_path, &hostname).unwrap();
    std::fs::write(server_config.join("hostname"), &hostname).unwrap();

    let seed_bytes = signing_key.to_bytes();
    std::fs::write(&seed_path, &seed_bytes).unwrap();

    println!("cargo:warning=Generated onion address: {}", hostname);
    println!("cargo:rerun-if-changed=build.rs");
}
