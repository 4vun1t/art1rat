#!/bin/bash
cd artirat-client
cargo build --lib --release --target armv7-linux-androideabi
cargo build --release --target armv7-linux-androideabi
cargo build --release --lib --target aarch64-linux-android
cargo build --release --target aarch64-linux-android
cargo build --target x86_64-pc-windows-gnu --lib --release
cargo build --target x86_64-pc-windows-gnu --release
cargo build --release --lib --target x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target i586-unknown-linux-musl --lib
cargo build --release --target i586-unknown-linux-musl
cargo build --lib --release --target aarch64-apple-darwin
cargo build --release --target aarch64-apple-darwin
cargo build --lib --release --target x86_64-apple-darwin
cargo build --release --target x86_64-apple-darwin

