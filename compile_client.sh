#!/bin/bash
export CARGO_TARGET_ARMV7_LINUX_ANDROID_LINKER=armv7a-linux-androideabi21-clang
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=aarch64-linux-android21-clang
cd artirat-client
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
cargo build --target i686-pc-windows-gnu --lib --release
cargo build --target i686-pc-windows-gnu --release
cargo build --target x86_64-unknown-linux-gnu --release --lib
cargo build --target x86_64-unknown-linux-gnu --release
cargo build --target i686-unknown-linux-gnu --release --lib
cargo build --target i686-unknown-linux-gnu --release
