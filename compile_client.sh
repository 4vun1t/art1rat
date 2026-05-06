#!/bin/bash
export CARGO_TARGET_ARMV7_LINUX_ANDROID_LINKER=armv7a-linux-androideabi21-clang
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=aarch64-linux-android21-clang
cd artirat-client
archs = " aarch64-linux-android x86_64-pc-windows-gnu i686-pc-windows-gnu x86_64-unknown-linux-musl i686-unknown-linux-musl x86_64-unknown-linux-gnu i686-unknown-linux-gnu aarch64-apple-darwin x86_64-apple-darwin " 
for $arch in $archs
do
    echo -e "[INFO] Building for $arch"
    cargo build --quiet --offline --release --lib --target $arch
    cargo build --quiet --offline --release --target $arch
    echo -e "[INFO] Done building for $arch"
done
