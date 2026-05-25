# Artirat

A command-and-control (C2) framework with a Python-based C2 server and a Rust-based implant client. Communication occurs over Tor hidden services (onion routing).

## Components

- **server.py** — Python C2 server that listens for reverse shell connections and provides an interactive C2 console with multi-client management.
- **artirat-client/** — Rust implant supporting Windows, Linux, macOS, and Android targets with features including:
  - Reverse shell over Tor
  - File upload/download
  - Screenshot capture
  - Keylogging
  - Port scanning
  - UAC bypass (Windows)
  - Persistence mechanisms
  - Shellcode injection
  - Sandbox detection

## Usage

1. Configure Tor (see `torrc`)
2. Run `python3 server.py` to start the C2 server
3. Use `build <target>` to compile the client for your target platform
4. Deploy the client on the target machine
5. Use `select <id>` to enter an interactive session
