# Artirat

A command-and-control (C2) framework with a Python-based C2 server and a Rust-based implant client. Communication occurs over Tor hidden services (onion routing) with an optional XOR obfuscation layer for defense-in-depth.

> **Disclaimer**: This tool is for authorized security testing and research only. Unauthorized use is illegal.

## Features

### C2 Server (`server.py`)
- Multi-client management with concurrent reverse shell sessions
- Interactive C2 console with tab completion for commands and file paths
- Per-client working directories, hostname tracking, and screenshot counters
- Stream message hiding toggle (`hide_stream` / `show_stream`)
- Autorun commands — execute predefined commands automatically when a client connects
- Client session backgrounding (suspend a session without disconnecting)
- `multi_run` — broadcast a command to all connected clients simultaneously
- Cross-build toolchain management for multiple targets (Windows, Linux, Android)
- Automatic Tor hidden service setup via stem (ephemeral and persistent)
- Client config generation (`write_config`) that parses torrc and writes `.onion` addresses
- Non-interactive mode (`-x`/`--execute`) for scripting builds and config

### Implant Client (`artirat-client/`)
The Rust-based implant supports Windows, Linux, macOS, and Android targets.

| Capability | Details |
|---|---|
| **Reverse shell** | Text-based protocol over Tor, prompt-driven interaction, semicolon command chaining |
| **File upload/download** | Chunked base64 transfer with start/chunk/end markers |
| **Screenshot capture** | Desktop capture (PNG), Android via `screencap` |
| **Keylogging** | Windows (`GetAsyncKeyState`) and Linux (`/dev/input/event*`), auto-flush every 60s |
| **Port scanning** | TCP, UDP, SCTP — concurrent connections, fast mode for common ports |
| **System info** | OS version, CPU model/cores, memory, uptime, private IPs, mounted filesystems |
| **UAC bypass** | `uac` (slui registry abuse) and `uac2` (CMSTP INF auto-elevation) — Windows only |
| **Persistence** | Windows: Run key, scheduled task, service, CLSID, VBS. Linux: cron, systemd, bashrc, XDG autostart |
| **Privilege escalation** | `self_uac` elevates current process via CMSTP |
| **Shellcode injection** | Send raw shellcode from server to inject into implant process |
| **AMSI bypass** | Patches `AmsiScanBuffer` in memory (xor eax, eax; ret) — Windows |
| **Sandbox detection** | Debugger check, analysis process scan, env var heuristics, sleep acceleration detection, low-resource checks (CPU ≤2, RAM <2GB, disk <60GB) |
| **Obfuscated sleep** | Randomized micro-sleeps with junk operations to evade sandbox timing analysis |
| **Self-update** | Swaps binary from `dist/` directory, spawns new process, exits old one |
| **Multi-onion redundancy** | Connect to multiple fallback C2 onion addresses in parallel |
| **Build modes** | EXE, shared library (DLL/SO), static library, shellcode (raw `.bin`) |

## Tor Configuration

Artirat requires Tor with the **ControlPort** and **CookieAuthentication** enabled. The server uses `stem` to communicate with the Tor controller for hidden service setup.

Example `torrc` entries:

```
ControlPort 127.0.0.1:9051
CookieAuthentication 1
```

The project includes a `torrc` file with these settings. On Termux, the system torrc is at `/data/data/com.termux/files/usr/etc/tor/torrc`. On desktop Linux, it is typically `/etc/tor/torrc`.

Use the `configure_tor` command from the C2 menu to append hidden service configuration to your torrc:

```
c2> configure_tor 1337
```

This writes:
```
HiddenServiceDir /var/lib/tor/artirat-server
HiddenServicePort 1337 127.0.0.1:1337
```

After configuring, restart Tor and run `write_config` to generate the client hostname file.

## Usage

### Quick Start

```bash
# 1. Ensure Tor is running with ControlPort and CookieAuthentication
# 2. Start the C2 server
python3 server.py

# 3. From the C2 menu, configure Tor and write client config
c2> configure_tor
c2> write_config

# 4. Build the client for a target platform
c2> build linux
c2> build windows
c2> build android

# 5. Deploy the built binary on the target machine
# 6. When a client connects, select it for an interactive session
c2> list
c2> select 1
```

### Server Commands

| Command | Description |
|---|---|
| `list` | List all connected clients by ID |
| `select <id>` | Enter an interactive session with a client |
| `multi_run <command>` | Execute a command on all connected clients simultaneously |
| `build <target>` | Cross-compile the implant for the specified target |
| `build all` | Build for all EXE targets |
| `configure_tor [port]` | Append hidden service config to torrc (default port 1337) |
| `write_config` | Parse torrc and write `.onion:port` to client config |
| `hide_stream` | Suppress background stream (autorun/keylogger) messages |
| `show_stream` | Show background stream messages |
| `autorun_commands <cmds>` | Set semicolon-separated commands to autorun on new clients |
| `exit` | Shut down the C2 server |

#### Build targets

`windows`, `linux`, `linux32`, `windows32`, `android`, `dll-windows`, `dll-linux`, `windows-shellcode`, `windows32-shellcode`, `linux-shellcode`, `linux32-shellcode`

Flags: `--verbose`, `--static`, `--upx`

### Interactive Session Commands

Once you `select <id>`, you are in an interactive session with the client:

| Command | Description |
|---|---|
| `help`, `/h`, `/?` | Show help menu |
| `cd <dir>` | Change working directory on the target |
| `screenshot [filename]` | Capture desktop screenshot |
| `upload <filename>` | Upload a file from the target to the server |
| `download <filename>` | Download a file from the server to the target |
| `uac <exe_path>` | UAC bypass via slui (Windows) |
| `uac2 <exe_path>` | UAC bypass via CMSTP (Windows) |
| `persist` | Install persistence mechanism |
| `check_elevated` | Check if running as admin (Windows) |
| `self_uac` | Elevate current process via CMSTP (Windows) |
| `sandbox_detect` | Run sandbox/environment checks |
| `portscan <tcp\|udp\|sctp> <host>` | Scan ports on a remote host |
| `keylogger_start` | Start keylogger (Windows/Linux) |
| `keylogger_stop` | Stop keylogger |
| `shellcode <filepath>` | Inject shellcode from a local file |
| `update_implant` | Self-update from dist/ directory |
| `sysinfo` | Gather system information |
| `background` | Suspend session and return to C2 menu |
| `exit`, `quit` | End the session |
| *anything else* | Executed as a shell command on the target |

## Command-Line Options

```
python3 server.py [-w] [-i] [-a autorun_cmds] [-x command]

-w, --write-hostname     Parse torrc and write hostname:port to client config
-i, --interactive        Drop into C2 shell after executing -x commands
-a, --autorun-commands   Comma-separated commands to autorun on each connection
-x, --execute <command>  Run a command non-interactively (build, write_config, configure_tor)
```

Examples:
```bash
python3 server.py -x 'build linux --verbose'
python3 server.py -x 'write_config; build all'
python3 server.py -x 'build windows --upx' -i
```

## Post-Build Obfuscation

`build_obfuscate.py` strips PE Rich Headers, corrupts timestamps, appends junk data, and modifies ELF section headers to evade signature-based detection. It backs up the original with a `.bak` extension.

```bash
python3 build_obfuscate.py dist/x86_64-pc-windows-gnu/artirat_client.exe
python3 build_obfuscate.py dist/x86_64-unknown-linux-gnu/artirat_client --dry-run
```

## Project Structure

```
art1rat/
├── server.py              # C2 server and build tool
├── cryptoutil.py           # Server-side XOR obfuscation
├── build_obfuscate.py      # Post-build PE/ELF obfuscation
├── torrc                   # Tor configuration template
├── .autorun_commands       # Default autorun commands
├── artirat-client/         # Rust implant source
│   ├── src/                # Client source code
│   ├── config/             # Onion hostname config (generated)
│   ├── external/           # linpeas.sh, winPEAS.bat
│   └── Cargo.toml
└── dist/                   # Build output directory
```
