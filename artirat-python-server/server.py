import socket
import os
import base64
HOST = "0.0.0.0"
PORT = 1337
BUFFER_SIZE = 16384


def handle_client(conn, addr):
    print(f"[+] Connection from {addr}")

    try:
        buffer = b""

        while True:
            data = conn.recv(BUFFER_SIZE)
            if not data:
                break

            buffer += data

            # process line-based protocol
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                line = line.decode(errors="ignore").strip()

                if not line:
                    continue

                print(f"[>] {line}")

                # ---- FILE UPLOAD (Rust client style) ----
                if line.startswith("[file] "):
                    try:
                        _, filename, b64data = line.split(" ", 2)

                        filedata = base64.b64decode(b64data)

                        with open(filename, "wb") as f:
                            f.write(filedata)

                        print(f"[+] Saved file: {filename} ({len(filedata)} bytes)")
                        conn.sendall(f"[OK] uploaded {filename}\n".encode())

                    except Exception as e:
                        print(f"[!] Upload error: {e}")
                        conn.sendall(b"[ERR] upload failed\n")

                # ---- DOWNLOAD REQUEST ----
                elif line.startswith("download "):
                    filename = line.split(" ", 1)[1]

                    if not os.path.exists(filename):
                        conn.sendall(b"[ERR] file not found\n")
                        continue

                    try:
                        with open(filename, "rb") as f:
                            data = f.read()

                        b64 = base64.b64encode(data).decode()

                        response = f"[file] {os.path.basename(filename)} {b64}\n"
                        conn.sendall(response.encode())

                        print(f"[+] Sent file: {filename}")

                    except Exception as e:
                        print(f"[!] Download error: {e}")
                        conn.sendall(b"[ERR] download failed\n")

                # ---- NORMAL COMMAND ----
                else:
                    print(f"[shell] {line}")
                    conn.sendall(f"echo: {line}\n".encode())

    except Exception as e:
        print(f"[!] Error: {e}")

    finally:
        conn.close()
        print(f"[-] Disconnected {addr}")


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[+] Listening on {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            handle_client(conn, addr)


if __name__ == "__main__":
    main()