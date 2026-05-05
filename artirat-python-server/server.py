import socket
import os
import struct

HOST = "0.0.0.0"
PORT = 1337
BUFFER_SIZE = 4096


def recv_all(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(min(BUFFER_SIZE, size - len(data)))
        if not chunk:
            return None
        data += chunk
    return data


def handle_client(conn, addr):
    print(f"[+] Connection from {addr}")

    try:
        while True:
            header = conn.recv(1024)
            if not header:
                break

            header = header.decode().strip()
            print(f"[>] Received command: {header}")

            # ---- FILE RECEIVE ----
            if header.startswith("file ") or header.startswith("upload "):
                filename = header.split(" ", 1)[1]

                # receive file size (8 bytes)
                raw_size = recv_all(conn, 8)
                if not raw_size:
                    break
                filesize = struct.unpack(">Q", raw_size)[0]

                print(f"[+] Receiving file: {filename} ({filesize} bytes)")

                with open(filename, "wb") as f:
                    remaining = filesize
                    while remaining > 0:
                        chunk = conn.recv(min(BUFFER_SIZE, remaining))
                        if not chunk:
                            break
                        f.write(chunk)
                        remaining -= len(chunk)

                print(f"[+] Saved file: {filename}")

            # ---- FILE SEND ----
            elif header.startswith("download "):
                filename = header.split(" ", 1)[1]

                if not os.path.exists(filename):
                    conn.sendall(b"ERR File not found\n")
                    continue

                filesize = os.path.getsize(filename)

                conn.sendall(b"OK\n")
                conn.sendall(struct.pack(">Q", filesize))

                print(f"[+] Sending file: {filename}")

                with open(filename, "rb") as f:
                    while chunk := f.read(BUFFER_SIZE):
                        conn.sendall(chunk)

            # ---- NORMAL COMMAND ----
            else:
                print(f"[shell] {header}")
                conn.sendall(f"echo: {header}\n".encode())

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
