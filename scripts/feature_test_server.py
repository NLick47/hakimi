#!/usr/bin/env python3
"""Local HTTP/SSE/Range/WebSocket server used by the hakimi proxy feature tests."""
import base64
import hashlib
import socketserver
import struct
import time

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        lines = head.decode("latin1").split("\r\n")
        method, target, _version = lines[0].split(" ", 2)
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name.strip().lower()] = value.strip()

        if target.endswith("/ws"):
            key = headers.get("sec-websocket-key", "")
            accept = base64.b64encode(
                hashlib.sha1((key + GUID).encode()).digest()
            ).decode()
            self.request.sendall(
                (
                    "HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
                ).encode()
            )
            header = self.request.recv(2)
            if len(header) < 2:
                return
            length = header[1] & 0x7F
            if length == 126:
                length = struct.unpack(">H", self.request.recv(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self.request.recv(8))[0]
            mask = self.request.recv(4) if header[1] & 0x80 else b""
            payload = b""
            while len(payload) < length:
                chunk = self.request.recv(length - len(payload))
                if not chunk:
                    return
                payload += chunk
            if mask:
                payload = bytes(payload[i] ^ mask[i % 4] for i in range(len(payload)))
            self.request.sendall(bytes([0x81, len(payload)]) + payload)
            return

        if target.endswith("/sse"):
            self.request.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/event-stream\r\n"
                b"Cache-Control: no-cache\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Connection: close\r\n\r\n"
            )
            for index in range(3):
                chunk = f"data: event-{index}\n\n".encode()
                self.request.sendall(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                time.sleep(0.4)
            self.request.sendall(b"0\r\n\r\n")
            return

        if target.endswith("/range"):
            if headers.get("range") == "bytes=0-3":
                body = b"0123"
                self.request.sendall(
                    b"HTTP/1.1 206 Partial Content\r\n"
                    b"Content-Range: bytes 0-3/10\r\n"
                    b"Content-Length: 4\r\n"
                    b"Connection: close\r\n\r\n" + body
                )
            else:
                body = b"0123456789"
                self.request.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n"
                    b"Connection: close\r\n\r\n" + body
                )
            return

        body = b"hello-through-proxy"
        self.request.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"Connection: close\r\n\r\n" + body
        )


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server(("127.0.0.1", 18080), Handler) as server:
        server.serve_forever()
