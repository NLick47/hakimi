#!/usr/bin/env python3
"""WebSocket client that talks to the local hakimi proxy (HTTP absolute-form upgrade)."""
import base64
import os
import socket
import struct
import sys

proxy_port = int(sys.argv[1]) if len(sys.argv) > 1 else 18473
target = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
target_port = int(sys.argv[3]) if len(sys.argv) > 3 else 18080
sock = socket.create_connection(("127.0.0.1", proxy_port), 10)
key = base64.b64encode(os.urandom(16)).decode()
request = (
    f"GET http://{target}:{target_port}/ws HTTP/1.1\r\n"
    f"Host: {target}:{target_port}\r\n"
    "Connection: Upgrade\r\n"
    "Upgrade: websocket\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n\r\n"
).encode()
sock.sendall(request)
response = b""
while b"\r\n\r\n" not in response:
    chunk = sock.recv(4096)
    if not chunk:
        break
    response += chunk
if b" 101 " not in response.split(b"\r\n", 1)[0]:
    print("handshake failed:", response[:300])
    sys.exit(1)
payload = b"ping"
mask = os.urandom(4)
masked = bytes(payload[i] ^ mask[i % 4] for i in range(len(payload)))
sock.sendall(bytes([0x81, 0x80 | len(payload)]) + mask + masked)
header = sock.recv(2)
if len(header) < 2:
    print("no websocket frame")
    sys.exit(1)
length = header[1] & 0x7F
if length == 126:
    length = struct.unpack(">H", sock.recv(2))[0]
data = b""
while len(data) < length:
    data += sock.recv(length - len(data))
print("status=101 echo=" + data.decode())
assert data == b"ping"
