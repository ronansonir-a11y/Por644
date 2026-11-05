#!/usr/bin/env python3
"""Synthetic REST/WebSocket/UDP backend for preservation experiments.

This is NOT a PSN service, a real game's protocol, an authentication server,
TLS, or a means to connect an unmodified commercial game. Adapt only for your
own offline client or a documented, authorized protocol. Loopback by default.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import ipaddress
import json
import struct
import sys
from dataclasses import dataclass

MAX_BODY = 4096
MAX_UDP = 1024
PRIVATE_V4 = tuple(ipaddress.ip_network(n) for n in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def allowed_address(address: str) -> bool:
    try:
        addr = ipaddress.ip_address(address)
        return addr.version == 4 and any(addr in network for network in PRIVATE_V4)
    except ValueError:
        return False


def check_bind(address: str, allow_lan: bool) -> None:
    if not allowed_address(address):
        raise ValueError("Bind must be a specific IPv4 loopback or RFC1918 address; no wildcard/public address")
    if not ipaddress.ip_address(address).is_loopback and not allow_lan:
        raise ValueError("LAN binding requires --allow-lan; use an isolated trusted network")


@dataclass
class State:
    """One anonymous local player; no persistence/auth; NOT a production server."""
    x: int = 0
    y: int = 0
    last_seq: int = -1
    tick: int = 0

    def snapshot(self) -> dict:
        return {"x": self.x, "y": self.y, "last_seq": self.last_seq, "tick": self.tick}

    def apply(self, payload) -> dict:
        if not isinstance(payload, dict) or set(payload) != {"type", "seq", "dx", "dy"} or payload.get("type") != "move":
            return {"ok": False, "error": "expected move with type, seq, dx, dy"}
        seq, dx, dy = payload["seq"], payload["dx"], payload["dy"]
        # bool is a subclass of int: use exact types for protocol validation.
        if any(type(v) is not int for v in (seq, dx, dy)):
            return {"ok": False, "error": "seq/dx/dy must be integers"}
        if not 0 <= seq <= 2**31 - 1 or seq <= self.last_seq:
            return {"ok": False, "error": "sequence must be newer and within range"}
        if dx not in (-1, 0, 1) or dy not in (-1, 0, 1):
            return {"ok": False, "error": "movement exceeds one cell per input"}
        self.x = max(-100, min(100, self.x + dx))
        self.y = max(-100, min(100, self.y + dy))
        self.last_seq = seq
        self.tick += 1
        return {"ok": True, "state": self.snapshot()}


def json_bytes(value) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")


async def respond(writer: asyncio.StreamWriter, status: int, obj) -> None:
    reasons = {200: "OK", 400: "Bad Request", 403: "Forbidden", 404: "Not Found", 413: "Payload Too Large"}
    body = json_bytes(obj)
    headers = (f"HTTP/1.1 {status} {reasons.get(status, 'Error')}\r\n"
               f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
               "Cache-Control: no-store\r\nConnection: close\r\n\r\n").encode("ascii")
    writer.write(headers + body)
    await writer.drain()


def encode_frame(opcode: int, payload: bytes) -> bytes:
    size = len(payload)
    if size < 126:
        header = bytes((0x80 | opcode, size))
    elif size <= 65535:
        header = bytes((0x80 | opcode, 126)) + struct.pack("!H", size)
    else:
        header = bytes((0x80 | opcode, 127)) + struct.pack("!Q", size)
    return header + payload


async def websocket(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, state: State) -> None:
    # Deliberately small RFC 6455 subset: masked, final text/control frames only.
    while True:
        head = await asyncio.wait_for(reader.readexactly(2), 30)
        fin, rsv, opcode = bool(head[0] & 0x80), head[0] & 0x70, head[0] & 0x0F
        masked, size = bool(head[1] & 0x80), head[1] & 0x7F
        if not fin or rsv or not masked or opcode not in (1, 8, 9, 10):
            return
        if size == 126:
            size = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), 5))[0]
        elif size == 127:
            size = struct.unpack("!Q", await asyncio.wait_for(reader.readexactly(8), 5))[0]
        if size > MAX_BODY or (opcode >= 8 and size > 125):
            return
        key = await asyncio.wait_for(reader.readexactly(4), 5)
        wire = await asyncio.wait_for(reader.readexactly(size), 5)
        payload = bytes(b ^ key[i % 4] for i, b in enumerate(wire))
        if opcode == 8:
            writer.write(encode_frame(8, b""))
            await writer.drain()
            return
        if opcode == 9:
            writer.write(encode_frame(10, payload))
        elif opcode == 1:
            try:
                obj = json.loads(payload.decode("utf-8"))
                result = state.apply(obj)
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
                result = {"ok": False, "error": "invalid JSON"}
            writer.write(encode_frame(1, json_bytes(result)))
        await writer.drain()


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, state: State) -> None:
    peer = writer.get_extra_info("peername")
    try:
        if not peer or not allowed_address(peer[0]):
            await respond(writer, 403, {"ok": False, "error": "local peers only"})
            return
        raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        if len(raw) > 8192:
            await respond(writer, 413, {"ok": False, "error": "headers too large"})
            return
        lines = raw.decode("iso-8859-1").split("\r\n")
        request = lines[0].split(" ")
        if len(request) != 3 or request[2] != "HTTP/1.1":
            await respond(writer, 400, {"ok": False, "error": "expected HTTP/1.1"})
            return
        method, path, _ = request
        headers = {}
        for line in lines[1:]:
            if not line:
                continue
            if ":" not in line:
                await respond(writer, 400, {"ok": False, "error": "invalid header"})
                return
            key, value = line.split(":", 1)
            key = key.strip().lower()
            if not key or key in headers:
                await respond(writer, 400, {"ok": False, "error": "duplicate/invalid header"})
                return
            headers[key] = value.strip()
        # Avoid browser-origin requests, proxying, chunking and cross-site LAN requests.
        if "origin" in headers or "transfer-encoding" in headers:
            await respond(writer, 403, {"ok": False, "error": "browser origins/chunking not supported"})
            return
        if method == "GET" and path == "/ws" and headers.get("upgrade", "").lower() == "websocket":
            key = headers.get("sec-websocket-key", "")
            try:
                decoded = base64.b64decode(key, validate=True)
            except (ValueError, base64.binascii.Error):
                decoded = b""
            tokens = {s.strip().lower() for s in headers.get("connection", "").split(",")}
            if len(decoded) != 16 or headers.get("sec-websocket-version") != "13" or "upgrade" not in tokens:
                await respond(writer, 400, {"ok": False, "error": "invalid WebSocket handshake"})
                return
            accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()).decode("ascii")
            writer.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                          f"Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").encode("ascii"))
            await writer.drain()
            await websocket(reader, writer, state)
            return
        if method == "GET" and path == "/health":
            await respond(writer, 200, {"ok": True, "service": "synthetic-offline-demo"})
        elif method == "GET" and path == "/state":
            await respond(writer, 200, {"ok": True, "state": state.snapshot()})
        elif method == "POST" and path == "/input":
            try:
                size = int(headers.get("content-length", "-1"))
            except ValueError:
                size = -1
            if size < 0 or size > MAX_BODY:
                await respond(writer, 413, {"ok": False, "error": "invalid content length"})
                return
            if headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
                await respond(writer, 400, {"ok": False, "error": "application/json required"})
                return
            body = await asyncio.wait_for(reader.readexactly(size), 5)
            try:
                result = state.apply(json.loads(body.decode("utf-8")))
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
                result = {"ok": False, "error": "invalid JSON"}
            await respond(writer, 200 if result["ok"] else 400, result)
        else:
            await respond(writer, 404, {"ok": False, "error": "unknown synthetic endpoint"})
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError, ConnectionError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionError:
            pass


class LocalUDP(asyncio.DatagramProtocol):
    def __init__(self, state: State):
        self.state = state
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, peer):
        if not peer or not allowed_address(peer[0]) or not 0 < len(data) <= MAX_UDP:
            return
        try:
            result = self.state.apply(json.loads(data.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            result = {"ok": False, "error": "invalid JSON"}
        self.transport.sendto(json_bytes(result), peer)


async def start_services(bind: str, port: int, udp_port: int, allow_lan: bool = False):
    check_bind(bind, allow_lan)
    if not 0 <= port <= 65535 or not 0 <= udp_port <= 65535:
        raise ValueError("Ports must be 0..65535")
    state = State()
    server = await asyncio.start_server(lambda r, w: handle_client(r, w, state), bind, port, limit=8192)
    try:
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: LocalUDP(state), local_addr=(bind, udp_port))
    except Exception:
        server.close()
        await server.wait_closed()
        raise
    return server, transport, state


async def run(args):
    server, udp, _state = await start_services(args.bind, args.port, args.udp_port, args.allow_lan)
    tcp_port = server.sockets[0].getsockname()[1]
    udp_port = udp.get_extra_info("sockname")[1]
    print(f"Synthetic demo on {args.bind}: HTTP/WS TCP {tcp_port}, UDP {udp_port}", flush=True)
    print("No TLS/auth/persistence. Not compatible with a real PS4 game without an authorized adapter.", flush=True)
    try:
        async with server:
            await server.serve_forever()
    finally:
        udp.close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1", help="specific IPv4 address (default loopback)")
    parser.add_argument("--allow-lan", action="store_true", help="allow a specific RFC1918 address on an isolated LAN")
    parser.add_argument("--port", type=int, default=8765, help="HTTP/WebSocket TCP port; 0 selects a free port")
    parser.add_argument("--udp-port", type=int, default=8766, help="UDP port; 0 selects a free port")
    args = parser.parse_args(argv)
    try:
        asyncio.run(run(args))
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
