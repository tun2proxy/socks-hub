#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import ipaddress
import os
import selectors
import socket
import socketserver
import struct
import subprocess
import threading
import time
from pathlib import Path
from typing import Iterator, Tuple

SOCKS_VERSION = 5
CMD_CONNECT = 1
CMD_UDP_ASSOCIATE = 3
ATYP_IPV4 = 1
ATYP_DOMAIN = 3
ATYP_IPV6 = 4
REP_SUCCEEDED = 0
REP_GENERAL_FAILURE = 1
REP_COMMAND_NOT_SUPPORTED = 7


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def socks_hub_binary() -> Path:
    override = os.environ.get("SOCKS_HUB_BIN")
    if override:
        return Path(override)
    return repo_root() / "target" / "debug" / "socks-hub"


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining > 0:
        data = sock.recv(remaining)
        if not data:
            raise ConnectionError("unexpected EOF")
        chunks.append(data)
        remaining -= len(data)
    return b"".join(chunks)


def encode_address(host: str, port: int) -> bytes:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        host_bytes = host.encode("utf-8")
        if len(host_bytes) > 255:
            raise ValueError("domain name too long")
        return bytes([ATYP_DOMAIN, len(host_bytes)]) + host_bytes + struct.pack("!H", port)

    if ip.version == 4:
        return bytes([ATYP_IPV4]) + ip.packed + struct.pack("!H", port)
    return bytes([ATYP_IPV6]) + ip.packed + struct.pack("!H", port)


def decode_address(sock: socket.socket) -> Tuple[str, int]:
    atyp = recv_exact(sock, 1)[0]
    return decode_address_by_type(sock, atyp)


def decode_address_by_type(sock: socket.socket, atyp: int) -> Tuple[str, int]:
    if atyp == ATYP_IPV4:
        host = socket.inet_ntop(socket.AF_INET, recv_exact(sock, 4))
    elif atyp == ATYP_DOMAIN:
        length = recv_exact(sock, 1)[0]
        host = recv_exact(sock, length).decode("utf-8")
    elif atyp == ATYP_IPV6:
        host = socket.inet_ntop(socket.AF_INET6, recv_exact(sock, 16))
    else:
        raise ValueError(f"unsupported atyp: {atyp}")
    port = struct.unpack("!H", recv_exact(sock, 2))[0]
    return host, port


def build_udp_datagram(dst: Tuple[str, int], payload: bytes) -> bytes:
    host, port = dst
    return b"\x00\x00\x00" + encode_address(host, port) + payload


def parse_udp_datagram(data: bytes) -> Tuple[Tuple[str, int], bytes]:
    if len(data) < 4:
        raise ValueError("udp packet too short")
    if data[0:2] != b"\x00\x00" or data[2] != 0:
        raise ValueError("invalid udp header")

    offset = 3
    atyp = data[offset]
    offset += 1
    if atyp == ATYP_IPV4:
        host = socket.inet_ntop(socket.AF_INET, data[offset : offset + 4])
        offset += 4
    elif atyp == ATYP_DOMAIN:
        length = data[offset]
        offset += 1
        host = data[offset : offset + length].decode("utf-8")
        offset += length
    elif atyp == ATYP_IPV6:
        host = socket.inet_ntop(socket.AF_INET6, data[offset : offset + 16])
        offset += 16
    else:
        raise ValueError(f"unsupported atyp: {atyp}")

    port = struct.unpack("!H", data[offset : offset + 2])[0]
    offset += 2
    return (host, port), data[offset:]


def socks5_handshake(sock: socket.socket) -> None:
    sock.sendall(b"\x05\x01\x00")
    reply = recv_exact(sock, 2)
    if reply != b"\x05\x00":
        raise RuntimeError(f"unexpected handshake reply: {reply!r}")


def socks5_connect(proxy_addr: Tuple[str, int], dst: Tuple[str, int], timeout: float = 5.0) -> socket.socket:
    sock = socket.create_connection(proxy_addr, timeout=timeout)
    socks5_handshake(sock)
    sock.sendall(b"\x05\x01\x00" + encode_address(*dst))
    reply = recv_exact(sock, 4)
    if reply[0] != SOCKS_VERSION or reply[1] != REP_SUCCEEDED:
        raise RuntimeError(f"connect failed with reply: {reply!r}")
    decode_address_by_type(sock, reply[3])
    return sock


def socks5_udp_associate(proxy_addr: Tuple[str, int], timeout: float = 5.0) -> tuple[socket.socket, socket.socket, Tuple[str, int]]:
    control = socket.create_connection(proxy_addr, timeout=timeout)
    socks5_handshake(control)

    control.sendall(b"\x05\x03\x00" + encode_address("0.0.0.0", 0))
    reply = recv_exact(control, 4)
    if reply[0] != SOCKS_VERSION or reply[1] != REP_SUCCEEDED:
        raise RuntimeError(f"udp associate failed with reply: {reply!r}")
    relay_addr = decode_address_by_type(control, reply[3])

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(timeout)
    return control, client, relay_addr


def tcp_smoke(proxy_addr: Tuple[str, int], dst_addr: Tuple[str, int]) -> bytes:
    sock = socks5_connect(proxy_addr, dst_addr)
    try:
        payload = b"tcp-smoke-through-middle-hop"
        sock.sendall(payload)
        received = recv_exact(sock, len(payload))
        if received != payload:
            raise RuntimeError(f"tcp smoke mismatch: {received!r}")
        return received
    finally:
        sock.close()


def udp_smoke(proxy_addr: Tuple[str, int], dst_addr: Tuple[str, int]) -> bytes:
    control, client, relay_addr = socks5_udp_associate(proxy_addr)
    try:
        payload = b"udp-smoke-through-middle-hop"
        packet = build_udp_datagram(dst_addr, payload)
        client.sendto(packet, relay_addr)
        response, _ = client.recvfrom(65535)
        src, data = parse_udp_datagram(response)
        if src != dst_addr:
            raise RuntimeError(f"unexpected udp response source: {src!r}")
        if data != payload:
            raise RuntimeError(f"udp smoke mismatch: {data!r}")
        return data
    finally:
        control.close()
        client.close()


class ReusableThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ReusableThreadingUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True


class TcpEchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        while True:
            data = self.request.recv(4096)
            if not data:
                return
            self.request.sendall(data)


class UdpEchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        sock.sendto(data, self.client_address)


class Socks5TcpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        sock: socket.socket = self.request
        sock.settimeout(5.0)

        version = recv_exact(sock, 1)[0]
        if version != SOCKS_VERSION:
            return
        method_count = recv_exact(sock, 1)[0]
        _methods = recv_exact(sock, method_count)
        sock.sendall(b"\x05\x00")

        header = recv_exact(sock, 4)
        if header[0] != SOCKS_VERSION:
            return
        cmd = header[1]
        if header[2] != 0:
            self.send_reply(sock, REP_GENERAL_FAILURE, ("0.0.0.0", 0))
            return
        dst = decode_address_by_type(sock, header[3])

        if cmd == CMD_CONNECT:
            self.handle_connect(sock, dst)
        elif cmd == CMD_UDP_ASSOCIATE:
            self.handle_udp_associate(sock)
        else:
            self.send_reply(sock, REP_COMMAND_NOT_SUPPORTED, ("0.0.0.0", 0))

    def send_reply(self, sock: socket.socket, rep: int, bind_addr: Tuple[str, int]) -> None:
        sock.sendall(b"\x05" + bytes([rep]) + b"\x00" + encode_address(*bind_addr))

    def handle_connect(self, sock: socket.socket, dst: Tuple[str, int]) -> None:
        upstream = socket.create_connection(dst, timeout=5.0)
        try:
            self.send_reply(sock, REP_SUCCEEDED, upstream.getsockname()[:2])
            relay_bidirectional(sock, upstream)
        finally:
            upstream.close()

    def handle_udp_associate(self, sock: socket.socket) -> None:
        udp_addr = getattr(self.server, "udp_address", None)
        if udp_addr is None:
            self.send_reply(sock, REP_GENERAL_FAILURE, ("0.0.0.0", 0))
            return
        self.send_reply(sock, REP_SUCCEEDED, udp_addr)
        try:
            while True:
                try:
                    if not sock.recv(1):
                        return
                except socket.timeout:
                    continue
        except OSError:
            return


class Socks5UdpRelayHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        dst, payload = parse_udp_datagram(data)
        family = socket.AF_INET6 if ":" in dst[0] else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as upstream:
            upstream.settimeout(5.0)
            upstream.sendto(payload, dst)
            response, src_addr = upstream.recvfrom(65535)

        reply = build_udp_datagram(src_addr, response)
        sock.sendto(reply, self.client_address)


def relay_bidirectional(left: socket.socket, right: socket.socket) -> None:
    left.setblocking(False)
    right.setblocking(False)
    selector = selectors.DefaultSelector()
    selector.register(left, selectors.EVENT_READ, right)
    selector.register(right, selectors.EVENT_READ, left)

    try:
        while True:
            for key, _ in selector.select(timeout=0.5):
                source = key.fileobj
                target = key.data
                try:
                    data = source.recv(65535)
                except BlockingIOError:
                    continue
                if not data:
                    return
                target.sendall(data)
    finally:
        selector.close()
        with contextlib.suppress(OSError):
            left.shutdown(socket.SHUT_RDWR)
        with contextlib.suppress(OSError):
            right.shutdown(socket.SHUT_RDWR)


@contextlib.contextmanager
def running_server(server: socketserver.BaseServer) -> Iterator[socketserver.BaseServer]:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


@contextlib.contextmanager
def running_socks_hub(
    listen_port: int,
    remote_port: int,
    middle_port: int | None = None,
) -> Iterator[subprocess.Popen[str]]:
    binary = socks_hub_binary()
    if not binary.exists():
        raise FileNotFoundError(f"socks-hub binary not found at {binary}; build it first or set SOCKS_HUB_BIN")

    command = [
        str(binary),
        "-l",
        f"socks5://127.0.0.1:{listen_port}",
        "-r",
        f"socks5://127.0.0.1:{remote_port}",
    ]
    if middle_port is not None:
        command.extend([
            "-m",
            f"socks5://127.0.0.1:{middle_port}",
        ])
    env = os.environ.copy()
    env.setdefault("RUST_LOG", "warn")
    proc = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, text=True)
    try:
        wait_for_port(("127.0.0.1", listen_port), proc)
        yield proc
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5.0)


def wait_for_port(addr: Tuple[str, int], proc: subprocess.Popen[str], timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"socks-hub exited early with code {proc.returncode}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.25)
            if sock.connect_ex(addr) == 0:
                return
        time.sleep(0.05)
    raise TimeoutError(f"timed out waiting for {addr}")


def start_tcp_echo(port: int) -> socketserver.TCPServer:
    return ReusableThreadingTCPServer(("127.0.0.1", port), TcpEchoHandler)


def start_udp_echo(port: int) -> socketserver.UDPServer:
    return ReusableThreadingUDPServer(("127.0.0.1", port), UdpEchoHandler)


def start_socks_proxy(port: int) -> tuple[socketserver.TCPServer, socketserver.UDPServer]:
    server = ReusableThreadingTCPServer(("127.0.0.1", port), Socks5TcpHandler)
    udp_server = ReusableThreadingUDPServer(("127.0.0.1", port), Socks5UdpRelayHandler)
    server.udp_address = udp_server.server_address
    udp_server.udp_address = udp_server.server_address
    return server, udp_server


def smoke_tcp_chain() -> bytes:
    tcp_port = pick_free_port()
    udp_port = pick_free_port()
    remote_port = pick_free_port()
    hub_port = pick_free_port()
    middle_hub_port = pick_free_port()

    with running_server(start_tcp_echo(tcp_port)), running_server(start_udp_echo(udp_port)):
        remote_tcp, remote_udp = start_socks_proxy(remote_port)
        with running_server(remote_tcp), running_server(remote_udp):
            with running_socks_hub(middle_hub_port, remote_port):
                with running_socks_hub(hub_port, remote_port, middle_hub_port):
                    return tcp_smoke(("127.0.0.1", hub_port), ("127.0.0.1", tcp_port))


def smoke_udp_chain() -> bytes:
    tcp_port = pick_free_port()
    udp_port = pick_free_port()
    remote_port = pick_free_port()
    hub_port = pick_free_port()
    middle_hub_port = pick_free_port()

    with running_server(start_tcp_echo(tcp_port)), running_server(start_udp_echo(udp_port)):
        remote_tcp, remote_udp = start_socks_proxy(remote_port)
        with running_server(remote_tcp), running_server(remote_udp):
            with running_socks_hub(middle_hub_port, remote_port):
                with running_socks_hub(hub_port, remote_port, middle_hub_port):
                    return udp_smoke(("127.0.0.1", hub_port), ("127.0.0.1", udp_port))


def smoke_tcp_direct() -> bytes:
    tcp_port = pick_free_port()
    udp_port = pick_free_port()
    remote_port = pick_free_port()
    hub_port = pick_free_port()

    with running_server(start_tcp_echo(tcp_port)), running_server(start_udp_echo(udp_port)):
        remote_tcp, remote_udp = start_socks_proxy(remote_port)
        with running_server(remote_tcp), running_server(remote_udp):
            with running_socks_hub(hub_port, remote_port):
                return tcp_smoke(("127.0.0.1", hub_port), ("127.0.0.1", tcp_port))


def smoke_udp_direct() -> bytes:
    tcp_port = pick_free_port()
    udp_port = pick_free_port()
    remote_port = pick_free_port()
    hub_port = pick_free_port()

    with running_server(start_tcp_echo(tcp_port)), running_server(start_udp_echo(udp_port)):
        remote_tcp, remote_udp = start_socks_proxy(remote_port)
        with running_server(remote_tcp), running_server(remote_udp):
            with running_socks_hub(hub_port, remote_port):
                return udp_smoke(("127.0.0.1", hub_port), ("127.0.0.1", udp_port))


def main() -> int:
    raise SystemExit("Use smoke_tcp_chain.py or smoke_udp_chain.py")


if __name__ == "__main__":
    main()