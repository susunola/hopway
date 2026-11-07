#!/usr/bin/env python3
"""Exercise a HopWay core using only disposable profiles and loopback traffic."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import http.client
import json
from pathlib import Path
import selectors
import signal
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(32768):
            self.request.sendall(data)


class Origin(socketserver.ThreadingTCPServer):
    daemon_threads = True
    request_queue_size = 32


def dial(address):
    host, port = address.rsplit(":", 1)
    return socket.create_connection((host, int(port)), timeout=3)


def send_echo(conn, salt=0):
    payload = bytes((n + salt) % 256 for n in range(256)) * 160
    conn.sendall(payload)
    with conn.makefile("rb") as reader:
        assert reader.read(len(payload)) == payload


def http_handshake(conn, target):
    conn.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
    with conn.makefile("rb") as reader:
        status = reader.readline()
        assert status.startswith(b"HTTP/1.1 200 "), status
        for line in reader:
            if line == b"\r\n":
                return
    raise RuntimeError("incomplete CONNECT headers")


def socks_handshake(conn, port):
    with conn.makefile("rb") as reader:
        conn.sendall(b"\x05\x01\x00")
        assert reader.read(2) == b"\x05\x00"
        conn.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", port))
        header = reader.read(4)
        assert header[:2] == b"\x05\x00", header
        length = {1: 6, 4: 18}[header[3]]
        assert len(reader.read(length)) == length


def reload(ready):
    url = urlsplit(ready["control"])
    connection = http.client.HTTPConnection(url.hostname, url.port, timeout=3)
    try:
        connection.request("POST", "/reload", headers={"Authorization": "Bearer " + ready["token"]})
        response = connection.getresponse()
        assert response.status == 204, (response.status, response.read())
    finally:
        connection.close()


def parallel_tunnels(ready, port):
    def exchange(index):
        if index % 2:
            with dial(ready["http"]) as conn:
                http_handshake(conn, f"127.0.0.1:{port}")
                send_echo(conn, index)
        else:
            with dial(ready["socks"]) as conn:
                socks_handshake(conn, port)
                send_echo(conn, index)
    with ThreadPoolExecutor(max_workers=16) as workers:
        list(workers.map(exchange, range(16)))


def run(binary, path, port, cycle):
    config = dict(socksPort=0, httpPort=0, systemProxy=False, mode="rule",
                  selected="DIRECT", rules=[{"type": "match", "via": "DIRECT"}])
    path.write_text(json.dumps(config))
    with subprocess.Popen([binary, "-managed", "-config", str(path)], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                if not selector.select(5):
                    raise RuntimeError("core did not report readiness")
            ready = json.loads(process.stdout.readline())
            if cycle == 0:
                contender = subprocess.run([binary, "-managed", "-config", str(path)],
                                           input=b"", capture_output=True, timeout=4)
                refusal = json.loads(contender.stdout)
                assert contender.returncode != 0 and "control" not in refusal, "two cores opened the same profile"
                assert "已在使用此配置" in refusal.get("error", ""), refusal
                parallel_tunnels(ready, port)
            target = f"127.0.0.1:{port}"
            with dial(ready["http"]) as http_conn:
                http_handshake(http_conn, target)
                send_echo(http_conn)
                config["rules"][0]["via"] = "REJECT"
                path.write_text(json.dumps(config))
                reload(ready)
                send_echo(http_conn)  # an established tunnel keeps its original route
                with dial(ready["http"]) as blocked:
                    blocked.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
                    with blocked.makefile("rb") as reader:
                        status = reader.readline()
                        assert status.startswith(b"HTTP/1.1 403 "), status
                config["rules"][0]["via"] = "DIRECT"
                path.write_text(json.dumps(config))
                reload(ready)
                with dial(ready["socks"]) as socks_conn:
                    socks_handshake(socks_conn, port)
                    send_echo(socks_conn)
                    started = time.monotonic()
                    if cycle % 2:
                        process.stdin.close()
                    else:
                        process.send_signal(signal.SIGTERM)
                    assert process.wait(timeout=4) == 0
                    duration = time.monotonic() - started
                    for conn in (http_conn, socks_conn):
                        assert conn.recv(1) == b"", "a tunnel survived shutdown"
            for address in (ready["http"], ready["socks"], urlsplit(ready["control"]).netloc):
                try:
                    with dial(address):
                        raise AssertionError("a listener survived shutdown")
                except ConnectionRefusedError:
                    pass
            return duration
        finally:
            if process.poll() is None:
                process.kill()


def occupied_http_port(binary, path):
    with socket.socket() as blocker:
        blocker.bind(("127.0.0.1", 0))
        blocker.listen()
        with socket.socket() as temporary:
            temporary.bind(("127.0.0.1", 0))
            socks = temporary.getsockname()
        path.write_text(json.dumps(dict(httpPort=blocker.getsockname()[1], socksPort=socks[1])))
        result = subprocess.run([binary, "-managed", "-config", str(path)], input=b"",
                                capture_output=True, timeout=4)
        message = json.loads(result.stdout)
        assert result.returncode != 0 and message.get("error", "").startswith("HTTP proxy:"), message
        # The SOCKS listener was opened first and must be available again.
        with socket.socket() as released:
            released.bind(socks)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("core", type=Path)
    parser.add_argument("--cycles", default=50, type=int)
    args = parser.parse_args()
    if args.cycles <= 0:
        parser.error("expected a positive cycle count")
    with tempfile.TemporaryDirectory(prefix="hopway-smoke-") as work, Origin(("127.0.0.1", 0), Echo) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            binary = str(args.core.resolve())
            path = Path(work) / "config.json"
            occupied_http_port(binary, path)
            durations = [run(binary, path, server.server_address[1], cycle)
                         for cycle in range(args.cycles)]
        finally:
            server.shutdown()
    print(f"{args.cycles}/{args.cycles} cycles passed: HTTP CONNECT, SOCKS5, reload with open tunnels, "
          f"SIGTERM/stdin EOF, listener and tunnel closure. "
          f"Port conflict, profile exclusion, and 16 parallel tunnels passed. Max shutdown: {max(durations) * 1000:.1f} ms.")


if __name__ == "__main__":
    main()
