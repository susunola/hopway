#!/usr/bin/env python3
"""Exercise the packaged UDP capacity and reload on isolated loopback sockets."""

from contextlib import ExitStack
import http.client
import json
from pathlib import Path
import selectors
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit


def bound_udp(stack):
    sock = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
    sock.bind(("127.0.0.1", 0))
    return sock


def udp_association(stack, socks):
    host, port = socks.rsplit(":", 1)
    control = stack.enter_context(socket.create_connection((host, int(port)), timeout=4))
    reader = stack.enter_context(control.makefile("rb"))
    control.sendall(b"\x05\x01\x00")
    assert reader.read(2) == b"\x05\x00"
    control.sendall(b"\x05\x03\x00\x01" + b"\x00" * 6)
    reply = reader.read(10)
    assert reply[:4] == b"\x05\x00\x00\x01", reply
    relay = socket.inet_ntoa(reply[4:8]), int.from_bytes(reply[8:10], "big")
    client = bound_udp(stack)
    return client, relay


def exchange(association, target, payload, fragment=0):
    client, relay = association
    host, port = target
    header = bytes((0, 0, fragment, 1)) + socket.inet_aton(host) + struct.pack("!H", port)
    if fragment:
        client.sendto(header + payload, relay)
        return 0
    expected = header + payload
    for retry in range(4):
        client.sendto(expected, relay)
        deadline = time.monotonic() + 0.5
        while (left := deadline - time.monotonic()) > 0:
            client.settimeout(left)
            try:
                data, source = client.recvfrom(2048)
            except TimeoutError:
                break
            assert source == relay, (source, relay)
            if data == expected:
                return retry
    raise TimeoutError(f"no relay reply for {payload!r} at target {target}")


def main(core):
    with tempfile.TemporaryDirectory(prefix="hopway-udp-smoke-") as directory, ExitStack() as stack:
        config = Path(directory) / "config.json"
        config.write_text(json.dumps({
            "socksPort": 0, "httpPort": 0, "mode": "direct", "selected": "DIRECT",
            "nodes": [], "rules": [],
        }))
        child = stack.enter_context(subprocess.Popen(
            [core, "-managed", "-config", str(config)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        ))

        def shutdown():
            child.stdin.close()
            try:
                assert child.wait(timeout=8) == 0
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
                raise

        stack.callback(shutdown)
        with selectors.DefaultSelector() as startup:
            startup.register(child.stdout, selectors.EVENT_READ)
            assert startup.select(5), "core did not report readiness"
        ready = json.loads(child.stdout.readline())
        endpoint = urlsplit(ready["control"])

        def control(method, path):
            conn = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=4)
            try:
                conn.request(method, path, headers={"Authorization": "Bearer " + ready["token"]})
                reply = conn.getresponse()
                return reply.status, reply.read()
            finally:
                conn.close()

        def status():
            code, body = control("GET", "/status")
            assert code == 200
            return json.loads(body)

        closed = threading.Event()
        echoed = {}
        selector = stack.enter_context(selectors.DefaultSelector())
        listener_ports = {
            int(ready["socks"].rsplit(":", 1)[1]),
            int(ready["http"].rsplit(":", 1)[1]),
            endpoint.port,
        }
        targets = []
        while len(targets) < 32:
            receiver = bound_udp(stack)
            if receiver.getsockname()[1] in listener_ports:
                receiver.close()
                continue
            targets.append(receiver.getsockname())
            selector.register(receiver, selectors.EVENT_READ)

        def echo():
            while not closed.is_set():
                for key, _ in selector.select(0.05):
                    receiver = key.fileobj
                    data, source = receiver.recvfrom(2048)
                    echoed[data] = echoed.get(data, 0) + 1
                    receiver.sendto(data, source)

        thread = threading.Thread(target=echo, daemon=True)
        thread.start()
        stack.callback(lambda: (closed.set(), thread.join(1)))
        associations = []
        retries = 0
        for a in range(32):
            assoc = udp_association(stack, ready["socks"])
            associations.append(assoc)
            for index, target in enumerate(targets):
                payload = f"association {a}, destination {index}".encode()
                try:
                    retries += exchange(assoc, target, payload)
                except TimeoutError as exc:
                    state = status()
                    matches = [c for c in state["connections"] if c["target"] == f"{target[0]}:{target[1]}"]
                    outcome = [{k: c[k] for k in ("state", "sent", "received", "error") if k in c} for c in matches[-3:]]
                    raise AssertionError(
                        f"{exc}, {state['active']} active, last target records {outcome}, "
                        f"echo server received {echoed.get(payload, 0)} copies, UDP drops {state.get('udpDrops', {})}"
                    ) from exc
        assert status()["active"] == 1024
        print(f"Verified 1,024 UDP sessions across 32 SOCKS5 associations ({retries} packet retries)", flush=True)

        assert control("POST", "/reload")[0] == 204
        fresh = udp_association(stack, ready["socks"])
        exchange(fresh, targets[0], b"first session after reload")
        assert status()["active"] == 1
        # A reply and a new active record together confirm the old association
        # opened a socket on the replacement engine.
        exchange(associations[0], targets[0], b"oldest session reopened")
        assert status()["active"] == 2, "oldest session was not retired across reload"
        exchange(associations[-1], targets[-1], b"recent session remains active")
        assert status()["active"] == 2, "a recent session was unexpectedly retired"

        exchange(fresh, targets[0], b"invalid fragment", fragment=1)
        exchange(fresh, targets[0], b"valid packet after fragment")
        assert status()["udpDrops"]["SOCKS5"]["fragmented"] == 1
        print("Reload shared the cap, retired the oldest session and preserved a recent one")
        print("Control API counted the fragment while the association remained usable")


if __name__ == "__main__":
    main(sys.argv[1])
