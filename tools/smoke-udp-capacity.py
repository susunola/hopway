#!/usr/bin/env python3
"""Exercise the packaged UDP capacity and reload on isolated loopback sockets."""

from contextlib import ExitStack
from concurrent.futures import ThreadPoolExecutor
import http.client
import json
from pathlib import Path
import selectors
import socket
import statistics
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


def exchange(association, target, payload, fragment=0, attempts=4):
    client, relay = association
    host, port = target
    header = bytes((0, 0, fragment, 1)) + socket.inet_aton(host) + struct.pack("!H", port)
    if fragment:
        client.sendto(header + payload, relay)
        return 0
    expected = header + payload
    for retry in range(attempts):
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


def measure_active_reload(ready, control, association, target):
    tcp_address = ready["http"].rsplit(":", 1)
    with socket.socket() as origin, ExitStack() as stack, ThreadPoolExecutor(max_workers=3) as workers:
        origin.bind(("127.0.0.1", 0))
        origin.listen()
        origin.settimeout(3)

        def echo_tcp():
            peer, _ = origin.accept()
            with peer:
                peer.settimeout(3)
                while data := peer.recv(4096):
                    peer.sendall(data)

        echo = workers.submit(echo_tcp)
        tcp = stack.enter_context(socket.create_connection((tcp_address[0], int(tcp_address[1])), timeout=3))
        reader = stack.enter_context(tcp.makefile("rb"))
        address = f"127.0.0.1:{origin.getsockname()[1]}"
        tcp.sendall(f"CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n".encode())
        assert reader.readline().startswith(b"HTTP/1.1 200 ")
        for line in reader:
            if line == b"\r\n":
                break

        def exchange_tcp(seq):
            payload = seq.to_bytes(8, "big")
            tcp.sendall(payload)
            assert reader.read(len(payload)) == payload

        def exchange_udp(seq):
            exchange(association, target, f"reload sample {seq}".encode(), attempts=1)

        finished = threading.Event()

        def sample(send, started):
            timings = []
            failures = 0
            while not finished.is_set():
                before = time.monotonic()
                try:
                    send(len(timings))
                except (OSError, AssertionError):
                    failures += 1
                timings.append((time.monotonic() - before) * 1000)
                started.set()
                time.sleep(0.005)
            return timings, failures

        tcp_started, udp_started = threading.Event(), threading.Event()
        tcp_results = workers.submit(sample, exchange_tcp, tcp_started)
        udp_results = workers.submit(sample, exchange_udp, udp_started)
        reloads = []
        try:
            assert tcp_started.wait(3) and udp_started.wait(3)
            for _ in range(12):
                before = time.monotonic()
                code, response = control("POST", "/reload")
                reloads.append((time.monotonic() - before) * 1000)
                assert code == 204, (code, response)
                time.sleep(0.025)
        finally:
            finished.set()
            tcp_timings, tcp_failures = tcp_results.result(timeout=5)
            udp_timings, udp_failures = udp_results.result(timeout=5)
            reader.close()
            tcp.close()
            echo.result(timeout=5)
        print(f"12 reloads under traffic, reload median {statistics.median(reloads):.2f} ms, max {max(reloads):.2f} ms. "
              f"TCP {len(tcp_timings)} samples, {tcp_failures} failures, max {max(tcp_timings):.2f} ms. "
              f"UDP {len(udp_timings)} samples, {udp_failures} failures without retries, max {max(udp_timings):.2f} ms.")
        assert tcp_timings and udp_timings and not (tcp_failures or udp_failures)


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

        def get(path):
            code, body = control("GET", path)
            assert code == 200, (code, body)
            return json.loads(body), len(body)

        legacy, legacy_bytes = get("/status")
        compact, compact_bytes = get("/status?view=compact")
        assert legacy["active"] == compact["active"] == 1024
        assert len(legacy["connections"]) == 1024 and "connections" not in compact
        assert compact_bytes < legacy_bytes / 20
        initial, _ = get("/connections")
        assert initial["full"] and len(initial["records"]) == 1024
        assert initial["generation"] == compact["generation"]

        cursor = f"/connections?generation={initial['generation']}&cursor={initial['cursor']}"
        idle, idle_bytes = get(cursor)
        assert idle == {"generation": initial["generation"], "cursor": initial["cursor"]}
        exchange(associations[15], targets[7], b"one live connection changed")
        changed, changed_bytes = get(cursor)
        assert not ("records" in changed or "removed" in changed or "full" in changed)
        assert len(changed["counters"]) == 1 and changed["cursor"] > initial["cursor"]
        patch = changed["counters"][0]
        before = next(row for row in initial["records"] if row["id"] == patch["id"])
        assert patch["sent"] - before["sent"] == len(b"one live connection changed")
        assert patch["received"] - before["received"] == len(b"one live connection changed")
        print(f"1,024 active connections: full status {legacy_bytes:,} bytes, compact status {compact_bytes:,} bytes, "
              f"idle delta {idle_bytes} bytes, one counter patch {changed_bytes} bytes", flush=True)

        assert control("POST", "/reload")[0] == 204
        reset, _ = get(cursor)
        assert reset["full"] and reset["generation"] != initial["generation"] and not reset.get("records")
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
        measure_active_reload(ready, control, fresh, targets[0])


if __name__ == "__main__":
    main(sys.argv[1])
