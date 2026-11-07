#!/usr/bin/env python3
"""Exercise cancellation against real loopback sockets and an isolated profile."""
import fcntl
import hashlib
import http.client
import http.server
import json
from pathlib import Path
import queue
import runpy
import selectors
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit


qa = runpy.run_path(str(Path(__file__).with_name("smoke-lifecycle.py")))


class Partial(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        closed = threading.Event()
        self.send_response(200)
        self.send_header("Content-Length", str(8 << 20))
        self.end_headers()
        self.wfile.write(b"partial body\n")
        self.wfile.flush()
        self.server.arrivals[self.path].put(closed)
        self.connection.settimeout(8)
        try:
            if not self.connection.recv(1):
                closed.set()
        except ConnectionResetError:
            closed.set()
        except TimeoutError:
            pass


class StalledSocks(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(8)
        if not self.request.recv(32):
            return
        self.server.started.set()
        try:
            if not self.request.recv(1):
                self.server.disconnected.set()
        except ConnectionResetError:
            self.server.disconnected.set()
        except TimeoutError:
            pass


def main(core):
    with (tempfile.TemporaryDirectory(prefix="hopway-refresh-cancel-") as directory,
          http.server.ThreadingHTTPServer(("127.0.0.1", 0), Partial) as remote,
          qa["Origin"](("127.0.0.1", 0), StalledSocks) as socks,
          qa["Origin"](("127.0.0.1", 0), qa["Echo"]) as echo):
        remote.arrivals = {path: queue.Queue() for path in ("/subscription", "/rules.list")}
        socks.started, socks.disconnected = threading.Event(), threading.Event()
        for server in (remote, socks, echo):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            exercise(core, Path(directory), remote, socks, echo)
        finally:
            for server in (remote, socks, echo):
                server.shutdown()


def exercise(core, root, remote, socks, echo):
    origin = f"http://127.0.0.1:{remote.server_port}"
    sub, rules = origin + "/subscription", origin + "/rules.list"
    config = root / "config.json"
    initial = json.dumps({
        "socksPort": 0, "httpPort": 0, "mode": "rule", "selected": "DIRECT",
        "health": {"url": origin + "/rules.list"},
        "subscriptions": [{"name": "fixture", "url": sub}],
        "groups": [{"name": "choice", "type": "select", "members": ["DIRECT", "REJECT"]}],
        "ruleSets": [{"name": "fixture rules", "url": rules}],
        "rules": [{"type": "rule-set", "value": "fixture rules", "via": "REJECT"}, {"type": "match", "via": "DIRECT"}],
    }).encode()
    config.write_bytes(initial)
    subscription = root / "cache" / "subscriptions" / (hashlib.sha256(sub.encode()).hexdigest()[:16] + ".json")
    rule_set = root / "cache" / "rulesets" / (hashlib.sha256((rules + "\0text\0").encode()).hexdigest()[:16] + ".text")
    snapshot_bytes = json.dumps({"updated": int(time.time() * 1000), "nodes": [{
        "name": "fixture node", "type": "socks5", "server": f"127.0.0.1:{socks.server_address[1]}",
    }]}).encode()
    rules_bytes = b"DOMAIN,old.test\n"
    for path, data in ((subscription, snapshot_bytes), (rule_set, rules_bytes)):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def unchanged():
        assert config.read_bytes() == initial and subscription.read_bytes() == snapshot_bytes and rule_set.read_bytes() == rules_bytes
        assert list(subscription.parent.glob("*.json")) == [subscription]

    with subprocess.Popen([core, "-managed", "-config", str(config)], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
        try:
            ready = qa["wait_ready"](child)
            control = urlsplit(ready["control"])
            assert control.hostname == "127.0.0.1"

            def request(method, path, token=ready["token"], body=None):
                connection = http.client.HTTPConnection(control.hostname, control.port, timeout=3)
                headers = {"Authorization": "Bearer " + token} if token else {}
                connection.request(method, path, body=body, headers=headers)
                return connection, connection.getresponse()

            def code(method, path, **kwargs):
                connection, response = request(method, path, **kwargs)
                try:
                    response.read()
                    return response.status
                finally:
                    response.close()
                    connection.close()

            assert code("GET", "/status", token="") == 401
            assert code("POST", "/subscriptions/refresh", token="wrong") == 401
            assert code("PUT", "/groups/choice", body=b'{"selected":"REJECT"}' + b" " * 5000) == 400
            assert code("PUT", "/tun", body=b"{}") == 400
            _, data = qa["control_request"](ready, "GET", "/status")
            assert next(g for g in json.loads(data)["groups"] if g["name"] == "choice")["selected"] == "DIRECT"
            assert code("PUT", "/groups/choice", body=b'{"selected":"REJECT"}') == 204
            assert code("PUT", "/groups/choice", body=b'{"selected":"DIRECT"}') == 204
            for control_path, path in (("/subscriptions/refresh", "/subscription"), ("/rulesets/refresh", "/rules.list")):
                connection, response = request("POST", control_path + "?wait=1")
                assert response.status == 200
                closed = remote.arrivals[path].get(timeout=3)
                response.close()
                connection.close()
                assert closed.wait(2), path
                unchanged()
                _, route = qa["control_request"](ready, "GET", "/route?target=old.test%3A443")
                assert json.loads(route)["outbound"] == "REJECT", route

            # One subscription and one rule set download can run, queued
            # refreshes remain bounded, and a probe owns a real SOCKS socket.
            assert code("POST", "/probe") == 202
            assert socks.started.wait(3)
            assert code("POST", "/rulesets/refresh") == 202
            rule_socket = remote.arrivals["/rules.list"].get(timeout=3)
            for _ in range(6):
                assert code("POST", "/subscriptions/refresh") == 202
            sub_socket = remote.arrivals["/subscription"].get(timeout=3)
            assert code("POST", "/subscriptions/refresh") == 429
            assert remote.arrivals["/subscription"].empty()
            with qa["dial"](ready["http"]) as stream:
                qa["http_handshake"](stream, f"127.0.0.1:{echo.server_address[1]}")
                qa["send_echo"](stream)
            _, payload = qa["control_request"](ready, "GET", "/status")
            expected = json.loads(payload)["sessionTraffic"]
            assert expected["upload"] >= qa["ECHO_SIZE"] and expected["download"] >= qa["ECHO_SIZE"]
            started = time.monotonic()
            child.stdin.close()
            assert child.wait(timeout=5) == 0, child.stderr.read()
            duration = time.monotonic() - started
            assert rule_socket.wait(2) and sub_socket.wait(2) and socks.disconnected.wait(2)
            assert remote.arrivals["/subscription"].empty()
            unchanged()
            ledger = json.loads((root / "traffic-history.json").read_bytes())
            assert all(sum(count[key] for day in ledger["days"].values() for count in day.values()) == expected[key]
                       for key in ("upload", "download"))
            print(f"Managed shutdown joined 8 accepted jobs in {duration * 1000:.1f} ms. All sockets closed, caches unchanged, traffic finalized exactly once.")
        finally:
            if child.poll() is None:
                child.kill()

    source = root / "preview-input"
    source.write_text(sub)
    for flags in (["-refresh-subscriptions"], ["-preview-import", "-input-file", str(source)],
                  ["-commit-import", "-input-file", str(source), "-expected-revision", hashlib.sha256(initial).hexdigest()]):
        with subprocess.Popen([core, *flags, "-watch-stdin", "-config", str(config)], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
            try:
                closed = remote.arrivals["/subscription"].get(timeout=3)
                child.stdin.close()
                assert child.wait(timeout=4) != 0
                assert closed.wait(2)
                unchanged()
            finally:
                if child.poll() is None:
                    child.kill()
    with (subscription.parent / ".write.lock").open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with subprocess.Popen([core, "-managed", "-config", str(config)], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as child:
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ)
                    assert not selector.select(0.10) and child.poll() is None
                child.stdin.close()
                assert child.wait(timeout=2) == 0
                unchanged()
            finally:
                if child.poll() is None:
                    child.kill()
    print("Control auth, body bounds, disconnect cancellation and offline parent exit passed.")


if __name__ == "__main__":
    main(str(Path(sys.argv[1]).resolve()))
