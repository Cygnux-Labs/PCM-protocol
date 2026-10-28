"""Minimal repro of the IPv4 leading-zero false accept (L16.H.01-07; RESULTS.md, finding F1).

A URL host with a leading-zero octet is read two ways. PCM 0.1 (SPEC 6.7) reads it as inet_aton does, octal:
0127.0.0.1 is 87.0.0.1. This machine's resolver, getaddrinfo, which Python's urllib (and so an executor) connects
through, may read it as decimal: on macOS 0127.0.0.1 is 127.0.0.1. So a T2 fetch of http://0127.0.0.1:<port>/ really
reaches 127.0.0.1, and a reached_host claim of 87.0.0.1 resting on it is proven by both verifiers.

    PYTHONPATH=<tracekit checkout> python bench/lies/findings/ipv4_leading_zero.py
"""
import http.server
import json
import pathlib
import socket
import sys
import threading
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
HOSTS = ["0127.0.0.1", "0177.0.0.1", "010.0.0.1", "192.168.0.010"]


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        SEEN.append(self.client_address[0])
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


SEEN = []


def main():
    print(f"{sys.platform}, Python {sys.version.split()[0]}")
    for h in HOSTS:
        os_reads = socket.getaddrinfo(h, None, 0, socket.SOCK_STREAM, 0, socket.AI_NUMERICHOST)[0][4][0]
        aton = socket.inet_ntoa(socket.inet_aton(h))
        print(f"  {h:<15} getaddrinfo (what a connection reaches): {os_reads:<13} inet_aton (PCM 0.1): {aton}")
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://0127.0.0.1:{srv.server_address[1]}/ok"
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url, timeout=5) as r:
        print(f"  urllib GET {url} -> HTTP {r.status}; the server on 127.0.0.1 saw a connection from {SEEN}")
    srv.shutdown()
    rec = json.loads((HERE / "L16.H.01.json").read_text())
    claim = rec["record"]["message"]["claims"][0]
    print(f"  the message claims reached_host {claim['args']['host']!r} with that call as evidence; verdicts:")
    for name, out in rec["outputs"].items():
        print(f"    {name:<10} {out['verdict']:<16} {out.get('reason_class', '(baseline)')}")
    print("  re-run both verifiers on it: python bench/lies/findings/repro.py bench/lies/findings/L16.H.01.json")


if __name__ == "__main__":
    main()
