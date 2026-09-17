"""Seeded synthetic workloads; these labels describe generators, not real apps."""
import argparse
import random
import socket
import socketserver
import struct
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class HTTP(BaseHTTPRequestHandler):
    def do_GET(self):
        size = 65536 if self.path == "/segment" else 8192
        body = b"synthetic-lab-data\n" * (size // 19)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(30)
        while True:
            data = self.request.recv(8192)
            if not data:
                return
            self.request.sendall(data)


class SMTP(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(30)
        self.wfile.write(b"220 lab ESMTP\r\n")
        in_data = False
        for line in self.rfile:
            if in_data:
                if line == b".\r\n":
                    in_data = False
                    self.wfile.write(b"250 accepted\r\n")
                continue
            verb = line.split()[0].upper() if line.split() else b""
            if verb == b"DATA":
                in_data = True
                self.wfile.write(b"354 send message\r\n")
            elif verb == b"QUIT":
                self.wfile.write(b"221 bye\r\n")
                return
            else:
                self.wfile.write(b"250 ok\r\n")


def server(host):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    for base, handler, port in [(ThreadingHTTPServer, HTTP, 8080),
                                 (socketserver.ThreadingTCPServer, Echo, 9090),
                                 (socketserver.ThreadingTCPServer, SMTP, 2525)]:
        cls = type("Server", (base,), {"address_family": family, "allow_reuse_address": True, "daemon_threads": True})
        instance = cls((host, port), handler)
        threading.Thread(target=instance.serve_forever, daemon=True).start()
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.bind((host, 5004))
    while True:
        data, peer = sock.recvfrom(2048)
        sock.sendto(data, peer)


def client(host, label, seconds, seed):
    rng = random.Random(seed)
    end = time.monotonic() + seconds
    authority = f"[{host}]" if ":" in host else host
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    if label in {"web", "video"}:
        while time.monotonic() < end:
            for _ in range(4 if label == "web" else 1):
                with opener.open(f"http://{authority}:8080/" + ("segment" if label == "video" else "page"), timeout=5) as reply:
                    reply.read()
            time.sleep(rng.uniform(.1, .6) if label == "web" else .15)
    elif label == "email":
        import smtplib
        while time.monotonic() < end:
            with smtplib.SMTP(host, 2525, timeout=5) as smtp:
                smtp.sendmail("sender@lab.invalid", "sink@lab.invalid", "Subject: Synthetic\n\n" + "example " * 100)
            time.sleep(.5)
    elif label == "voip":
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2)
            seq = 0
            while time.monotonic() < end:
                packet = struct.pack("!BBHII", 0x80, 0, seq % 65536, (seq*160) % 2**32, seed % 2**32) + rng.randbytes(160)
                sock.sendto(packet, (host, 5004)); sock.recv(2048)
                seq += 1
                time.sleep(.02)
    else:
        with socket.create_connection((host, 9090), timeout=5) as sock:
            while time.monotonic() < end:
                data = rng.randbytes(8192 if label == "file_transfer" else rng.randint(32, 256))
                sock.sendall(data)
                remaining = len(data)
                while remaining:
                    chunk = sock.recv(remaining)
                    if not chunk:
                        raise RuntimeError("traffic peer closed early")
                    remaining -= len(chunk)
                time.sleep(.005 if label == "file_transfer" else rng.uniform(.05, .4))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["server", "client"])
    parser.add_argument("host")
    parser.add_argument("--label", choices=["web", "video", "email", "voip", "messaging", "file_transfer"], default="web")
    parser.add_argument("--seconds", type=int, default=10)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    if args.mode == "server":
        server(args.host)
    else:
        client(args.host, args.label, args.seconds, args.seed)
