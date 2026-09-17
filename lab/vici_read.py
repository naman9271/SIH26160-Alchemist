"""Minimal bounded VICI reader for version/list-sas only.

Wire format: strongSwan src/libcharon/plugins/vici/README.md. No command here
loads credentials or modifies connections; swanctl handles lab configuration.
"""
import socket
import struct


def decode(data):
    pos = 0
    root = {}
    stack = [root]
    current_list = None

    def read(n):
        nonlocal pos
        if n > len(data) - pos:
            raise ValueError("truncated VICI message")
        value = data[pos:pos+n]
        pos += n
        return value

    def name():
        return read(read(1)[0]).decode()

    def value():
        return read(struct.unpack("!H", read(2))[0]).decode()

    while pos < len(data):
        kind = read(1)[0]
        if kind == 1:
            key = name()
            child = {}
            stack[-1][key] = child
            stack.append(child)
        elif kind == 2:
            if len(stack) == 1:
                raise ValueError("unbalanced VICI section")
            stack.pop()
        elif kind == 3:
            key = name()
            stack[-1][key] = value()
        elif kind == 4:
            key = name()
            current_list = []
            stack[-1][key] = current_list
        elif kind == 5:
            if current_list is None:
                raise ValueError("VICI list item outside list")
            current_list.append(value())
        elif kind == 6:
            current_list = None
        else:
            raise ValueError("unknown VICI element")
    if len(stack) != 1 or current_list is not None:
        raise ValueError("unfinished VICI message")
    return root


class Session:
    def request(self, command, event=None):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(10)
            sock.connect("/var/run/charon.vici")

            def receive():
                def exact(n):
                    out = bytearray()
                    while len(out) < n:
                        chunk = sock.recv(n-len(out))
                        if not chunk:
                            raise ValueError("VICI connection closed")
                        out.extend(chunk)
                    return bytes(out)
                size = struct.unpack("!I", exact(4))[0]
                if not 1 <= size <= 4*1024*1024:
                    raise ValueError("invalid VICI frame size")
                return exact(size)

            def send(kind, name):
                encoded = name.encode()
                packet = bytes([kind, len(encoded)]) + encoded
                sock.sendall(struct.pack("!I", len(packet)) + packet)

            if event:
                send(3, event)
                if receive()[0] != 5:
                    raise ValueError("VICI event registration failed")
            send(0, command)
            rows = []
            while True:
                packet = receive()
                if packet[0] == 1:
                    return rows if event else decode(packet[1:])
                if packet[0] != 7 or len(packet) < 2:
                    raise ValueError("VICI command failed")
                rows.append(decode(packet[2+packet[1]:]))

    def version(self):
        return self.request("version")

    def list_sas(self):
        return self.request("list-sas", "list-sa")
