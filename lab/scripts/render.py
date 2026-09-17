#!/usr/bin/env python3
"""Render the selected, allow-listed lab profile into swanctl configs."""
import pathlib, sys
from profile import load

p = load(sys.argv[1]); root = pathlib.Path("lab/runtime")
dh = {"modp2048": "modp2048", "ecp256": "ecp256"}[p["dh_group"]]
esp = {"aes128-sha256": "aes128-sha256", "aes256-sha256": "aes256-sha256", "aes128gcm16": "aes128gcm16", "aes256gcm16": "aes256gcm16"}[p["esp"]]
selector = "::/0" if p["address_family"] == "ipv6" else "0.0.0.0/0"
mode = p["mode"]
def config(local, remote):
    return f'''connections {{
  lab-{p["id"]} {{
    version = 2
    local_addrs = {local}
    remote_addrs = {remote}
    proposals = aes256gcm16-prfsha256-{dh}
    local {{
      auth = psk
      id = {local}
    }}
    remote {{
      auth = psk
      id = {remote}
    }}
    children {{ protected {{
      mode = {mode}
      local_ts = {selector}
      remote_ts = {selector}
      esp_proposals = {esp}-{dh}
      start_action = start
    }} }}
  }}
}}
secrets {{
  ike-lab {{
    id-0 = {local}
    id-1 = {remote}
    secret = "alchemist-lab-only-psk"
  }}
}}
'''
for name, local, remote in (("left", "172.30.0.10", "172.30.0.20"), ("right", "172.30.0.20", "172.30.0.10")):
    directory = root / name; directory.mkdir(parents=True, exist_ok=True)
    (directory / "lab.conf").write_text(config(local, remote))
