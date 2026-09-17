"""Reproducible isolated IPsec lab controller (Python standard library only).

Use via root Makefile. It never configures the host VPN or routes. Compose owns
all lab networks. Run manifests are written last, only after verification.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent
LABELS = ["icmp", "web", "video", "voip", "email", "messaging", "file_transfer"]
COMPOSE = ["docker", "compose", "-f", str(ROOT / "compose.yaml")]


def command(args, *, timeout=120, check=True):
    return subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, check=check)


def execute(node, *args, **kwargs):
    return command(COMPOSE + ["exec", "-T", node, *args], **kwargs)


def profile(name):
    if not re.fullmatch(r"[a-z0-9-]+", name):
        raise ValueError("invalid profile ID")
    p = json.loads((ROOT / "profiles" / f"{name}.json").read_text())
    if p["id"] != name or p["mode"] not in {"tunnel", "transport"} or p["ip_version"] not in {4, 6}:
        raise ValueError("invalid profile")
    if p["key_bits"] not in {128, 256} or p["cipher"] not in {"AES_CBC", "AES_GCM_16"}:
        raise ValueError("unsupported cipher profile")
    for key in ("ike", "esp"):
        if not re.fullmatch(r"[a-z0-9-]+", p[key]):
            raise ValueError("invalid StrongSwan proposal")
    return p


def addresses(p):
    if p["ip_version"] == 4:
        return "172.30.160.2", "172.30.160.3", "172.30.161.10", "172.30.162.10"
    return "fd26:160:0::2", "fd26:160:0::3", "fd26:160:1::10", "fd26:160:2::10"


def config(p, side, secret):
    left, right, client, server = addresses(p)
    if p["mode"] == "transport":
        client, server = left, right
    local, remote, local_ts, remote_ts = (left, right, client, server) if side == "left" else (right, left, server, client)
    bits = 32 if p["ip_version"] == 4 else 128
    return f"""connections {{
  lab {{
    version = 2
    local_addrs = {local}
    remote_addrs = {remote}
    proposals = {p['ike']}
    encap = {'yes' if p['encap'] else 'no'}
    rekey_time = 3600s
    local {{ auth = psk
      id = lab-{side}
    }}
    remote {{ auth = psk
      id = lab-{'right' if side == 'left' else 'left'}
    }}
    children {{
      protected {{
        mode = {p['mode']}
        local_ts = {local_ts}/{bits}
        remote_ts = {remote_ts}/{bits}
        esp_proposals = {p['esp']}
        start_action = none
        rekey_time = 300s
        life_time = 360s
        rand_time = 0s
        replay_window = 32
      }}
    }}
  }}
}}
secrets {{
  ike-lab {{
    id-1 = lab-left
    id-2 = lab-right
    secret = {secret}
  }}
}}
"""


def setup(p):
    runtime = ROOT / "runtime"
    runtime.mkdir(exist_ok=True, mode=0o700)
    (ROOT / "runs").mkdir(exist_ok=True)
    secret = secrets.token_hex(32)
    for side in ("left", "right"):
        path = runtime / f"{side}.conf"
        path.write_text(config(p, side, secret))
        path.chmod(0o600)
    (runtime / "profile.json").write_text(json.dumps(p))
    command(COMPOSE + ["up", "-d", "--build"], timeout=900)
    for side in ("left", "right"):
        for attempt in range(30):
            result = execute(side, "swanctl", "--load-all", "--file", f"/runtime/{side}.conf", check=False)
            if result.returncode == 0:
                break
            time.sleep(.5)
        else:
            raise RuntimeError(f"{side} StrongSwan failed to load configuration: {result.stderr}")


def snapshot(node):
    return json.loads(execute(node, "python3", "/opt/lab/snapshot.py").stdout)


def verify_snapshot(p, data):
    """Fail closed on negotiated fallback, uninstalled SAs, or mismatched mode."""
    children = []
    for event in data.get("sas", []):
        for ike in event.values():
            if ike.get("state") != "ESTABLISHED" or str(ike.get("version")) != "2":
                continue
            if ike.get("dh-group") != p["dh"]:
                raise ValueError("negotiated IKE DH group differs from profile")
            children.extend(ike.get("child-sas", {}).values())
    installed = [c for c in children if c.get("state") == "INSTALLED"]
    if not installed:
        raise ValueError("no installed Child SA")
    for child in installed:
        if child.get("mode", "").lower() != p["mode"]:
            raise ValueError("negotiated mode differs from profile")
        if child.get("encr-alg") != p["cipher"] or int(child.get("encr-keysize", 0)) != p["key_bits"]:
            raise ValueError("negotiated cipher or key size differs from profile")
        if p["integrity"] and child.get("integ-alg") != p["integrity"]:
            raise ValueError("negotiated integrity differs from profile")
        if p["pfs"] and child.get("dh-group") != p["dh"]:
            raise ValueError("rekeyed Child SA has not verified the requested PFS group")
        if not p["pfs"] and child.get("dh-group") not in (None, "", "NONE", "MODP_NONE"):
            raise ValueError("unexpected Child-SA PFS group")
    states = [s for s in data.get("states", []) if s.get("proto") == "esp"]
    if len(states) < 2:
        raise ValueError("bidirectional XFRM ESP states missing")
    for state in states:
        if state.get("mode") != p["mode"]:
            raise ValueError("XFRM mode mismatch")
        if ipaddress.ip_address(state["src"]).version != p["ip_version"]:
            raise ValueError("XFRM address family mismatch")
        if bool(state.get("encap")) != p["encap"]:
            raise ValueError("XFRM UDP encapsulation mismatch")
    if not data.get("policies"):
        raise ValueError("XFRM policy snapshot missing")
    return {"verified": True, "ike_sas": len(data["sas"]), "installed_children": len(installed),
            "xfrm_states": len(states), "pfs_verification": "post-rekey"}


def verify(p):
    results = {}
    for node in ("left", "right"):
        data = snapshot(node)
        results[node] = {"check": verify_snapshot(p, data), "snapshot": data}
    return results


def network_interface(node, address):
    rows = json.loads(execute(node, "ip", "-j", "address").stdout)
    for row in rows:
        if any(info.get("local") == address for info in row.get("addr_info", [])):
            return row["ifname"]
    raise RuntimeError(f"interface for {address} not found")


def start_process(node, args, log):
    # Docker exec remains attached so its exit code is available for validation.
    handle = log.open("w")
    process = subprocess.Popen(COMPOSE + ["exec", "-T", node, *args], stdout=handle, stderr=handle)
    handle.close()
    return process


def stop_capture(node, process):
    # These containers are dedicated to one serialized lab run.
    execute(node, "pkill", "-INT", "tcpdump", check=False)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.terminate()
        process.wait(timeout=5)


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024*1024), b""):
            h.update(block)
    return h.hexdigest()


def run(p, label, seconds, seed):
    saved = json.loads((ROOT / "runtime/profile.json").read_text())
    if saved != p:
        raise ValueError("running configuration differs: run lab-up with this PROFILE first")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(4)
    directory = ROOT / "runs" / run_id
    directory.mkdir(mode=0o700)
    left, right, client, server = addresses(p)
    source_node, target_node = "client", "server"
    if p["mode"] == "transport":
        source_node, target_node, client, server = "left", "right", left, right
    captures = []
    workload = None
    try:
        # Remove the previous lab SA through its named connection, never flush
        # the host's XFRM database. Start capture before negotiation.
        execute("left", "swanctl", "--terminate", "--ike", "lab", check=False)
        execute("right", "swanctl", "--terminate", "--ike", "lab", check=False)
        for node, address in [("left", left), ("right", right)]:
            interface = network_interface(node, address)
            log = directory / f"{node}-outer.log"
            args = ["tcpdump", "-U", "-n", "-i", interface, "-w", f"/runs/{run_id}/{node}-outer.pcap", "ip or ip6"]
            captures.append((node, start_process(node, args, log), interface, "outer"))
        if p["mode"] == "tunnel":
            iface = network_interface("client", client)
            args = ["tcpdump", "-U", "-n", "-i", iface, "-w", f"/runs/{run_id}/inner.pcap", "ip or ip6"]
            captures.append(("client", start_process("client", args, directory / "inner.log"), iface, "inner"))
        else:
            # NFLOG captures plaintext at the endpoint before transport-mode
            # XFRM processing. This ground-truth file is not classifier input.
            firewall = "ip6tables" if p["ip_version"] == 6 else "iptables"
            execute("left", firewall, "-t", "mangle", "-A", "OUTPUT", "-d", right,
                    "-p", "icmpv6" if p["ip_version"] == 6 else "icmp", "-j", "NFLOG", "--nflog-group", "5")
            execute("left", firewall, "-t", "mangle", "-A", "OUTPUT", "-d", right,
                    "-p", "tcp", "-j", "NFLOG", "--nflog-group", "5")
            execute("left", firewall, "-t", "mangle", "-A", "OUTPUT", "-d", right,
                    "-p", "udp", "--dport", "5004", "-j", "NFLOG", "--nflog-group", "5")
            args = ["tcpdump", "-U", "-n", "-i", "nflog:5", "-w", f"/runs/{run_id}/inner.pcap"]
            captures.append(("left", start_process("left", args, directory / "inner.log"), "nflog:5", "inner"))
        time.sleep(1)
        if any(proc.poll() is not None for _, proc, _, _ in captures):
            raise RuntimeError("capture failed to start; inspect run logs")
        execute("left", "swanctl", "--initiate", "--child", "protected")
        # The first Child SA uses IKE's DH. Force a rekey to verify separate PFS.
        execute("left", "swanctl", "--rekey", "--child", "protected")
        for attempt in range(20):
            try:
                verified = verify(p)
                break
            except ValueError:
                if attempt == 19:
                    raise
                time.sleep(.5)
        (directory / "gateway-before.json").write_text(json.dumps(verified, indent=2))
        workload = start_process(target_node, ["python3", "/opt/lab/traffic.py", "server", server], directory / "traffic-server.log")
        time.sleep(.5)
        if workload.poll() is not None:
            raise RuntimeError("traffic server failed to start")
        if label == "icmp":
            execute(source_node, "ping", "-6" if p["ip_version"] == 6 else "-4", "-c", str(seconds), "-i", "0.2", server, timeout=seconds+15)
        else:
            execute(source_node, "python3", "/opt/lab/traffic.py", "client", server, "--label", label,
                    "--seconds", str(seconds), "--seed", str(seed), timeout=seconds+30)
        after = verify(p)
        (directory / "gateway-after.json").write_text(json.dumps(after, indent=2))
    finally:
        for node, proc, _, _ in captures:
            stop_capture(node, proc)
        if workload:
            execute(target_node, "pkill", "-f", "/opt/lab/traffic.py server", check=False)
            workload.wait(timeout=10)
        if p["mode"] == "transport":
            firewall = "ip6tables" if p["ip_version"] == 6 else "iptables"
            # Only our dedicated lab container's rules are reset.
            execute("left", firewall, "-t", "mangle", "-F", "OUTPUT", check=False)
    artifacts = []
    for path in sorted(directory.iterdir()):
        if path.suffix in {".pcap", ".json", ".log"}:
            artifacts.append({"path": path.name, "sha256": sha256(path), "bytes": path.stat().st_size})
    for name in ("left-outer.pcap", "right-outer.pcap", "inner.pcap"):
        if (directory / name).stat().st_size <= 24:
            raise RuntimeError(f"empty capture {name}; run not accepted")
    drops = {}
    for name in ("left-outer.log", "right-outer.log", "inner.log"):
        log = (directory / name).read_text()
        match = re.search(r"(\d+) packets dropped by kernel", log)
        if not match:
            raise RuntimeError("capture did not finalize cleanly; missing drop counter")
        drops[name] = int(match.group(1))
        if drops[name]:
            raise RuntimeError("capture has packet loss; run not accepted")
    manifest = {"schema": "ipsec-lab-run.v1", "run_id": run_id, "profile": p,
                "traffic_label": label, "label_source": "synthetic-generator", "seed": seed,
                "requested_duration_seconds": seconds, "created_at": datetime.now(timezone.utc).isoformat(),
                "actual_nat_present": False, "forced_udp_encapsulation": p["encap"],
                "dataset_role": "unassigned", "split_group_id": run_id,
                "capture_points": [{"node": n, "interface": i, "role": r} for n, _, i, r in captures],
                "packet_drops": drops, "artifacts": artifacts,
                "config_sha256": {side: hashlib.sha256(config(p, side, "REDACTED").encode()).hexdigest() for side in ("left", "right")},
                "package_versions": execute("left", "cat", "/opt/lab/versions.txt").stdout,
                "verification": {node: row["check"] for node, row in verified.items()}}
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(directory / "manifest.json")


def check_manifest(path):
    manifest = json.loads(path.read_text())
    if manifest.get("schema") != "ipsec-lab-run.v1":
        raise ValueError("unsupported manifest schema")
    for artifact in manifest["artifacts"]:
        candidate = (path.parent / artifact["path"]).resolve()
        if candidate.parent != path.parent.resolve() or sha256(candidate) != artifact["sha256"]:
            raise ValueError("artifact path or checksum mismatch")
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["up", "run", "verify", "down", "list", "check-manifest"])
    parser.add_argument("--profile", default="tunnel-v4-cbc128-pfs")
    parser.add_argument("--traffic", choices=LABELS, default="web")
    parser.add_argument("--seconds", type=int, default=10)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    if args.action == "list":
        print("\n".join(p.stem for p in sorted((ROOT / "profiles").glob("*.json"))))
        return
    if args.action == "check-manifest":
        check_manifest(args.manifest)
        print("All artifact checksums verified")
        return
    # Serializes operations across profiles; concurrent runs would mix captures.
    import fcntl
    (ROOT / "runtime").mkdir(exist_ok=True, mode=0o700)
    with (ROOT / "runtime/lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.action == "down":
            command(COMPOSE + ["down"])
            return
        p = profile(args.profile)
        if args.action == "up":
            setup(p)
        elif args.action == "verify":
            print(json.dumps(verify(p), indent=2))
        else:
            if not 1 <= args.seconds <= 300:
                raise ValueError("seconds must be between 1 and 300")
            run(p, args.traffic, args.seconds, args.seed)


if __name__ == "__main__":
    main()
