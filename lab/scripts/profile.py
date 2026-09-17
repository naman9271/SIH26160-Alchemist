#!/usr/bin/env python3
"""Validate Phase-1 profile files (JSON is valid YAML 1.2)."""
import json, pathlib, sys

REQUIRED = {"id", "ike_version", "mode", "address_family", "esp", "dh_group", "pfs", "nat_t", "traffic", "duration_seconds", "seed"}
VALUES = {"mode": {"tunnel", "transport"}, "address_family": {"ipv4", "ipv6"}, "traffic": {"web", "video", "voip", "email", "messaging", "icmp", "file_transfer"}}
def load(profile):
    value = json.loads(pathlib.Path(profile).read_text())
    missing = REQUIRED - value.keys()
    if missing: raise SystemExit("profile missing: " + ", ".join(sorted(missing)))
    for key, choices in VALUES.items():
        if value[key] not in choices: raise SystemExit(f"invalid {key}: {value[key]}")
    if value["ike_version"] != "IKEv2" or not isinstance(value["pfs"], bool) or value["duration_seconds"] < 1: raise SystemExit("invalid Phase-1 profile")
    return value
if __name__ == "__main__": print(json.dumps(load(sys.argv[1]), sort_keys=True))
