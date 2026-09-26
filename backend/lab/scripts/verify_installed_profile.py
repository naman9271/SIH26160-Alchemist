#!/usr/bin/env python3
"""Verify that StrongSwan installed the mode and algorithms requested by a profile."""

from __future__ import annotations

import re
import sys
from pathlib import Path


def compact(value: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", value.upper())


def require(haystack: str, alternatives: tuple[str, ...], description: str) -> None:
    if not any(compact(item) in haystack for item in alternatives):
        raise SystemExit(f"installed SA does not prove requested {description}: {alternatives}")


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_installed_profile.py PROFILE_CONFIG < statusall.txt")
    config = Path(sys.argv[1]).read_text(encoding="utf-8")
    status = compact(sys.stdin.read())
    if "INSTALLED" not in status:
        raise SystemExit("StrongSwan did not report an installed CHILD_SA")

    settings = {}
    for raw in config.splitlines():
        line = raw.strip()
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            settings[key.strip()] = value.strip().rstrip("!")

    require(status, (settings.get("type", "tunnel"),), "operating mode")
    ike = settings.get("ike", "")
    esp = settings.get("esp", "")
    combined = f"{ike}-{esp}".lower()
    if "aes128gcm" in combined:
        require(status, ("AES_GCM_16_128", "AESGCM16128"), "AES-128-GCM")
    elif "aes256gcm" in combined:
        require(status, ("AES_GCM_16_256", "AESGCM16256"), "AES-256-GCM")
    elif "aes128" in combined:
        require(status, ("AES_CBC_128", "AESCBC128"), "AES-128-CBC")
    elif "aes256" in combined:
        require(status, ("AES_CBC_256", "AESCBC256"), "AES-256-CBC")
    if "sha256" in esp and "gcm" not in esp:
        require(status, ("HMAC_SHA2_256", "HMACSHA2256"), "HMAC-SHA-256")
    if "sha384" in esp and "gcm" not in esp:
        require(status, ("HMAC_SHA2_384", "HMACSHA2384"), "HMAC-SHA-384")


if __name__ == "__main__":
    main()
