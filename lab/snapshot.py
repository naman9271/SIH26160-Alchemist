"""Read-only gateway snapshot. Never persist XFRM keys or VICI secrets."""
import json
import subprocess
from vici_read import Session


def clean(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, dict):
        return {str(clean(k)): clean(v) for k, v in value.items()
                if str(clean(k)).lower() not in {"key", "keys", "secret", "psk"}}
    if isinstance(value, (list, tuple)):
        return [clean(v) for v in value]
    return value


if __name__ == "__main__":
    session = Session()
    states = json.loads(subprocess.check_output(["ip", "-j", "-s", "xfrm", "state"]))
    policies = json.loads(subprocess.check_output(["ip", "-j", "xfrm", "policy"]))
    print(json.dumps(clean({"version": session.version(), "sas": list(session.list_sas()),
                            "states": states, "policies": policies})))
