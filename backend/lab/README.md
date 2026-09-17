# Managed IPsec lab

The only active entry point is `scripts/managed.sh`. Backend activation invokes
its `activate` command; experiments invoke `generate` with validated settings.
It uses `compose.yaml`, five StrongSwan presets in `configs/`, and capture and
metadata helpers in `scripts/`. See [MANAGED_LAB.md](MANAGED_LAB.md) for operation.

`legacy-phase1/` preserves the earlier implementation. `legacy-reference-tools/`
preserves unused standalone batch utilities. They are not runtime dependencies.
Their historical relative paths are not supported entry points; use the managed
runner rather than invoking archived scripts directly.
Existing captures in `output/` and configuration snapshots in `runtime/` were
not removed. The original `ipsec-pcap-lab/` reference is unchanged.
