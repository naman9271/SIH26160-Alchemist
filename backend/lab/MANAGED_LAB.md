# Managed PCAP runner

The active frontend runner is `scripts/managed.sh`, invoked by Core using fixed
script arguments. Its `configs`, `generators`, `docker` and capture scripts derive from the repository's
`ipsec-pcap-lab/lab` implementation. The original Phase-1 scripts and profiles
are archived in `legacy-phase1` for historical reproducibility; unused reference
batch tools are archived in `legacy-reference-tools`. Neither archive is called
by the managed runtime. Existing `output` and `runtime` data are preserved.
The frontend no longer creates
synthetic JSON flow records.

The managed topology uses `managed-ipsec-left/right`, the Compose project
`alchemist-managed-lab`, and the isolated `172.31.0.0/24` and `fd00:31::/64`
network. Configurations and generators are built into the gateway image, avoiding
Docker host bind-mount paths that do not exist inside the backend container.

Five profile presets reproduce IKEv1/IKEv2, IPv4/IPv6, tunnel/transport, native
ESP/forced UDP4500 and the original suites, DH and PFS combinations. Forced
encapsulation does not claim real NAT. Seven known classes use the original
HTTP/HLS/RTP/SMTP/WebSocket/ICMP generators. Optional OOD and isolated anomaly
classes have separate metadata roles; optional protocol captures include IKE
negotiation before ESP traffic.

Each experiment has its own output directory, immutable PCAP filenames, CSV
metadata and JSON manifest. Capture runs on gateway eth0 with an outer IPsec
filter. Successful output must contain the expected native ESP or UDP4500,
nonzero packets and matching SHA256. `metadata.csv` contains generator parameters,
seeds, timestamps, actual packet statistics, versions and role labels.
Each capture clears its isolated gateway temporary file before starting tcpdump,
checks that the process started, and propagates its exit status. A failed capture
cannot silently reuse a previous profile's PCAP.

From the repository root:

```sh
make lab-up
make lab-run PROFILES=1,2 LABELS=icmp,web REPETITIONS=1
make lab-down
make lab-test
```

In Docker, Core runs `/opt/alchemist/lab/scripts/managed.sh` and persists its
results in the lab-data volume. The operator-configured Docker socket group must
match `DOCKER_GID` in `.env`. Activating the runtime sends actual build/process
stdout and stderr to the frontend runtime logs; capture logs are saved per run.
Jobs are serialized because they reconfigure shared gateways. Server restart
marks interrupted captures failed and requires reactivation. ZIP and file
downloads are limited to artifacts indexed for that experiment.
