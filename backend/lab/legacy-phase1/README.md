# Reproducible IPsec lab

The frontend uses the managed PCAP engine described in
[MANAGED_LAB.md](MANAGED_LAB.md). It imports the five-profile, seven-class
`ipsec-pcap-lab` generators, runs actual traffic capture, emits complete
`metadata.csv`, and supports OOD, anomaly and IKE validation selections.
Activate from the frontend or run `make lab-up`; capture a selected matrix with
`make lab-run PROFILES=1,2 LABELS=icmp,web REPETITIONS=1`.

The sections below document the retained historical Phase-1 scripts, which can
be invoked explicitly from the backend directory; they are not the frontend
runner. The current Make targets select the managed engine.

This lab generates authorised, labelled IPsec captures. It is isolated from
production analysis: protected-side captures are ground truth only and must
not be uploaded to the passive analyser.

Prerequisites: Docker Compose v2, a Linux Docker host, internet access to pull
`alpine:3.20.3`, and permission to grant `NET_ADMIN` to lab containers. No
Docker Hub login is required. Run `make lab-up`, then use a profile path:

```bash
cd backend
./lab/scripts/up.sh
./lab/scripts/run.sh lab/profiles/ikev2-tunnel-ipv4-aes128cbc-pfs14.yaml
./lab/scripts/verify.sh lab/profiles/ikev2-tunnel-ipv4-aes128cbc-pfs14.yaml
```

Each run writes `backend/lab/output/<run-id>/` containing `outer.pcap`, optional
protected-side ground truth, `gateway-state.txt`, and an immutable manifest.
The manifest includes configuration/capture SHA-256 values, packet counts,
timestamps, seed, suite, mode, and traffic label. Failed negotiation is never
captured as a successful sample.

The lab uses only synthetic request/response, HTTP, SMTP-like, ICMP, RTP-like,
and video-like streams. `messaging` is a traffic category; it never automates
or claims to identify WhatsApp.

## What each command does

1. `make lab-up` builds the repository-owned StrongSwan gateway image from
   pinned `alpine:3.20.3`, then starts left/right gateways and synthetic
   traffic endpoints on an isolated Docker network.
2. `make lab-verify PROFILE=...` validates the profile, confirms gateway
   containers are running, and refuses to proceed unless `swanctl --list-sas`
   reports an established/installed SA.
3. `make lab-run PROFILE=...` calls verification, starts an outer-interface
   capture for IKE, NAT-T, ESP, and AH, produces deterministic labelled
   traffic, snapshots gateway state, hashes each artifact, and writes the
   manifest.
4. `make lab-down` stops and removes lab containers and the isolated network.

## Generated artifacts

Each successful run creates `backend/lab/output/<profile>-<UTC timestamp>/`:

| File | Purpose |
| --- | --- |
| `outer.pcap` | Uploadable outer IPsec evidence capture: IKE, NAT-T, ESP, AH only. |
| `gateway-state.txt` | Read-only `swanctl --list-sas` ground-truth snapshot. |
| `manifest.json` | Profile, traffic label, suite, PFS, mode, capture point, hashes, timestamp, and ground-truth source. |
| `SHA256SUMS` | Integrity checks for the profile, PCAP, and state snapshot. |

`outer.pcap` is suitable for the analyser. Do not upload any future
protected-side capture: it may contain synthetic inner traffic and is retained
only as lab ground truth.

## Troubleshooting

- **`strongswan-swanctl: no such package`**: update this repository revision;
  the lab now installs `strongswan`, which provides `swanctl` on Alpine.
- **`pull access denied for alchemist-ipsec-lab-strongswan`**: update this
  revision and run `make lab-up`; the script builds before `up` and never pulls
  that local image name.
- **Alpine `temporary error`**: this is a registry/CDN/DNS issue. The gateway
  build retries three times; retry `make lab-up` after connectivity recovers.
- **SA not established**: inspect `docker compose -f backend/lab/compose.yaml logs
  left right`. `lab-run` intentionally refuses to produce a labelled capture.
- **`/usr/lib/ipsec/charon: not found`**: update this repository revision. The
  verified Alpine StrongSwan daemon location is `/usr/lib/strongswan/charon`.
