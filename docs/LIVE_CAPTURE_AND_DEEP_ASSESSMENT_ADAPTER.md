# Live Capture and Deep Assessment adapter

## Purpose

The browser application currently supports offline PCAP analysis. Go Core already supports passive live capture and authorised Deep Assessment through trusted gRPC, but these controls must not be exposed directly to an unauthenticated browser: they can start packet capture on a host interface and read local VPN gateway state.

## Existing trusted services

The Go Core input service implements `ListInterfaces`, `StartLive` with `PASSIVE_LIVE` or `DEEP_ASSESSMENT`, and `StopLive`. Passive Live captures packet metadata through the configured capture engine; it does not decrypt ESP payloads. Deep Assessment is passive live capture enriched with read-only StrongSwan VICI and Linux XFRM telemetry.

Relevant implementation locations:

- `backend/src/internal/core/input/service.go`
- `backend/src/internal/transport/grpc/core/input_handler.go`
- `backend/src/internal/sensor/capture/`
- `backend/src/internal/sensor/session/service.go`

## Required browser adapter

Add a server-side HTTP/BFF adapter between the Next.js browser UI and Go Core gRPC. The adapter runs on an authorised capture host or trusted network zone; the browser must never connect to Core gRPC or local sockets directly.

| Browser endpoint | Trusted Core action | Required guard |
| --- | --- | --- |
| `GET /api/capture/interfaces` | `ListInterfaces` | Authenticated operator; return only capture-capable interfaces. |
| `POST /api/capture/live` | `StartLive(PASSIVE_LIVE)` | Authorised role, approved interface/filter/limits, audit record. |
| `POST /api/capture/:sourceId/stop` | `StopLive` | Capture owner or administrator, audit record. |
| `GET /api/capture/:sourceId` | Source/counter status | Capture owner or administrator. |
| `POST /api/capture/deep-assessment` | `StartLive(DEEP_ASSESSMENT)` | Live guards plus explicit consent and VICI/XFRM readiness. |

Do not accept arbitrary shell commands or unrestricted BPF expressions from the browser. Start with the built-in `IPSEC_ONLY` filter. If custom BPF is enabled later, validate it server-side against a small allow-list and record it in the audit trail.

## Live capture host requirements

1. Use Linux with a compatible local capture binary such as `tcpdump`; live capture is not supported from a remote browser or unprivileged container.
2. Grant the Go Core service account the minimum capture capabilities, such as `CAP_NET_RAW` and `CAP_NET_ADMIN`, rather than running the web process as root.
3. Allow only approved network interfaces and enforce maximum duration, byte limits, and a packet filter on every start.
4. Store saved PCAPs in a quota-controlled directory outside public web roots.
5. Authenticate operators, authorise capture actions, and audit start, stop, interface, filter, limits, and result identifiers.

## Deep Assessment requirements

Deep Assessment is for an authorised Linux/StrongSwan lab or approved gateway environment. It is read-only and must not alter IKE, CHILD SA, XFRM, routes, or firewall state.

1. Use a Linux host with StrongSwan and access to `charon.vici`, normally `unix:///var/run/charon.vici`.
2. Give the Go Core service account permission to read the VICI socket and query Linux XFRM Netlink state.
3. Require a live-capture-capable interface if packet evidence is collected.
4. Require explicit per-session operator consent naming the authorised target and purpose.
5. Probe VICI and XFRM before enabling the start control. Show unavailable status instead of inferring gateway facts.
6. Mark evidence `VERIFIED_GATEWAY` only in `DEEP_ASSESSMENT` mode with explicit gateway provenance.

For lab setup and sign-off evidence, see [DEEP_ASSESSMENT_LAB.md](./DEEP_ASSESSMENT_LAB.md).

## Recommended browser workflow

1. Request capabilities and approved interfaces from the adapter.
2. Let the operator choose Passive Live or Deep Assessment.
3. For Deep Assessment, require acknowledgement and show VICI/XFRM readiness before enabling start.
4. Submit interface, built-in filter, promiscuous-mode choice, duration, byte limit, and whether to save the PCAP.
5. Poll a protected status endpoint or use an authenticated server-sent-events bridge for counters and terminal state.
6. Stop capture, then start analysis using the returned source ID.
7. Display passive observations separately from gateway-verified evidence.

## Safe deployment checklist

- [ ] HTTPS, authenticated users, role-based authorisation, and action audit.
- [ ] Adapter reachable only from the approved frontend deployment.
- [ ] Go Core and capture engine use least-privilege permissions.
- [ ] Interface, filter, duration, and byte-limit policy is enforced server-side.
- [ ] Deep Assessment is limited to approved Linux/StrongSwan environments.
- [ ] Gateway evidence is shown only with explicit Deep Assessment provenance.
- [ ] ESP payload is never decrypted, stored, or displayed.

Until this adapter and its security controls are deployed, the frontend must continue to label Live Capture and Deep Assessment as adapter required.
