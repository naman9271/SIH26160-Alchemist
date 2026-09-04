# API connection audit

Checked against the protobuf contracts and the server registrations on 4 September 2026.

## Transport boundary

The browser is intentionally limited to the Next.js same-origin proxy at
`/api/core/*`. It must not call Go or Python gRPC directly. Go Core owns the
HTTP adapter and the Core process now registers all native Core and Sensor
gRPC services on `CORE_GRPC_ADDRESS` for trusted clients.

| Domain | Native service coverage | Browser connection |
|---|---|---|
| System and local-sensor status | Core System, LocalSensor; Sensor System | `GET /api/v1/system/overview`; Health and Gateway views |
| Offline PCAP input | Input upload, validation, source | `POST /api/v1/pcap`; Workspace view |
| Analysis lifecycle | Start, get, progress, summary, cancel/retry | Start/get through workflow routes; progress/summary in insights |
| Protocol read | sessions, IKE, SAs, crypto, NAT, timeline, evidence | `GET /api/v1/analyses/{id}/insights`; Sessions and Evidence views |
| Flow telemetry | flows, stats, feature windows, sequence sketch, stream | analysis-scoped flow records in `insights`; Flows view |
| ML orchestration | worker/model/status/predictions/explanations/cancel | worker, predictions, explanations in `insights`; Classification view |
| Fusion | run/status/summary/conclusions/evidence chain/recompute | status, summary, conclusions in `insights`; Evidence view |
| Security and risk | assessment/findings/recommendations/compliance; score/breakdown/overrides | assessment and risk data in `insights`; Findings and Risk views |
| Reports and artifacts | generate/get/download/delete/types; artifact lifecycle | executive PDF generate/poll/download workflow; report controls |
| Policy and runtime config | policy lifecycle and runtime config | trusted gRPC only (administrative writes are not browser exposed) |
| Live capture, VICI and XFRM | Sensor sessions/capture/network, VICI, XFRM, telemetry | trusted gRPC only; the dashboard shows real readiness but does not expose privileged control operations |
| Event/telemetry streams | Core events, capture stats, VICI events, feature/observation streams | trusted gRPC only; no unauthenticated browser stream is exposed |

## Safety decisions

The absence of a browser endpoint for an administrative or privileged gRPC
method is deliberate, not a missing connection. Live capture can require host
permissions; VICI and XFRM read local gateway/kernel state; policy/configuration
methods mutate global process state; and streams need authentication, ownership
checks and cancellation semantics. These remain connected through the registered
native gRPC server until an authenticated browser adapter is added.

## Dashboard data mapping

Every dashboard detail view reads its analysis-specific block from `insights`:
Overview (summary/security/risk/fusion), Progress, Sessions, Flows,
Classification, Evidence, Findings, and Risk. Health and Gateway also load the
new system overview without requiring an analysis ID. Empty blocks are rendered
as unavailable/no-capture-data rather than fabricated results.
