# IPsec Security Analyzer — Go Sensor Internal Contract Specification v1.0

> **Scope:** This document specifies **only the Go Sensor logical module** inside the one Go Server.  
> Go Backend / Security Engine and Evidence Fusion contracts are intentionally specified separately.
>
> **Transport:** internal Go calls in v1.  
> The Sensor is not a separately deployed service in the current architecture. The method names below define the internal capability surface that Go Core calls through interfaces, channels, and shared domain models. If the Sensor is extracted in a later release, these method names can be mapped to protobuf/gRPC without changing ownership semantics.
>
> **v1 deployment assumption:** no application authentication/database. The Sensor is expected to run on the analysis machine or IPsec gateway in a controlled environment. Production mTLS/RBAC can be added later.

---

# 1. Sensor responsibility

The Go Sensor is the **network observation and gateway telemetry plane**.

It has two operating modes:

## 1.1 Passive Analysis Mode

The Sensor sees only network traffic.

Supported inputs:

- Live network interface
- Uploaded PCAP / PCAPNG

The Sensor can observe or derive:

- IPv4 / IPv6
- IKE packets
- IKE version
- ESP
- AH
- NAT-T
- endpoint metadata
- IKE exchanges visible on the wire
- offered/selected cryptographic proposals when observable
- ESP/AH SPI values
- packet sequence information
- flow statistics
- packet size/timing/direction behaviour
- session timelines
- ML-ready feature windows

It must **not claim hidden information as verified**.

---

## 1.2 Deep Assessment / Sensor Mode

The Sensor is installed on or next to the IPsec gateway.

For StrongSwan it additionally connects locally to the **VICI** interface and, on Linux, the **XFRM** subsystem.

Deep Mode adds verified gateway-side information such as:

- active IKE SAs
- active CHILD SAs
- IKE version
- negotiated IKE cryptographic algorithms
- negotiated ESP algorithms
- DH group
- mode (Tunnel / Transport) when available
- SPIs
- byte/packet counters
- SA rekey timers
- SA lifetime information
- loaded connection definitions
- loaded policies
- supported algorithms
- IKE counters
- certificate / authority metadata
- daemon statistics
- kernel XFRM states
- kernel XFRM policies
- replay-window information where exposed by the kernel
- NAT encapsulation state
- async SA lifecycle events

**v1 Deep Mode is read-only.**

The Sensor must not:

- initiate an IKE SA
- terminate an IKE SA
- force a rekey
- modify StrongSwan configuration
- install/delete XFRM state
- modify firewall/network policy

Those may be considered separately for a lab/testbed controller, not for the assessment Sensor.

---

# 2. High-level Go Sensor architecture

```text
              GO SENSOR MODULE INSIDE ONE GO SERVER
┌────────────────────────────────────────────────────────────────┐
│                                                                │
│  SensorSystemService                                           │
│  SensorSessionService                                          │
│  NetworkInterfaceService                                       │
│                                                                │
│  PASSIVE MODE                                                  │
│  ├── PassiveCaptureService                                     │
│  ├── PcapIngestService                                         │
│  ├── ProtocolObservationService                                │
│  └── FlowTelemetryService                                      │
│                                                                │
│  DEEP ASSESSMENT                                               │
│  ├── StrongSwanViciService                                     │
│  └── KernelXfrmService                                         │
│                                                                │
│  CORE MODULE EXPORT                                            │
│  └── SensorTelemetryService                                    │
│                                                                │
│              In-memory session / flow / SA state               │
└────────────────────────────────────────────────────────────────┘
```

These services are internal Go interfaces, not process-boundary gRPC services
in v1. The frontend never calls them directly; it calls the Core external
gRPC services only.

---

# 3. Service catalogue

| # | Service | Purpose |
|---|---|---|
| 1 | `SensorSystemService` | Health, readiness, version, capabilities, runtime resource usage |
| 2 | `SensorSessionService` | Creates/stops/resets a Passive or Deep Assessment sensor session |
| 3 | `NetworkInterfaceService` | Discovers capture-capable interfaces and interface statistics |
| 4 | `PassiveCaptureService` | Starts/stops live packet capture and exposes capture telemetry |
| 5 | `PcapIngestService` | Uploads, validates, inspects, processes and removes PCAP/PCAPNG sources |
| 6 | `ProtocolObservationService` | Exposes passive IKE/ESP/AH/NAT-T/SPI/session observations |
| 7 | `FlowTelemetryService` | Exposes flows, aggregate statistics, ML feature windows and sequence sketches |
| 8 | `StrongSwanViciService` | Read-only Deep Assessment through StrongSwan VICI |
| 9 | `KernelXfrmService` | Read-only Linux kernel IPsec/XFRM ground truth |
| 10 | `SensorTelemetryService` | Unified snapshot/event/feature stream consumed by Go Backend |

---

# 4. Common conventions

## 4.1 IDs

All logical resources use opaque IDs.

Examples:

```text
sensor_session_id
capture_id
pcap_id
flow_id
protocol_event_id
ike_sa_id
child_sa_id
```

Recommended implementation: UUIDv7.

---

## 4.2 Timestamps

Use UTC `google.protobuf.Timestamp`.

Example:

```text
2026-08-27T14:32:08.511Z
```

---

## 4.3 Common modes

```protobuf
enum SensorMode {
  SENSOR_MODE_UNSPECIFIED = 0;
  PASSIVE_LIVE = 1;
  PASSIVE_PCAP = 2;
  DEEP_ASSESSMENT = 3;
}
```

`DEEP_ASSESSMENT` means:

```text
Passive network observation
        +
StrongSwan VICI telemetry when available
        +
Linux XFRM telemetry when available
```

---

## 4.4 Evidence status

Every security-relevant value emitted by the Sensor should identify how it was obtained.

```protobuf
enum EvidenceStatus {
  EVIDENCE_STATUS_UNSPECIFIED = 0;
  OBSERVED = 1;
  DERIVED = 2;
  VERIFIED_GATEWAY = 3;
  UNKNOWN = 4;
}
```

Examples:

| Value | Status |
|---|---|
| ESP SPI parsed from packet | `OBSERVED` |
| IKEv2 from packet header | `OBSERVED` |
| tunnel direction inferred from flow relationship | `DERIVED` |
| CHILD SA mode returned by VICI | `VERIFIED_GATEWAY` |
| unavailable PFS configuration | `UNKNOWN` |

---

## 4.5 Error semantics

Use these canonical status codes for internal errors and map them to gRPC
status codes at the Core external boundary when needed.

| Code | Example |
|---|---|
| `INVALID_ARGUMENT` | invalid interface / chunk index |
| `NOT_FOUND` | unknown capture / PCAP / flow |
| `ALREADY_EXISTS` | duplicate session creation |
| `FAILED_PRECONDITION` | capture already active |
| `RESOURCE_EXHAUSTED` | max PCAP size / flow capacity |
| `UNAVAILABLE` | VICI socket unavailable |
| `DEADLINE_EXCEEDED` | gateway telemetry timed out |
| `INTERNAL` | unexpected sensor failure |

Machine-readable error details should include an internal code such as:

```text
CAPTURE_ALREADY_RUNNING
INTERFACE_NOT_FOUND
INVALID_PCAP
VICI_UNAVAILABLE
VICI_PLUGIN_DISABLED
XFRM_UNAVAILABLE
SESSION_NOT_ACTIVE
```

---

# SERVICE 1 — SensorSystemService

Purpose: system lifecycle, health and capabilities.

```protobuf
service SensorSystemService {
  rpc Health(HealthRequest) returns (HealthResponse);
  rpc Readiness(ReadinessRequest) returns (ReadinessResponse);
  rpc GetVersion(GetVersionRequest) returns (GetVersionResponse);
  rpc GetCapabilities(GetCapabilitiesRequest) returns (GetCapabilitiesResponse);
  rpc GetRuntimeStats(GetRuntimeStatsRequest) returns (GetRuntimeStatsResponse);
}
```

---

## API 1.1 — Health

**Internal Method:** `SensorSystemService.Health`  
**Internal Call Shape:** Unary

### What it does

Checks whether the Go Sensor process is alive.

### Request

```json
{}
```

### Response

```json
{
  "status": "HEALTHY",
  "time": "2026-08-27T14:32:08.511Z"
}
```

### Possible status

```text
HEALTHY
DEGRADED
UNHEALTHY
```

---

## API 1.2 — Readiness

**Internal Method:** `SensorSystemService.Readiness`  
**Internal Call Shape:** Unary

### What it does

Checks whether the Sensor can actually accept a new acquisition session.

### Request

```json
{}
```

### Response

```json
{
  "ready": true,
  "capture_engine": "READY",
  "temp_storage": "READY",
  "protocol_engine": "READY",
  "vici": "AVAILABLE",
  "xfrm": "AVAILABLE"
}
```

`vici` and `xfrm` may be unavailable while Passive Mode remains ready.

---

## API 1.3 — GetVersion

**Internal Method:** `SensorSystemService.GetVersion`  
**Internal Call Shape:** Unary

### Request

```json
{}
```

### Response

```json
{
  "sensor_version": "1.0.0",
  "api_version": "sensor.v1",
  "build_commit": "abc1234",
  "go_version": "go1.xx",
  "os": "linux",
  "architecture": "amd64"
}
```

---

## API 1.4 — GetCapabilities

**Internal Method:** `SensorSystemService.GetCapabilities`  
**Internal Call Shape:** Unary

### What it does

Lets Go Core discover what this Sensor installation can do.

### Request

```json
{}
```

### Response

```json
{
  "passive_live": true,
  "passive_pcap": true,
  "deep_assessment": true,
  "ipv4": true,
  "ipv6": true,
  "ikev1": true,
  "ikev2": true,
  "esp": true,
  "ah": true,
  "nat_t": true,
  "vici": true,
  "xfrm": true,
  "feature_windows": true,
  "sequence_sketches": true
}
```

---

## API 1.5 — GetRuntimeStats

**Internal Method:** `SensorSystemService.GetRuntimeStats`  
**Internal Call Shape:** Unary

### What it does

Returns Sensor resource usage and pipeline pressure.

### Request

```json
{}
```

### Response

```json
{
  "uptime_seconds": 4321,
  "cpu_percent": 8.4,
  "rss_bytes": 71303168,
  "goroutines": 42,
  "active_flows": 1281,
  "packet_queue_depth": 128,
  "feature_queue_depth": 5,
  "temporary_disk_bytes": 107374182
}
```

---

# SERVICE 2 — SensorSessionService

Purpose: defines which mode the Sensor is currently operating in and owns the lifecycle of one sensor run.

```protobuf
service SensorSessionService {
  rpc CreateSession(CreateSensorSessionRequest) returns (SensorSession);
  rpc GetSession(GetSensorSessionRequest) returns (SensorSession);
  rpc StopSession(StopSensorSessionRequest) returns (StopSensorSessionResponse);
  rpc ResetSession(ResetSensorSessionRequest) returns (ResetSensorSessionResponse);
}
```

---

## API 2.1 — CreateSession

**Internal Method:** `SensorSessionService.CreateSession`  
**Internal Call Shape:** Unary

### What it does

Creates the logical Sensor session before a live capture, PCAP analysis or Deep Assessment begins.

### Request — Passive Live

```json
{
  "mode": "PASSIVE_LIVE",
  "name": "live-test-01"
}
```

### Request — Passive PCAP

```json
{
  "mode": "PASSIVE_PCAP",
  "name": "uploaded-pcap-01"
}
```

### Request — Deep Assessment

```json
{
  "mode": "DEEP_ASSESSMENT",
  "name": "gateway-assessment-01",
  "deep_options": {
    "enable_vici": true,
    "enable_xfrm": true
  }
}
```

### Response

```json
{
  "sensor_session_id": "sess-...",
  "mode": "DEEP_ASSESSMENT",
  "state": "READY",
  "created_at": "2026-08-27T14:35:00Z"
}
```

---

## API 2.2 — GetSession

**Internal Method:** `SensorSessionService.GetSession`  
**Internal Call Shape:** Unary

### Request

```json
{
  "sensor_session_id": "sess-..."
}
```

### Response

```json
{
  "sensor_session_id": "sess-...",
  "mode": "DEEP_ASSESSMENT",
  "state": "RUNNING",
  "capture_id": "cap-...",
  "created_at": "...",
  "started_at": "...",
  "last_activity_at": "..."
}
```

---

## API 2.3 — StopSession

**Internal Method:** `SensorSessionService.StopSession`  
**Internal Call Shape:** Unary

### What it does

Gracefully ends the session.

It must:

- stop capture
- finalize active flows
- flush final feature windows
- unsubscribe from VICI events
- finalize protocol events
- retain in-memory results until reset

### Request

```json
{
  "sensor_session_id": "sess-..."
}
```

### Response

```json
{
  "sensor_session_id": "sess-...",
  "state": "STOPPED",
  "ended_at": "..."
}
```

---

## API 2.4 — ResetSession

**Internal Method:** `SensorSessionService.ResetSession`  
**Internal Call Shape:** Unary

### What it does

Clears all ephemeral Sensor state.

### Clears

```text
capture state
PCAP metadata
flows
feature windows
protocol observations
passive SA observations
VICI snapshots
XFRM snapshots
event buffers
```

### Request

```json
{
  "sensor_session_id": "sess-...",
  "delete_temporary_files": true
}
```

### Response

```json
{
  "reset": true,
  "state": "EMPTY"
}
```

---

# SERVICE 3 — NetworkInterfaceService

Purpose: live-capture interface discovery.

```protobuf
service NetworkInterfaceService {
  rpc ListInterfaces(ListInterfacesRequest) returns (ListInterfacesResponse);
  rpc GetInterface(GetInterfaceRequest) returns (NetworkInterface);
  rpc GetInterfaceStats(GetInterfaceStatsRequest) returns (InterfaceStats);
}
```

---

## API 3.1 — ListInterfaces

**Internal Method:** `NetworkInterfaceService.ListInterfaces`  
**Internal Call Shape:** Unary

### Request

```json
{}
```

### Response

```json
{
  "interfaces": [
    {
      "name": "eth0",
      "index": 2,
      "mac_address": "00:11:22:33:44:55",
      "addresses": ["10.0.0.10/24"],
      "up": true,
      "loopback": false,
      "capture_supported": true
    }
  ]
}
```

---

## API 3.2 — GetInterface

**Internal Method:** `NetworkInterfaceService.GetInterface`  
**Internal Call Shape:** Unary

### Request

```json
{
  "interface_name": "eth0"
}
```

### Response

Full interface metadata.

---

## API 3.3 — GetInterfaceStats

**Internal Method:** `NetworkInterfaceService.GetInterfaceStats`  
**Internal Call Shape:** Unary

### Request

```json
{
  "interface_name": "eth0"
}
```

### Response

```json
{
  "rx_packets": 182393,
  "tx_packets": 152192,
  "rx_bytes": 91827381,
  "tx_bytes": 78122191,
  "rx_bytes_per_second": 4218381,
  "tx_bytes_per_second": 3183938
}
```

---

# SERVICE 4 — PassiveCaptureService

Purpose: live passive acquisition.

```protobuf
service PassiveCaptureService {
  rpc StartCapture(StartCaptureRequest) returns (StartCaptureResponse);
  rpc StopCapture(StopCaptureRequest) returns (StopCaptureResponse);
  rpc GetCaptureStatus(GetCaptureStatusRequest) returns (CaptureStatus);
  rpc GetCaptureStats(GetCaptureStatsRequest) returns (CaptureStats);
  rpc StreamCaptureStats(StreamCaptureStatsRequest) returns (stream CaptureStats);
  rpc UpdateCaptureFilter(UpdateCaptureFilterRequest) returns (UpdateCaptureFilterResponse);
}
```

---

## API 4.1 — StartCapture

**Internal Method:** `PassiveCaptureService.StartCapture`  
**Internal Call Shape:** Unary

### What it does

Starts live packet capture on a selected network interface.

### Request

```json
{
  "sensor_session_id": "sess-...",
  "interface_name": "eth0",
  "filter_mode": "IPSEC_ONLY",
  "custom_bpf": "",
  "promiscuous_mode": false,
  "save_pcap": false,
  "max_duration_seconds": 3600,
  "max_capture_bytes": 5368709120
}
```

### Filter modes

```text
IPSEC_ONLY
ALL_TRAFFIC
CUSTOM_BPF
```

### Response

```json
{
  "capture_id": "cap-...",
  "state": "STARTING",
  "started_at": "..."
}
```

---

## API 4.2 — StopCapture

**Internal Method:** `PassiveCaptureService.StopCapture`  
**Internal Call Shape:** Unary

### Request

```json
{
  "capture_id": "cap-..."
}
```

### Response

```json
{
  "capture_id": "cap-...",
  "state": "STOPPED",
  "packets_total": 1823818,
  "bytes_total": 3281938181,
  "ended_at": "..."
}
```

Idempotent.

---

## API 4.3 — GetCaptureStatus

**Internal Method:** `PassiveCaptureService.GetCaptureStatus`  
**Internal Call Shape:** Unary

### Request

```json
{
  "capture_id": "cap-..."
}
```

### Response

```json
{
  "state": "CAPTURING",
  "interface_name": "eth0",
  "started_at": "...",
  "duration_seconds": 121,
  "packet_drops": 0
}
```

---

## API 4.4 — GetCaptureStats

**Internal Method:** `PassiveCaptureService.GetCaptureStats`  
**Internal Call Shape:** Unary

### Response

```json
{
  "packets_total": 1823818,
  "bytes_total": 3281938181,
  "packets_per_second": 18421,
  "bytes_per_second": 8412881,
  "ike_packets": 42,
  "esp_packets": 1728181,
  "ah_packets": 0,
  "nat_t_packets": 1721921,
  "active_flows": 81,
  "active_vpn_sessions": 3,
  "packet_drops": 0
}
```

---

## API 4.5 — StreamCaptureStats

**Internal Method:** `PassiveCaptureService.StreamCaptureStats`  
**Internal Call Shape:** Server Streaming

### Request

```json
{
  "capture_id": "cap-...",
  "interval_ms": 1000
}
```

### Response stream

Repeated `CaptureStats` messages until:

- capture stops
- client cancels
- session resets

---

## API 4.6 — UpdateCaptureFilter

**Internal Method:** `PassiveCaptureService.UpdateCaptureFilter`  
**Internal Call Shape:** Unary

### Request

```json
{
  "capture_id": "cap-...",
  "filter_mode": "CUSTOM_BPF",
  "custom_bpf": "udp port 500 or udp port 4500 or proto 50 or proto 51"
}
```

### Response

```json
{
  "updated": true,
  "active_filter": "..."
}
```

If the capture backend cannot safely change filters while running, return `FAILED_PRECONDITION`.

---

# SERVICE 5 — PcapIngestService

Purpose: offline Passive Analysis from `.pcap` / `.pcapng`.

```protobuf
service PcapIngestService {
  rpc BeginUpload(BeginPcapUploadRequest) returns (BeginPcapUploadResponse);
  rpc UploadChunk(UploadPcapChunkRequest) returns (UploadPcapChunkResponse);
  rpc CompleteUpload(CompletePcapUploadRequest) returns (PcapSource);
  rpc ValidatePcap(ValidatePcapRequest) returns (ValidatePcapResponse);
  rpc GetPcapInfo(GetPcapInfoRequest) returns (PcapSource);
  rpc StartOfflineProcessing(StartOfflineProcessingRequest) returns (StartOfflineProcessingResponse);
  rpc GetOfflineProcessingStatus(GetOfflineProcessingStatusRequest) returns (OfflineProcessingStatus);
  rpc CancelOfflineProcessing(CancelOfflineProcessingRequest) returns (CancelOfflineProcessingResponse);
  rpc RemovePcap(RemovePcapRequest) returns (RemovePcapResponse);
}
```

---

## API 5.1 — BeginUpload

**Internal Method:** `PcapIngestService.BeginUpload`  
**Internal Call Shape:** Unary

### Request

```json
{
  "sensor_session_id": "sess-...",
  "filename": "unknown-vpn.pcapng",
  "expected_size_bytes": 918273812,
  "expected_sha256": "optional"
}
```

### Response

```json
{
  "upload_id": "upload-...",
  "recommended_chunk_size_bytes": 1048576,
  "max_file_size_bytes": 5368709120
}
```

---

## API 5.2 — UploadChunk

**Internal Method:** `PcapIngestService.UploadChunk`  
**Internal Call Shape:** Unary

### Request

```json
{
  "upload_id": "upload-...",
  "chunk_index": 0,
  "data": "<bytes>"
}
```

### Response

```json
{
  "chunk_index": 0,
  "accepted": true,
  "received_bytes_total": 1048576
}
```

Chunk writes must be idempotent.

---

## API 5.3 — CompleteUpload

**Internal Method:** `PcapIngestService.CompleteUpload`  
**Internal Call Shape:** Unary

### Request

```json
{
  "upload_id": "upload-..."
}
```

### What it validates

- expected size
- SHA-256 if supplied
- supported capture format
- file can be opened
- at least one readable packet exists

### Response

```json
{
  "pcap_id": "pcap-...",
  "filename": "unknown-vpn.pcapng",
  "size_bytes": 918273812,
  "sha256": "...",
  "state": "READY"
}
```

---

## API 5.4 — ValidatePcap

**Internal Method:** `PcapIngestService.ValidatePcap`  
**Internal Call Shape:** Unary

### Request

```json
{
  "pcap_id": "pcap-..."
}
```

### Response

```json
{
  "valid": true,
  "format": "PCAPNG",
  "link_type": "ETHERNET",
  "packet_count_estimate": 1823811,
  "first_packet_at": "...",
  "last_packet_at": "...",
  "preliminary": {
    "ipv4_seen": true,
    "ipv6_seen": false,
    "ike_seen": true,
    "esp_seen": true,
    "ah_seen": false,
    "nat_t_seen": true
  }
}
```

This is only a lightweight validation/pre-scan, not full analysis.

---

## API 5.5 — GetPcapInfo

**Internal Method:** `PcapIngestService.GetPcapInfo`  
**Internal Call Shape:** Unary

### Request

```json
{
  "pcap_id": "pcap-..."
}
```

### Response

PCAP metadata and validation status.

---

## API 5.6 — StartOfflineProcessing

**Internal Method:** `PcapIngestService.StartOfflineProcessing`  
**Internal Call Shape:** Unary

### What it does

Feeds packets from the PCAP into the exact same internal processing pipeline used by live capture.

### Request

```json
{
  "sensor_session_id": "sess-...",
  "pcap_id": "pcap-...",
  "processing_speed": "MAXIMUM"
}
```

### Response

```json
{
  "capture_id": "cap-offline-...",
  "state": "PROCESSING"
}
```

---

## API 5.7 — GetOfflineProcessingStatus

**Internal Method:** `PcapIngestService.GetOfflineProcessingStatus`  
**Internal Call Shape:** Unary

### Purpose

Reports progress while a PCAP/PCAPNG is being replayed through the Sensor
pipeline.

### Request

```json
{
  "capture_id": "cap-offline-..."
}
```

### Response

```json
{
  "capture_id": "cap-offline-...",
  "state": "PROCESSING",
  "packets_processed": 1823811,
  "bytes_processed": 918273812,
  "percent": 64,
  "current_packet_time": "...",
  "packet_drops": 0,
  "last_error": ""
}
```

---

## API 5.8 — CancelOfflineProcessing

**Internal Method:** `PcapIngestService.CancelOfflineProcessing`  
**Internal Call Shape:** Unary

### Purpose

Stops offline processing with Go context cancellation, finalizes any complete
flow windows, marks incomplete windows as cancelled, and preserves partial
diagnostic state until reset.

### Request

```json
{
  "capture_id": "cap-offline-...",
  "reason": "user_cancelled"
}
```

### Response

```json
{
  "capture_id": "cap-offline-...",
  "state": "CANCELLED"
}
```

---

## API 5.9 — RemovePcap

**Internal Method:** `PcapIngestService.RemovePcap`  
**Internal Call Shape:** Unary

### Request

```json
{
  "pcap_id": "pcap-..."
}
```

### Response

```json
{
  "removed": true
}
```

---

# SERVICE 6 — ProtocolObservationService

Purpose: passive network/protocol intelligence.

```protobuf
service ProtocolObservationService {
  rpc GetProtocolSummary(GetProtocolSummaryRequest) returns (ProtocolSummary);
  rpc ListVpnSessions(ListVpnSessionsRequest) returns (ListVpnSessionsResponse);
  rpc GetVpnSession(GetVpnSessionRequest) returns (VpnSession);
  rpc ListIkeExchanges(ListIkeExchangesRequest) returns (ListIkeExchangesResponse);
  rpc ListCryptoProposals(ListCryptoProposalsRequest) returns (ListCryptoProposalsResponse);
  rpc ListEspStreams(ListEspStreamsRequest) returns (ListEspStreamsResponse);
  rpc GetEspStream(GetEspStreamRequest) returns (EspStream);
  rpc ListAhStreams(ListAhStreamsRequest) returns (ListAhStreamsResponse);
  rpc ListSpis(ListSpisRequest) returns (ListSpisResponse);
  rpc GetNatTraversal(GetNatTraversalRequest) returns (NatTraversalSummary);
  rpc ListProtocolEvents(ListProtocolEventsRequest) returns (ListProtocolEventsResponse);
  rpc StreamProtocolEvents(StreamProtocolEventsRequest) returns (stream ProtocolEvent);
}
```

---

## API 6.1 — GetProtocolSummary

**Internal Method:** `ProtocolObservationService.GetProtocolSummary`  
**Internal Call Shape:** Unary

### Request

```json
{
  "sensor_session_id": "sess-..."
}
```

### Response

```json
{
  "ipsec_detected": true,
  "ike_detected": true,
  "ike_versions": [2],
  "esp_detected": true,
  "ah_detected": false,
  "nat_t_detected": true,
  "ipv4_detected": true,
  "ipv6_detected": false,
  "vpn_session_count": 2,
  "observed_spi_count": 4
}
```

---

## API 6.2 — ListVpnSessions

**Internal Method:** `ProtocolObservationService.ListVpnSessions`  
**Internal Call Shape:** Unary

### Request

```json
{
  "sensor_session_id": "sess-...",
  "page_size": 100,
  "page_token": ""
}
```

### Response per session

```json
{
  "session_id": "vpn-...",
  "initiator_address": "192.0.2.10",
  "responder_address": "198.51.100.20",
  "ike_version": 2,
  "first_seen": "...",
  "last_seen": "...",
  "esp_seen": true,
  "ah_seen": false,
  "nat_t_seen": true,
  "evidence_status": "OBSERVED"
}
```

---

## API 6.3 — GetVpnSession

**Internal Method:** `ProtocolObservationService.GetVpnSession`  
**Internal Call Shape:** Unary

### Request

```json
{
  "session_id": "vpn-..."
}
```

### Response

Detailed passive session including associated:

- IKE exchanges
- observed SPIs
- passive SA observations
- endpoint metadata
- protocol counters

---

## API 6.4 — ListIkeExchanges

**Internal Method:** `ProtocolObservationService.ListIkeExchanges`  
**Internal Call Shape:** Unary

### Filters

```text
session_id
exchange_type
initiator/responder
time range
```

### Response fields

```text
exchange_id
IKE version
exchange type
message ID
initiator SPI
responder SPI
encrypted flag
timestamp
```

Possible exchange types include:

```text
IKE_SA_INIT
IKE_AUTH
CREATE_CHILD_SA
INFORMATIONAL
```

when observable.

---

## API 6.5 — ListCryptoProposals

**Internal Method:** `ProtocolObservationService.ListCryptoProposals`  
**Internal Call Shape:** Unary

### Response

```json
{
  "proposals": [
    {
      "proposal_number": 1,
      "protocol": "IKE",
      "encryption_algorithm": "AES_GCM_16",
      "key_length_bits": 256,
      "integrity_algorithm": "",
      "prf_algorithm": "PRF_HMAC_SHA2_256",
      "dh_group": "CURVE_25519",
      "selection_state": "SELECTED",
      "evidence_status": "OBSERVED"
    }
  ]
}
```

---

## API 6.6 — ListEspStreams

**Internal Method:** `ProtocolObservationService.ListEspStreams`  
**Internal Call Shape:** Unary

### Response fields

```text
stream_id
source address
destination address
SPI
packet count
byte count
first seen
last seen
sequence minimum
sequence maximum
suspected replay/duplicate observations
```

Do not claim the ESP cipher from ESP packets alone unless verified via observable IKE or Deep Mode telemetry.

---

## API 6.7 — GetEspStream

**Internal Method:** `ProtocolObservationService.GetEspStream`  
**Internal Call Shape:** Unary

Detailed view for one ESP SPI/direction stream.

---

## API 6.8 — ListAhStreams

**Internal Method:** `ProtocolObservationService.ListAhStreams`  
**Internal Call Shape:** Unary

Same concept as ESP stream API for AH.

---

## API 6.9 — ListSpis

**Internal Method:** `ProtocolObservationService.ListSpis`  
**Internal Call Shape:** Unary

### Response

```json
{
  "items": [
    {
      "spi": "0xc8931e89",
      "protocol": "ESP",
      "direction": "INBOUND",
      "first_seen": "...",
      "last_seen": "...",
      "session_id": "vpn-..."
    }
  ]
}
```

---

## API 6.10 — GetNatTraversal

**Internal Method:** `ProtocolObservationService.GetNatTraversal`  
**Internal Call Shape:** Unary

### Response

```json
{
  "nat_t_detected": true,
  "udp_4500_seen": true,
  "encapsulated_esp_seen": true,
  "nat_detection_payload_seen": true,
  "evidence_status": "OBSERVED"
}
```

---

## API 6.11 — ListProtocolEvents

**Internal Method:** `ProtocolObservationService.ListProtocolEvents`  
**Internal Call Shape:** Unary

### Filters

```text
IKE
ESP
AH
NAT_T
SPI
SESSION
ERROR
time range
```

---

## API 6.12 — StreamProtocolEvents

**Internal Method:** `ProtocolObservationService.StreamProtocolEvents`  
**Internal Call Shape:** Server Streaming

### What it emits

Examples:

```text
IPSEC_DETECTED
IKE_DETECTED
IKE_EXCHANGE_OBSERVED
ESP_SPI_DISCOVERED
AH_SPI_DISCOVERED
NAT_T_DETECTED
VPN_SESSION_CREATED
VPN_SESSION_UPDATED
POSSIBLE_REPLAY_OBSERVED
```

---

# SERVICE 7 — FlowTelemetryService

Purpose: network-flow aggregation and future ML input.

```protobuf
service FlowTelemetryService {
  rpc ListFlows(ListFlowsRequest) returns (ListFlowsResponse);
  rpc GetFlow(GetFlowRequest) returns (Flow);
  rpc GetFlowStats(GetFlowStatsRequest) returns (FlowStats);
  rpc ListFeatureWindows(ListFeatureWindowsRequest) returns (ListFeatureWindowsResponse);
  rpc GetFeatureWindow(GetFeatureWindowRequest) returns (FeatureWindow);
  rpc GetSequenceSketch(GetSequenceSketchRequest) returns (SequenceSketch);
  rpc StreamFeatureWindows(StreamFeatureWindowsRequest) returns (stream FeatureWindow);
}
```

---

## API 7.1 — ListFlows

**Internal Method:** `FlowTelemetryService.ListFlows`  
**Internal Call Shape:** Unary

### Filters

```text
session_id
protocol
SPI
source address
destination address
active/inactive
```

### Response fields

```text
flow_id
session_id
protocol
src/dst
SPI
first_seen
last_seen
packet_count
byte_count
active
```

---

## API 7.2 — GetFlow

**Internal Method:** `FlowTelemetryService.GetFlow`  
**Internal Call Shape:** Unary

### Response

Detailed flow identity and aggregate statistics.

---

## API 7.3 — GetFlowStats

**Internal Method:** `FlowTelemetryService.GetFlowStats`  
**Internal Call Shape:** Unary

### Response

```json
{
  "packet_count": 824,
  "byte_count": 923812,
  "duration_ms": 18420,
  "min_packet_size": 62,
  "max_packet_size": 1420,
  "mean_packet_size": 1121.7,
  "packet_size_stddev": 388.1,
  "forward_packets": 143,
  "reverse_packets": 681,
  "forward_bytes": 49302,
  "reverse_bytes": 874510,
  "mean_interarrival_us": 23110,
  "interarrival_stddev_us": 63011,
  "burst_count": 14,
  "mean_burst_packets": 48.1,
  "idle_period_count": 5,
  "mean_idle_ms": 720
}
```

---

## API 7.4 — ListFeatureWindows

**Internal Method:** `FlowTelemetryService.ListFeatureWindows`  
**Internal Call Shape:** Unary

### Request

```json
{
  "flow_id": "flow-...",
  "page_size": 100
}
```

### Response

Window summaries:

```text
window_id
window start
window end
feature_schema_version
sequence_schema_version when present
packet count
finalized/pending
eviction_reason when finalized by idle timeout or memory pressure
```

---

## API 7.5 — GetFeatureWindow

**Internal Method:** `FlowTelemetryService.GetFeatureWindow`  
**Internal Call Shape:** Unary

### Response

Exact ML-ready feature vector.

Mandatory field:

```text
feature_schema_version = "flow.v1"
```

The future ML Worker must reject incompatible feature versions.

Feature windows must include stable ordered feature names, numeric values,
normalization profile, direction convention, window duration, packet count,
flow/session IDs, and a finalized flag. Pending windows are visible for
debugging but must not be sent to ML inference.

---

## API 7.6 — GetSequenceSketch

**Internal Method:** `FlowTelemetryService.GetSequenceSketch`  
**Internal Call Shape:** Unary

### What it does

Returns the compact packet-sequence representation for future TCN/1D-CNN inference.

### Response example

```json
{
  "flow_id": "flow-...",
  "window_id": "window-...",
  "sequence_schema_version": "sequence.v1",
  "packets": [
    {"signed_size": 82, "delta_time_us": 0},
    {"signed_size": -1412, "delta_time_us": 8432},
    {"signed_size": -1398, "delta_time_us": 4201}
  ]
}
```

No raw payload bytes are returned.

---

## API 7.7 — StreamFeatureWindows

**Internal Method:** `FlowTelemetryService.StreamFeatureWindows`  
**Internal Call Shape:** Server Streaming

### Purpose

Primary future low-latency feed to the Go Backend / ML orchestration path.

Emits finalized feature windows as soon as they are ready.

The stream must use bounded channels. If the downstream consumer is too slow,
the Sensor should apply the configured backpressure policy:

```text
BLOCK_CAPTURE
DROP_FEATURE_WINDOW
CANCEL_SESSION
```

Dropped windows must emit a `SENSOR_WARNING` with counts and reason codes.

---

# SERVICE 8 — StrongSwanViciService

Purpose: **Deep Assessment** of a StrongSwan gateway through VICI.

> VICI should be accessed locally through the StrongSwan UNIX socket where possible.  
> VICI itself does not provide authentication/security, so the raw VICI socket should not be exposed over an untrusted network.

```protobuf
service StrongSwanViciService {
  rpc Probe(ProbeViciRequest) returns (ProbeViciResponse);
  rpc GetCapabilities(GetViciCapabilitiesRequest) returns (ViciCapabilities);
  rpc GetDaemonStats(GetDaemonStatsRequest) returns (ViciDaemonStats);
  rpc ListIkeSas(ListIkeSasRequest) returns (ListIkeSasResponse);
  rpc GetIkeSa(GetIkeSaRequest) returns (IkeSa);
  rpc ListChildSas(ListChildSasRequest) returns (ListChildSasResponse);
  rpc GetChildSa(GetChildSaRequest) returns (ChildSa);
  rpc ListConnections(ListConnectionsRequest) returns (ListConnectionsResponse);
  rpc GetConnection(GetConnectionRequest) returns (StrongSwanConnection);
  rpc ListPolicies(ListViciPoliciesRequest) returns (ListViciPoliciesResponse);
  rpc ListAlgorithms(ListAlgorithmsRequest) returns (ListAlgorithmsResponse);
  rpc GetCounters(GetCountersRequest) returns (ViciCounters);
  rpc ListCertificates(ListCertificatesRequest) returns (ListCertificatesResponse);
  rpc ListAuthorities(ListAuthoritiesRequest) returns (ListAuthoritiesResponse);
  rpc GetGatewaySnapshot(GetGatewaySnapshotRequest) returns (GatewaySnapshot);
  rpc StreamEvents(StreamViciEventsRequest) returns (stream ViciEvent);
}
```

---

## API 8.1 — Probe

**Internal Method:** `StrongSwanViciService.Probe`  
**Internal Call Shape:** Unary

### What it does

Tests whether the StrongSwan VICI plugin/socket is available.

### Request

```json
{
  "socket_uri": "unix:///var/run/charon.vici"
}
```

### Response

```json
{
  "available": true,
  "socket_uri": "unix:///var/run/charon.vici",
  "charon_reachable": true
}
```

---

## API 8.2 — GetCapabilities

**Internal Method:** `StrongSwanViciService.GetCapabilities`  
**Internal Call Shape:** Unary

### Response

Which read-only operations are supported on the installed StrongSwan build.

Example:

```json
{
  "list_sas": true,
  "list_connections": true,
  "list_policies": true,
  "list_algorithms": true,
  "stats": true,
  "counters": true,
  "list_certificates": true,
  "list_authorities": true,
  "events": true
}
```

---

## API 8.3 — GetDaemonStats

**Internal Method:** `StrongSwanViciService.GetDaemonStats`  
**Internal Call Shape:** Unary

### Response

```json
{
  "uptime_seconds": 3828,
  "worker_threads_total": 16,
  "worker_threads_idle": 11,
  "ike_sa_total": 2,
  "ike_sa_half_open": 0,
  "loaded_plugins": [
    "vici",
    "kernel-netlink",
    "openssl"
  ]
}
```

---

## API 8.4 — ListIkeSas

**Internal Method:** `StrongSwanViciService.ListIkeSas`  
**Internal Call Shape:** Unary

### Request filters

```text
IKE name
IKE unique ID
state
```

### Response per IKE SA

```text
name
unique ID
state
IKE version
local host/port
remote host/port
local identity
remote identity
initiator flag
initiator SPI
responder SPI
encryption algorithm
encryption key size
integrity algorithm
PRF
DH group
established duration
rekey time
reauth time when available
associated CHILD SAs
```

All values returned from VICI receive:

```text
evidence_status = VERIFIED_GATEWAY
```

---

## API 8.5 — GetIkeSa

**Internal Method:** `StrongSwanViciService.GetIkeSa`  
**Internal Call Shape:** Unary

### Request

```json
{
  "ike_unique_id": 1
}
```

### Response

Complete normalized IKE SA representation.

---

## API 8.6 — ListChildSas

**Internal Method:** `StrongSwanViciService.ListChildSas`  
**Internal Call Shape:** Unary

### Response per CHILD SA

```text
name
unique ID
reqid
state
mode
protocol
SPI in
SPI out
encryption algorithm
key length
integrity algorithm
bytes in/out
packets in/out
install time
rekey time
life time
local traffic selectors
remote traffic selectors
```

---

## API 8.7 — GetChildSa

**Internal Method:** `StrongSwanViciService.GetChildSa`  
**Internal Call Shape:** Unary

Detailed normalized CHILD SA.

---

## API 8.8 — ListConnections

**Internal Method:** `StrongSwanViciService.ListConnections`  
**Internal Call Shape:** Unary

### What it does

Returns loaded StrongSwan connection configurations.

Useful for:

- configured IKE version
- authentication methods
- proposal policy
- CHILD definitions
- traffic selectors
- configured lifetimes
- configured rekey options
- configured PFS/key-exchange policy where available

---

## API 8.9 — GetConnection

**Internal Method:** `StrongSwanViciService.GetConnection`  
**Internal Call Shape:** Unary

Returns one normalized configured connection.

---

## API 8.10 — ListPolicies

**Internal Method:** `StrongSwanViciService.ListPolicies`  
**Internal Call Shape:** Unary

Returns installed StrongSwan policies when supported.

---

## API 8.11 — ListAlgorithms

**Internal Method:** `StrongSwanViciService.ListAlgorithms`  
**Internal Call Shape:** Unary

### Response

Algorithms and their implementations loaded by the gateway.

Useful for distinguishing:

```text
configured/negotiated algorithm
vs
algorithm supported by gateway
```

---

## API 8.12 — GetCounters

**Internal Method:** `StrongSwanViciService.GetCounters`  
**Internal Call Shape:** Unary

### Request

```json
{
  "connection_name": "",
  "all_connections": true
}
```

### Response example categories

```text
IKE rekey initiations/responses
CHILD rekeys
invalid IKE messages
other available counters
```

If the StrongSwan counters plugin is not loaded, return:

```text
UNAVAILABLE / COUNTERS_PLUGIN_UNAVAILABLE
```

---

## API 8.13 — ListCertificates

**Internal Method:** `StrongSwanViciService.ListCertificates`  
**Internal Call Shape:** Unary

### Purpose

Provides certificate metadata relevant to authentication assessment.

Do not return private keys.

Fields may include:

```text
certificate type
subject
issuer
valid from
valid until
fingerprint
public-key type
```

---

## API 8.14 — ListAuthorities

**Internal Method:** `StrongSwanViciService.ListAuthorities`  
**Internal Call Shape:** Unary

Returns loaded authority metadata when available.

---

## API 8.15 — GetGatewaySnapshot

**Internal Method:** `StrongSwanViciService.GetGatewaySnapshot`  
**Internal Call Shape:** Unary

### Purpose

Creates one atomic-ish normalized Deep Assessment snapshot for the Go Core/Fusion layer.

### Response contains

```text
daemon stats
IKE SAs
CHILD SAs
loaded connections
loaded policies
supported algorithms
IKE counters
certificate metadata
authority metadata
snapshot timestamp
individual source availability
```

This is one of the most important Deep Assessment methods.

---

## API 8.16 — StreamEvents

**Internal Method:** `StrongSwanViciService.StreamEvents`  
**Internal Call Shape:** Server Streaming

### Purpose

Streams StrongSwan asynchronous lifecycle information.

Normalize events such as:

```text
IKE SA created
IKE SA updated
IKE SA deleted
CHILD SA established
CHILD SA deleted
CHILD SA rekeyed
authentication-related events when available
```

Do not expose raw VICI protocol messages directly to the frontend.

---

# SERVICE 9 — KernelXfrmService

Purpose: Deep Assessment of the Linux kernel IPsec Security Association Database / Security Policy Database.

The implementation should preferably use **netlink**, not parse shell command text.

```protobuf
service KernelXfrmService {
  rpc GetCapabilities(GetXfrmCapabilitiesRequest) returns (XfrmCapabilities);
  rpc ListStates(ListXfrmStatesRequest) returns (ListXfrmStatesResponse);
  rpc GetState(GetXfrmStateRequest) returns (XfrmState);
  rpc ListPolicies(ListXfrmPoliciesRequest) returns (ListXfrmPoliciesResponse);
  rpc GetReplayProtection(GetReplayProtectionRequest) returns (ReplayProtection);
  rpc GetKernelSnapshot(GetKernelSnapshotRequest) returns (KernelSnapshot);
}
```

---

## API 9.1 — GetCapabilities

**Internal Method:** `KernelXfrmService.GetCapabilities`  
**Internal Call Shape:** Unary

### Response

```json
{
  "available": true,
  "state_query": true,
  "policy_query": true,
  "replay_information": true
}
```

---

## API 9.2 — ListStates

**Internal Method:** `KernelXfrmService.ListStates`  
**Internal Call Shape:** Unary

### Response per state

```text
source
destination
protocol
SPI
reqid
mode
direction where available
encryption / AEAD metadata
authentication metadata
encapsulation metadata
replay window
sequence information
lifetime limits
statistics where available
```

Private cryptographic key material must never be exposed through this API.

---

## API 9.3 — GetState

**Internal Method:** `KernelXfrmService.GetState`  
**Internal Call Shape:** Unary

### Request

```json
{
  "source": "192.0.2.10",
  "destination": "198.51.100.20",
  "protocol": "ESP",
  "spi": "0xc8931e89"
}
```

### Response

Detailed sanitized XFRM state.

---

## API 9.4 — ListPolicies

**Internal Method:** `KernelXfrmService.ListPolicies`  
**Internal Call Shape:** Unary

### Response

```text
direction
selectors
priority
templates
reqid
mode
protocol
source/destination templates
```

---

## API 9.5 — GetReplayProtection

**Internal Method:** `KernelXfrmService.GetReplayProtection`  
**Internal Call Shape:** Unary

### Purpose

Retrieves replay-protection information for an installed kernel SA where available.

### Request

```json
{
  "protocol": "ESP",
  "spi": "0xc8931e89",
  "destination": "198.51.100.20"
}
```

### Response

```json
{
  "available": true,
  "enabled": true,
  "replay_window": 32,
  "sequence": 18281,
  "extended_sequence_numbers": false,
  "evidence_status": "VERIFIED_GATEWAY"
}
```

If a reliable value is not exposed, return `available=false`; do not guess.

---

## API 9.6 — GetKernelSnapshot

**Internal Method:** `KernelXfrmService.GetKernelSnapshot`  
**Internal Call Shape:** Unary

### Response

Normalized snapshot containing:

```text
all sanitized XFRM states
all policies
replay metadata
snapshot timestamp
```

This is the kernel-side counterpart to `StrongSwanViciService.GetGatewaySnapshot`.

---

# SERVICE 10 — SensorTelemetryService

Purpose: provides the **single normalized Sensor -> Go Core interface**.

The Go Core module should not have to individually poll 30 Sensor methods during live analysis.

```protobuf
service SensorTelemetryService {
  rpc GetSnapshot(GetSensorSnapshotRequest) returns (SensorSnapshot);
  rpc StreamObservations(StreamObservationsRequest) returns (stream SensorObservation);
  rpc StreamFeatureWindows(StreamSensorFeatureWindowsRequest) returns (stream FeatureWindow);
  rpc AcknowledgeCheckpoint(AcknowledgeCheckpointRequest) returns (AcknowledgeCheckpointResponse);
}
```

---

## API 10.1 — GetSnapshot

**Internal Method:** `SensorTelemetryService.GetSnapshot`  
**Internal Call Shape:** Unary

### What it does

Returns a consolidated current Sensor snapshot.

### Request

```json
{
  "sensor_session_id": "sess-...",
  "include": {
    "protocol_summary": true,
    "flows": true,
    "deep_vici": true,
    "deep_xfrm": true
  }
}
```

### Response concept

```json
{
  "sensor_session": {},
  "capture": {},
  "protocol_summary": {},
  "vpn_sessions": [],
  "flow_summary": {},
  "vici_snapshot": {},
  "xfrm_snapshot": {},
  "generated_at": "..."
}
```

Large detailed lists should remain paginated in their specific services.

---

## API 10.2 — StreamObservations

**Internal Method:** `SensorTelemetryService.StreamObservations`  
**Internal Call Shape:** Server Streaming

### Purpose

Main low-latency live stream to Go Core.

### Request

```json
{
  "sensor_session_id": "sess-...",
  "include_protocol_events": true,
  "include_capture_stats": true,
  "include_vici_events": true,
  "include_xfrm_updates": true
}
```

### Normalized event types

```text
CAPTURE_STARTED
CAPTURE_STATS
CAPTURE_STOPPED

IPSEC_DETECTED
IKE_EXCHANGE
ESP_SPI_DISCOVERED
AH_SPI_DISCOVERED
NAT_T_DETECTED
VPN_SESSION_UPDATE

FLOW_CREATED
FLOW_UPDATED
FLOW_FINALIZED

VICI_IKE_SA_UPDATE
VICI_CHILD_SA_UPDATE
VICI_SA_DELETED

XFRM_STATE_UPDATE

SENSOR_WARNING
SENSOR_ERROR
```

---

## API 10.3 — StreamFeatureWindows

**Internal Method:** `SensorTelemetryService.StreamFeatureWindows`  
**Internal Call Shape:** Server Streaming

### Purpose

Dedicated fast path for finalized ML feature windows.

This allows Go Core to:

```text
Sensor
   ↓ feature window
Go Core ML orchestration
   ↓ gRPC process boundary
Python ML Worker
```

without waiting for the whole capture.

### Response

```text
flow_id
window_id
feature_schema_version
feature vector
optional sequence sketch reference/data
window start/end
```

---

## API 10.4 — AcknowledgeCheckpoint

**Internal Method:** `SensorTelemetryService.AcknowledgeCheckpoint`  
**Internal Call Shape:** Unary

### Purpose

Allows Go Core to acknowledge the latest processed telemetry sequence number.

Useful for future reconnect/resume support.

### Request

```json
{
  "sensor_session_id": "sess-...",
  "last_processed_sequence": 18281
}
```

### Response

```json
{
  "acknowledged": true
}
```

For a simple local SIH deployment this can initially be a no-op while preserving the contract.

---

# 5. Internal method inventory summary

## SensorSystemService

```text
SensorSystemService.Health
SensorSystemService.Readiness
SensorSystemService.GetVersion
SensorSystemService.GetCapabilities
SensorSystemService.GetRuntimeStats
```

**5 methods**

---

## SensorSessionService

```text
SensorSessionService.CreateSession
SensorSessionService.GetSession
SensorSessionService.StopSession
SensorSessionService.ResetSession
```

**4 methods**

---

## NetworkInterfaceService

```text
NetworkInterfaceService.ListInterfaces
NetworkInterfaceService.GetInterface
NetworkInterfaceService.GetInterfaceStats
```

**3 methods**

---

## PassiveCaptureService

```text
PassiveCaptureService.StartCapture
PassiveCaptureService.StopCapture
PassiveCaptureService.GetCaptureStatus
PassiveCaptureService.GetCaptureStats
PassiveCaptureService.StreamCaptureStats
PassiveCaptureService.UpdateCaptureFilter
```

**6 methods**

---

## PcapIngestService

```text
PcapIngestService.BeginUpload
PcapIngestService.UploadChunk
PcapIngestService.CompleteUpload
PcapIngestService.ValidatePcap
PcapIngestService.GetPcapInfo
PcapIngestService.StartOfflineProcessing
PcapIngestService.GetOfflineProcessingStatus
PcapIngestService.CancelOfflineProcessing
PcapIngestService.RemovePcap
```

**9 methods**

---

## ProtocolObservationService

```text
ProtocolObservationService.GetProtocolSummary
ProtocolObservationService.ListVpnSessions
ProtocolObservationService.GetVpnSession
ProtocolObservationService.ListIkeExchanges
ProtocolObservationService.ListCryptoProposals
ProtocolObservationService.ListEspStreams
ProtocolObservationService.GetEspStream
ProtocolObservationService.ListAhStreams
ProtocolObservationService.ListSpis
ProtocolObservationService.GetNatTraversal
ProtocolObservationService.ListProtocolEvents
ProtocolObservationService.StreamProtocolEvents
```

**12 methods**

---

## FlowTelemetryService

```text
FlowTelemetryService.ListFlows
FlowTelemetryService.GetFlow
FlowTelemetryService.GetFlowStats
FlowTelemetryService.ListFeatureWindows
FlowTelemetryService.GetFeatureWindow
FlowTelemetryService.GetSequenceSketch
FlowTelemetryService.StreamFeatureWindows
```

**7 methods**

---

## StrongSwanViciService

```text
StrongSwanViciService.Probe
StrongSwanViciService.GetCapabilities
StrongSwanViciService.GetDaemonStats
StrongSwanViciService.ListIkeSas
StrongSwanViciService.GetIkeSa
StrongSwanViciService.ListChildSas
StrongSwanViciService.GetChildSa
StrongSwanViciService.ListConnections
StrongSwanViciService.GetConnection
StrongSwanViciService.ListPolicies
StrongSwanViciService.ListAlgorithms
StrongSwanViciService.GetCounters
StrongSwanViciService.ListCertificates
StrongSwanViciService.ListAuthorities
StrongSwanViciService.GetGatewaySnapshot
StrongSwanViciService.StreamEvents
```

**16 methods**

---

## KernelXfrmService

```text
KernelXfrmService.GetCapabilities
KernelXfrmService.ListStates
KernelXfrmService.GetState
KernelXfrmService.ListPolicies
KernelXfrmService.GetReplayProtection
KernelXfrmService.GetKernelSnapshot
```

**6 methods**

---

## SensorTelemetryService

```text
SensorTelemetryService.GetSnapshot
SensorTelemetryService.StreamObservations
SensorTelemetryService.StreamFeatureWindows
SensorTelemetryService.AcknowledgeCheckpoint
```

**4 methods**

---

# 6. Total Go Sensor v1 API surface

| Service | Method Count |
|---|---:|
| SensorSystemService | 5 |
| SensorSessionService | 4 |
| NetworkInterfaceService | 3 |
| PassiveCaptureService | 6 |
| PcapIngestService | 9 |
| ProtocolObservationService | 12 |
| FlowTelemetryService | 7 |
| StrongSwanViciService | 16 |
| KernelXfrmService | 6 |
| SensorTelemetryService | 4 |
| **Total** | **72 internal methods** |

This is the **complete product contract**, not the recommended first coding milestone.

---

# 7. Internal methods by operating mode

## Passive Live Mode

Primary runtime calls:

```text
SensorSystemService.Readiness
SensorSessionService.CreateSession
NetworkInterfaceService.ListInterfaces
PassiveCaptureService.StartCapture
SensorTelemetryService.StreamObservations
SensorTelemetryService.StreamFeatureWindows
PassiveCaptureService.StopCapture
SensorSessionService.StopSession
```

Supporting read methods:

```text
ProtocolObservationService.*
FlowTelemetryService.*
```

---

## Passive PCAP Mode

Primary runtime calls:

```text
SensorSessionService.CreateSession
PcapIngestService.BeginUpload
PcapIngestService.UploadChunk
PcapIngestService.CompleteUpload
PcapIngestService.ValidatePcap
PcapIngestService.StartOfflineProcessing
SensorTelemetryService.StreamObservations
SensorTelemetryService.StreamFeatureWindows
SensorSessionService.StopSession
```

---

## Deep Assessment Mode

Primary runtime calls:

```text
SensorSessionService.CreateSession

PassiveCaptureService.StartCapture

StrongSwanViciService.Probe
StrongSwanViciService.GetCapabilities
StrongSwanViciService.GetGatewaySnapshot
StrongSwanViciService.StreamEvents

KernelXfrmService.GetCapabilities
KernelXfrmService.GetKernelSnapshot

SensorTelemetryService.StreamObservations
SensorTelemetryService.StreamFeatureWindows
```

This produces:

```text
PASSIVE OBSERVATIONS
        +
VICI VERIFIED STATE
        +
XFRM VERIFIED STATE
```

which the later **Fusion Engine** can reconcile.

---

# 8. Critical data separation

The Go Sensor should emit three different evidence families.

## 8.1 Passive evidence

Example:

```json
{
  "property": "ike_version",
  "value": "IKEv2",
  "source": "PACKET_PARSER",
  "evidence_status": "OBSERVED"
}
```

---

## 8.2 VICI gateway evidence

Example:

```json
{
  "property": "child_sa_mode",
  "value": "TUNNEL",
  "source": "STRONGSWAN_VICI",
  "evidence_status": "VERIFIED_GATEWAY"
}
```

---

## 8.3 Kernel evidence

Example:

```json
{
  "property": "replay_window",
  "value": 32,
  "source": "LINUX_XFRM",
  "evidence_status": "VERIFIED_GATEWAY"
}
```

Do not merge these inside the Sensor into one security conclusion.

That is the responsibility of the internal **Evidence Fusion Engine** module.

---

# 9. What the Go Sensor must NOT do

The Sensor does not own:

```text
security score
severity classification
threat matrix
standards compliance decision
final security recommendation
ML traffic classification
SHAP
Evidence Fusion
executive report
technical report
frontend state
LLM/RAG
```

It provides high-quality **network and gateway evidence**.

---

# 10. Recommended Go package structure

```text
go-sensor/
│
├── cmd/
│   └── sensor/
│       └── main.go
│
├── api/
│   └── proto/
│       └── sensor/v1/
│
├── internal/
│
│   ├── grpc/
│   │   ├── system/
│   │   ├── session/
│   │   ├── network/
│   │   ├── capture/
│   │   ├── pcap/
│   │   ├── protocol/
│   │   ├── flow/
│   │   ├── vici/
│   │   ├── xfrm/
│   │   └── telemetry/
│   │
│   ├── capture/
│   │   ├── live/
│   │   └── offline/
│   │
│   ├── protocol/
│   │   ├── ike/
│   │   ├── esp/
│   │   ├── ah/
│   │   └── natt/
│   │
│   ├── sessions/
│   ├── flows/
│   ├── features/
│   ├── vici/
│   ├── xfrm/
│   ├── state/
│   ├── events/
│   └── tempstorage/
│
└── tests/
```

---

# 11. Internal data flow

```text
Live interface ─┐
                ├─> PacketSource
PCAP file ──────┘
                     │
                     ├──────────────┐
                     ▼              ▼
             Protocol Analyzer    Flow Tracker
                     │              │
                     ▼              ▼
             Protocol Events    Feature Windows
                     │              │
                     └──────┬───────┘
                            ▼
                   Sensor Telemetry Stream


Deep Mode additionally:

StrongSwan VICI ───> Gateway Evidence ───┐
                                        │
Linux XFRM ────────> Kernel Evidence ───┼─> Sensor Telemetry
                                        │
Passive Capture ───> Packet Evidence ───┘
```

---

# 12. Recommended implementation order

Do not implement all 72 internal methods in random order.

## Phase 1 — Sensor foundation

```text
Health
Readiness
GetCapabilities

CreateSession
GetSession
StopSession
ResetSession
```

---

## Phase 2 — Passive live capture

```text
ListInterfaces
GetInterface

StartCapture
StopCapture
GetCaptureStatus
GetCaptureStats
```

---

## Phase 3 — Passive protocol engine

```text
GetProtocolSummary
ListVpnSessions
ListIkeExchanges
ListEspStreams
ListSpis
GetNatTraversal
StreamProtocolEvents
```

At this point the Sensor is already a useful IPsec observer.

---

## Phase 4 — Flow engine

```text
ListFlows
GetFlowStats
ListFeatureWindows
GetFeatureWindow
GetSequenceSketch
StreamFeatureWindows
```

This prepares the ML boundary.

---

## Phase 5 — PCAP mode

```text
BeginUpload
UploadChunk
CompleteUpload
ValidatePcap
StartOfflineProcessing
GetOfflineProcessingStatus
CancelOfflineProcessing
```

Use the exact same packet-processing pipeline as live capture.

---

## Phase 6 — Deep Assessment: VICI

```text
Probe
GetCapabilities
GetDaemonStats
ListIkeSas
ListChildSas
ListConnections
ListPolicies
ListAlgorithms
GetCounters
GetGatewaySnapshot
StreamEvents
```

Then add certificate/authority endpoints.

---

## Phase 7 — Deep Assessment: XFRM

```text
ListStates
ListPolicies
GetReplayProtection
GetKernelSnapshot
```

---

## Phase 8 — Unified Backend telemetry

```text
GetSnapshot
StreamObservations
StreamFeatureWindows
AcknowledgeCheckpoint
```

At this point the **Go Sensor v1 is functionally complete** and ready to integrate with the Go Backend.

---

# 13. v1 completion criteria

The Sensor is considered ready when all of the following are true.

## Passive Live

- Can enumerate interfaces
- Can start/stop capture
- Detects IKE, ESP, AH, NAT-T
- Tracks SPIs
- Reconstructs passive VPN sessions
- Produces protocol events
- Produces flow statistics
- Produces ML-ready feature windows
- Streams results live

## Passive PCAP

- Accepts PCAP/PCAPNG
- Validates input
- Uses the same protocol and flow pipeline as live mode
- Produces identical normalized evidence objects

## Deep Assessment

- Connects to StrongSwan VICI locally
- Reads daemon status
- Reads active IKE/CHILD SAs
- Reads connection configuration
- Reads policies
- Reads supported algorithms
- Reads counters
- Receives SA lifecycle events
- Reads Linux XFRM state/policy when available
- Retrieves replay-window information where available
- Produces normalized gateway/kernel evidence

## Backend Integration

- Go Backend can get a full Sensor snapshot
- Go Backend can subscribe to live Sensor observations
- Go Backend can receive ML feature windows without raw packets
- Sensor remains functional if Deep Mode sources are unavailable
- Missing data is marked `UNKNOWN`, never fabricated

---

# 14. Important implementation rules

### Rule 1 — Never send packet payload to ML by default

ML should eventually receive:

```text
packet sizes
direction
timing
flow statistics
sequence sketches
```

not decrypted/raw application payloads.

---

### Rule 2 — Do not keep every packet in RAM

For each packet:

```text
parse
↓
update protocol/flow state
↓
discard packet object
```

Keep aggregated state only.

---

### Rule 3 — Bound all queues

Packet, event and feature channels must be bounded.

Track queue pressure in runtime stats.

---

### Rule 4 — Evict inactive flows

Flows should be finalized after a configurable idle timeout.

---

### Rule 5 — Deep Mode remains optional

If:

```text
VICI unavailable
```

or:

```text
XFRM unavailable
```

the Sensor must continue in Passive Analysis Mode.

---

### Rule 6 — Do not expose VICI secrets/key material

VICI/XFRM adapters must sanitize all responses.

Never expose:

```text
private keys
raw key material
PSKs
secret credentials
```

to the Go Backend.

---

### Rule 7 — Preserve evidence origin

Never turn:

```text
passively inferred
```

into:

```text
gateway verified
```

without an actual gateway-side source.

---

# 15. Future APIs intentionally excluded

These are **not required in the Sensor v1 assessment product**:

```text
InitiateIkeSa
TerminateIkeSa
ForceRekey
LoadStrongSwanConnection
DeleteStrongSwanConnection
InstallXfrmState
DeleteXfrmState
ModifyXfrmPolicy
```

They modify the VPN and belong in a separate **Testbed/Control Service** if the project later needs automated VPN generation.

---

# 16. StrongSwan / Linux implementation references

StrongSwan VICI:

- https://docs.strongswan.org/docs/latest/plugins/vici.html

StrongSwan active SA information:

- https://docs.strongswan.org/docs/latest/swanctl/swanctlListSas.html

StrongSwan monitoring/control surface:

- https://docs.strongswan.org/docs/latest/swanctl/swanctl.html

StrongSwan daemon statistics:

- https://docs.strongswan.org/docs/latest/swanctl/swanctlStats.html

StrongSwan IKE counters:

- https://docs.strongswan.org/docs/latest/swanctl/swanctlCounters.html

Linux XFRM state/policy model:

- https://man7.org/linux/man-pages/man8/ip-xfrm.8.html

---

# 17. Final sensor boundary

The clean responsibility is:

```text
                     GO SENSOR

NETWORK / PCAP
      │
      ▼
Passive Protocol Evidence
      │
      ├───────────────┐
      │               │
      ▼               ▼
Flow Features      Deep Assessment
                   VICI + XFRM
      │               │
      └───────┬───────┘
              ▼
      Normalized Sensor Evidence
              │
              ▼
          GO BACKEND
```

The Go Sensor answers:

> **"What did I observe, derive, or verify about this IPsec deployment?"**

The Go Backend / Security Engine answers:

> **"What does that evidence mean for security?"**

The Evidence Fusion Engine answers:

> **"How do passive, gateway, kernel and ML evidence combine into one trustworthy conclusion?"**

This separation should remain fixed throughout implementation.
