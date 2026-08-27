# IPsec Security Analyzer — Go Core Backend API Specification v1.0

> **Scope:** This document specifies the **Go Core Backend / Control Plane only**.
>
> It assumes the following logical contracts already exist inside the same Go process:
>
> - Go Sensor API Specification v1.0
> - A Fusion Engine contract defined separately
>
> It also assumes a future Python ML Worker process for model inference.
>
> **Transport:** gRPC over HTTP/2.
>
> **Frontend rule:** Next.js communicates only with the Go Core Backend using gRPC-Web / Connect-compatible transport. It never calls the Go Sensor or Python ML Worker directly.
>
> **One-process rule:** The Go Sensor, Go Core Backend / Security Engine, and Evidence Fusion Engine are logical modules compiled into one Go server. Do not introduce gRPC between these Go modules. Use Go interfaces, direct function calls, channels, shared domain models, and a synchronized in-memory state owner.
>
> **v1 storage:** Current workspace and analysis state are kept in Go memory. Large uploaded PCAPs and generated reports may use temporary disk. No SQL database or authentication is required in v1.

---

# 1. Go Core Backend responsibility

The Go Core Backend is the **control plane and security orchestration layer**.

It owns:

- frontend-facing gRPC APIs
- local Sensor module orchestration
- Passive / PCAP / Deep Assessment mode orchestration
- live capture orchestration
- PCAP upload orchestration
- analysis lifecycle
- ingestion of normalized Sensor evidence
- deterministic security-rule execution
- policy selection
- security score calculation
- threat matrix generation
- remediation prioritization
- ML Worker orchestration
- internal Fusion Engine orchestration
- live event streaming to Next.js
- temporary report generation
- in-memory current workspace/state
- graceful degradation when ML, VICI or XFRM are unavailable

It must **not**:

- parse raw packets directly if the Sensor is available
- bypass the Sensor module for StrongSwan VICI or Linux XFRM discovery
- perform ML inference itself
- allow the LLM to decide security score or severity
- fabricate unavailable evidence

---

# 2. End-to-end architecture

```text
                         NEXT.JS
                            │
                  gRPC-Web / Connect
                            │
                            ▼
                    ONE GO SERVER
                            │
                            ▼
                  Local Sensor Module
                  packet / PCAP / VICI / XFRM
                            │
                 ┌──────────┴──────────┐
                 │                     │ gRPC process boundary
                 ▼                     ▼
          Protocol/Gateway        PYTHON ML WORKER
          Evidence                XGBoost / sequence models
                 │                     │
                 └──────────┬──────────┘
                            ▼
                  Evidence Fusion Module
                  fused conclusions
                            │
                            ▼
                  Security / Risk / Reports
                            │
                            ▼
                    EventService updates
```

The Fusion module is shown after the ML worker in the dataflow because ML
predictions, calibrated confidence, abstention state, and SHAP explanation are
evidence inputs to Fusion. During live analysis Fusion may still run
incrementally before ML completes, but it must recompute affected conclusions
when ML evidence arrives.

---

# 3. Main operating modes

The backend exposes three analyst modes.

## 3.1 Passive Live Analysis

```text
User selects interface
      ↓
Go Core calls the local Sensor module to capture
      ↓
Sensor observes IKE / ESP / AH / NAT-T
      ↓
Sensor module emits flow windows + protocol evidence
      ↓
Go Core sends feature windows to ML Worker
      ↓
Fusion
      ↓
Security / Risk
      ↓
Frontend
```

No gateway access is required.

---

## 3.2 Passive PCAP Analysis

```text
User uploads PCAP
      ↓
Go Core orchestrates local Sensor PCAP ingestion
      ↓
Sensor module processes PCAP through same packet pipeline
      ↓
Go Core receives normalized evidence
      ↓
ML inference on feature windows
      ↓
Fusion
      ↓
Security / Risk
      ↓
Frontend
```

---

## 3.3 Deep Assessment / Sensor Mode

```text
Passive packet evidence
        +
StrongSwan VICI verified evidence
        +
Linux XFRM verified evidence
        ↓
Go Core
      ↓
ML inference where enabled
      ↓
Fusion
      ↓
Security / Risk
      ↓
Final assessment
```

Deep Assessment must gracefully fall back to Passive Mode when VICI or XFRM is unavailable.

---

# 4. Service catalogue

| # | Service | Responsibility |
|---|---|---|
| 1 | `CoreSystemService` | Health, readiness, version, capabilities, runtime stats |
| 2 | `WorkspaceService` | Ephemeral current-workspace lifecycle |
| 3 | `LocalSensorStatusService` | Local Sensor module status, mode readiness, Deep Assessment availability |
| 4 | `InputService` | Frontend-facing live capture and PCAP input orchestration |
| 5 | `AnalysisService` | End-to-end analysis lifecycle and progress |
| 6 | `ProtocolReadService` | Frontend access to normalized protocol/session/SA/timeline evidence |
| 7 | `SecurityAssessmentService` | Security rules, findings, compliance, threat matrix, recommendations |
| 8 | `RiskService` | Deterministic risk score and score breakdown |
| 9 | `PolicyService` | Security policy profiles loaded from disk |
| 10 | `MLOrchestrationService` | Python ML health/model/inference orchestration |
| 11 | `FusionOrchestrationService` | Starts fusion, exposes fused conclusions and evidence status |
| 12 | `ReportService` | Executive / technical / JSON reports |
| 13 | `EventService` | Unified server-streaming updates for Next.js |
| 14 | `RuntimeConfigService` | Runtime tuning without database persistence |
| 15 | `ArtifactService` | Temporary PCAP/report metadata and cleanup |

---

# 4A. System API Contract Review

The combined v1 system has one externally exposed Go gRPC surface:
`Go Core Backend -> Next.js / external clients`.

The Sensor and Fusion specifications remain separate because they describe
large internal modules, not because they are deployed as microservices.

## Removed or collapsed overlaps

- Remote Sensor attach/detach is not part of v1. `LocalSensorStatusService`
  exposes readiness and capabilities for the in-process Sensor module.
- Sensor session start/stop is not a separate frontend workflow. It is
  coordinated by `InputService`, `AnalysisService`, and `WorkspaceService`.
- Fusion does not expose a second external API to the frontend. Core exposes
  selected fusion reads through `FusionOrchestrationService`.
- Sensor protocol reads and Core protocol reads are not duplicates: Sensor owns
  raw normalized observations; Core owns frontend-ready normalized/fused views.
- Fusion conclusions and Security findings are not duplicates: Fusion answers
  what value is best supported; Security decides whether that value violates
  policy.
- Risk score and Security score are one deterministic scoring domain owned by
  `RiskService`; Fusion confidence must not be presented as security score.

## Ownership boundaries

```text
Sensor module:
  packet/PCAP acquisition, IKE/ESP/AH/NAT-T observation, SPI/SA tracking,
  VICI/XFRM read-only telemetry, flow windows, feature schemas

Python ML Worker:
  model inference, calibrated probabilities, abstention, SHAP/explanations

Fusion module:
  evidence normalization, correlation, conflict resolution, confidence,
  provenance, fused conclusion history

Security Engine:
  crypto-strength rules, compliance checks, findings, remediation,
  threat matrix inputs

Risk Engine:
  deterministic score, risk level, score breakdown, score caps/overrides,
  unknown-evidence handling

Report/Event layer:
  executive/technical/JSON reports, live dashboard progress and errors
```

## Required graceful-degradation behavior

Missing VICI, XFRM, ML, SHAP, or optional sequence-model support must not abort
deterministic passive analysis. The unavailable source is recorded with an
explicit reason, propagated into Fusion source coverage, and shown in reports
as unknown/unavailable evidence rather than as a passing or failing fact.

# 5. Common conventions

## IDs

Use UUIDv7 for:

```text
workspace_id
sensor_session_id
source_id
capture_id
analysis_id
assessment_id
ml_job_id
fusion_run_id
finding_id
report_id
event_id
```

## Timestamps

Use `google.protobuf.Timestamp`, always UTC.

## Pagination

Use cursor pagination:

```protobuf
message PageRequest {
  uint32 page_size = 1;
  string page_token = 2;
}
```

## Mutating RPCs

Mutating RPCs should support an idempotency key in request metadata:

```text
x-idempotency-key
```

## gRPC status codes

Use standard codes:

```text
INVALID_ARGUMENT
NOT_FOUND
ALREADY_EXISTS
FAILED_PRECONDITION
RESOURCE_EXHAUSTED
UNAVAILABLE
DEADLINE_EXCEEDED
CANCELLED
INTERNAL
```

Every externally exposed Core RPC entry must document:

```text
RPC: ServiceName.MethodName
gRPC Method Type: Unary | Server Streaming | Client Streaming | Bidirectional Streaming
Purpose
Request
Response
Errors
```

Unless a specific RPC overrides them, common errors are:

| Code | Failure condition |
|---|---|
| `INVALID_ARGUMENT` | malformed IDs, invalid mode, invalid upload chunk, invalid policy/options |
| `NOT_FOUND` | unknown workspace, source, analysis, finding, prediction, fusion run, report or artifact |
| `ALREADY_EXISTS` | active singleton workspace/input/session conflicts |
| `FAILED_PRECONDITION` | wrong lifecycle state, missing input source, incomplete PCAP, unavailable required evidence |
| `RESOURCE_EXHAUSTED` | upload size limit, queue overflow, event buffer pressure, report size limit |
| `UNAVAILABLE` | Python ML Worker unavailable; optional VICI/XFRM unavailable when explicitly required |
| `DEADLINE_EXCEEDED` | ML inference, report generation, or deep telemetry timeout |
| `CANCELLED` | client or server-side context cancellation |
| `INTERNAL` | unexpected server failure |

---

# SERVICE 1 — CoreSystemService

```protobuf
service CoreSystemService {
  rpc Health(HealthRequest) returns (HealthResponse);
  rpc Readiness(ReadinessRequest) returns (ReadinessResponse);
  rpc GetVersion(GetVersionRequest) returns (GetVersionResponse);
  rpc GetCapabilities(GetCapabilitiesRequest) returns (GetCapabilitiesResponse);
  rpc GetRuntimeStats(GetRuntimeStatsRequest) returns (GetRuntimeStatsResponse);
}
```

---

## API 1.1 — Health

**RPC:** `CoreSystemService.Health`  
**gRPC Method Type:** Unary

### Purpose
Checks whether the Go Core process is alive.

### Request

```json
{}
```

### Response

```json
{
  "status": "HEALTHY",
  "time": "2026-08-27T15:00:00Z"
}
```

---

## API 1.2 — Readiness

**RPC:** `CoreSystemService.Readiness`  
**gRPC Method Type:** Unary

### Purpose
Checks all mandatory runtime dependencies.

### Response

```json
{
  "ready": true,
  "in_memory_store": "READY",
  "temp_storage": "READY",
  "sensor": "READY",
  "ml_worker": "READY",
  "fusion_engine": "READY"
}
```

`ml_worker` may be unavailable while deterministic analysis remains usable.

---

## API 1.3 — GetVersion

**RPC:** `CoreSystemService.GetVersion`  
**gRPC Method Type:** Unary


### Response

```json
{
  "core_version": "1.0.0",
  "api_version": "core.v1",
  "sensor_contract": "sensor.v1",
  "ml_contract": "ml.v1",
  "fusion_contract": "fusion.v1",
  "build_commit": "..."
}
```

---

## API 1.4 — GetCapabilities

**RPC:** `CoreSystemService.GetCapabilities`  
**gRPC Method Type:** Unary


### Response examples

```text
passive_live
passive_pcap
deep_assessment
security_assessment
risk_scoring
threat_matrix
ml_classification
shap
metadata_exposure
executive_report
technical_report
```

---

## API 1.5 — GetRuntimeStats

**RPC:** `CoreSystemService.GetRuntimeStats`  
**gRPC Method Type:** Unary


### Response

```json
{
  "uptime_seconds": 8421,
  "cpu_percent": 6.2,
  "rss_bytes": 94371840,
  "goroutines": 62,
  "event_subscribers": 1,
  "current_workspace_state": "COMPLETED",
  "sensor_queue_depth": 0,
  "ml_round_trip_ms": 4.8,
  "fusion_recompute_ms": 0.9
}
```

---

# SERVICE 2 — WorkspaceService

The v1 backend owns exactly one current ephemeral workspace.

```protobuf
service WorkspaceService {
  rpc Create(CreateWorkspaceRequest) returns (Workspace);
  rpc Get(GetWorkspaceRequest) returns (Workspace);
  rpc GetState(GetWorkspaceStateRequest) returns (WorkspaceStateResponse);
  rpc Reset(ResetWorkspaceRequest) returns (ResetWorkspaceResponse);
}
```

---

## API 2.1 — Create

**RPC:** `WorkspaceService.Create`  
**gRPC Method Type:** Unary


### Request

```json
{
  "display_name": "NTRO Assessment"
}
```

### Response

```json
{
  "workspace_id": "uuid",
  "state": "EMPTY",
  "created_at": "..."
}
```

Creating a new workspace clears previous ephemeral state.

---

## API 2.2 — Get

**RPC:** `WorkspaceService.Get`  
**gRPC Method Type:** Unary


### Response

High-level current workspace:

```text
workspace ID
state
mode
sensor binding
input source
analysis ID
assessment ID
fusion run ID
report presence
created/updated timestamps
```

---

## API 2.3 — GetState

**RPC:** `WorkspaceService.GetState`  
**gRPC Method Type:** Unary


### Purpose

Fast frontend call after refresh.

### Response

```json
{
  "state": "COMPLETED",
  "mode": "PASSIVE_PCAP",
  "has_source": true,
  "has_analysis": true,
  "has_ml_result": true,
  "has_fused_result": true,
  "has_report": false
}
```

---

## API 2.4 — Reset

**RPC:** `WorkspaceService.Reset`  
**gRPC Method Type:** Unary


### Request

```json
{
  "force": false,
  "delete_temporary_files": true
}
```

### Behavior

- cancel active analysis
- stop sensor session
- stop live capture
- clear protocol cache
- clear ML predictions
- clear findings
- clear risk result
- clear fusion state
- delete temporary PCAP/report
- create fresh empty workspace

### Response

```json
{
  "workspace_id": "new-uuid",
  "state": "EMPTY"
}
```

---

# SERVICE 3 — LocalSensorStatusService

Go Core uses this service to expose local Sensor module readiness to the frontend.
It does not attach to a remote Sensor process. Sensor sessions are created
internally by `InputService.StartLive`, `InputService.CompletePcapUpload` /
`AnalysisService.Start`, and `WorkspaceService.Reset`.

```protobuf
service LocalSensorStatusService {
  rpc GetStatus(GetLocalSensorStatusRequest) returns (LocalSensorStatus);
  rpc GetCapabilities(GetLocalSensorCapabilitiesRequest) returns (LocalSensorCapabilities);
  rpc ProbeModes(ProbeModesRequest) returns (ProbeModesResponse);
  rpc GetDeepAssessmentAvailability(GetDeepAssessmentAvailabilityRequest) returns (GetDeepAssessmentAvailabilityResponse);
}
```

---

## API 3.1 — GetStatus

**RPC:** `LocalSensorStatusService.GetStatus`  
**gRPC Method Type:** Unary

### Purpose

Returns the health of the local Sensor module and acquisition pipeline.

### Response

```json
{
  "ready": true,
  "sensor_version": "1.0.0",
  "session_active": false,
  "capture_active": false,
  "packet_queue_depth": 0,
  "feature_queue_depth": 0,
  "last_error": ""
}
```

---

## API 3.2 — GetCapabilities

**RPC:** `LocalSensorStatusService.GetCapabilities`  
**gRPC Method Type:** Unary

Returns the local Sensor module capability set, including:

```text
passive live capture
passive PCAP processing
IPv4 / IPv6 parsing
IKEv1 / IKEv2
ESP / AH / NAT-T
flow feature windows
sequence sketches
StrongSwan VICI adapter
Linux XFRM adapter
```

---

## API 3.3 — ProbeModes

**RPC:** `LocalSensorStatusService.ProbeModes`  
**gRPC Method Type:** Unary

### Purpose

Determines which analysis modes can run now.

### Response

```json
{
  "passive_live": {
    "available": true
  },
  "passive_pcap": {
    "available": true
  },
  "deep_assessment": {
    "available": true,
    "vici": true,
    "xfrm": true
  }
}
```

---

## API 3.4 — GetDeepAssessmentAvailability

**RPC:** `LocalSensorStatusService.GetDeepAssessmentAvailability`  
**gRPC Method Type:** Unary

### Response

```json
{
  "available": true,
  "vici": {
    "available": true,
    "reason": ""
  },
  "xfrm": {
    "available": true,
    "reason": ""
  }
}
```

---

# SERVICE 4 — InputService

This is the only input API the frontend needs. Go Core internally calls local Sensor module interfaces.

```protobuf
service InputService {
  rpc ListInterfaces(ListInterfacesRequest) returns (ListInterfacesResponse);
  rpc StartLive(StartLiveInputRequest) returns (StartLiveInputResponse);
  rpc StopLive(StopLiveInputRequest) returns (StopLiveInputResponse);
  rpc GetLiveStatus(GetLiveStatusRequest) returns (LiveInputStatus);
  rpc BeginPcapUpload(BeginPcapUploadRequest) returns (BeginPcapUploadResponse);
  rpc UploadPcapChunk(UploadPcapChunkRequest) returns (UploadPcapChunkResponse);
  rpc CompletePcapUpload(CompletePcapUploadRequest) returns (CompletePcapUploadResponse);
  rpc ValidatePcap(ValidatePcapRequest) returns (ValidatePcapResponse);
  rpc GetSource(GetSourceRequest) returns (InputSource);
  rpc RemoveSource(RemoveSourceRequest) returns (RemoveSourceResponse);
}
```

---

## API 4.1 — ListInterfaces

**RPC:** `InputService.ListInterfaces`  
**gRPC Method Type:** Unary


Returns normalized interface inventory from the local Sensor module.

---

## API 4.2 — StartLive

**RPC:** `InputService.StartLive`  
**gRPC Method Type:** Unary


### Request

```json
{
  "mode": "PASSIVE_LIVE",
  "interface_name": "eth0",
  "filter_mode": "IPSEC_ONLY",
  "save_pcap": false,
  "max_duration_seconds": 3600
}
```

Deep Mode example:

```json
{
  "mode": "DEEP_ASSESSMENT",
  "interface_name": "eth0",
  "filter_mode": "IPSEC_ONLY",
  "enable_vici": true,
  "enable_xfrm": true
}
```

### Behavior

- create Sensor session if needed
- start passive capture
- if Deep Mode, probe and snapshot VICI/XFRM
- subscribe to Sensor observations
- initialize Go Core in-memory evidence state

### Response

```json
{
  "source_id": "uuid",
  "capture_id": "uuid",
  "sensor_session_id": "uuid",
  "state": "CAPTURING"
}
```

---

## API 4.3 — StopLive

**RPC:** `InputService.StopLive`  
**gRPC Method Type:** Unary


Stops capture, finalizes Sensor flows and feature windows.

---

## API 4.4 — GetLiveStatus

**RPC:** `InputService.GetLiveStatus`  
**gRPC Method Type:** Unary


### Response

```json
{
  "state": "CAPTURING",
  "duration_seconds": 91,
  "packets_total": 1828391,
  "esp_packets": 1718211,
  "ike_packets": 41,
  "active_flows": 83,
  "vpn_sessions": 2
}
```

---

## API 4.5 — BeginPcapUpload

**RPC:** `InputService.BeginPcapUpload`  
**gRPC Method Type:** Unary


### Request

```json
{
  "filename": "vpn.pcapng",
  "size_bytes": 918273812,
  "sha256": ""
}
```

### Behavior

Go Core opens/initializes a local Sensor module upload session.

### Response

```json
{
  "upload_id": "uuid",
  "chunk_size_bytes": 1048576
}
```

---

## API 4.6 — UploadPcapChunk

**RPC:** `InputService.UploadPcapChunk`  
**gRPC Method Type:** Unary


### Request

```json
{
  "upload_id": "uuid",
  "chunk_index": 0,
  "data": "<bytes>"
}
```

### Response

```json
{
  "accepted": true,
  "chunk_index": 0,
  "received_bytes_total": 1048576
}
```

---

## API 4.7 — CompletePcapUpload

**RPC:** `InputService.CompletePcapUpload`  
**gRPC Method Type:** Unary


### Response

```json
{
  "source_id": "uuid",
  "pcap_id": "uuid",
  "state": "SOURCE_READY"
}
```

---

## API 4.8 — ValidatePcap

**RPC:** `InputService.ValidatePcap`  
**gRPC Method Type:** Unary


Returns normalized Sensor validation result.

---

## API 4.9 — GetSource

**RPC:** `InputService.GetSource`  
**gRPC Method Type:** Unary


Returns current source type:

```text
PASSIVE_LIVE
PASSIVE_PCAP
DEEP_ASSESSMENT
```

and source metadata.

---

## API 4.10 — RemoveSource

**RPC:** `InputService.RemoveSource`  
**gRPC Method Type:** Unary


Removes current input and related temporary source data.

---

# SERVICE 5 — AnalysisService

```protobuf
service AnalysisService {
  rpc Start(StartAnalysisRequest) returns (StartAnalysisResponse);
  rpc Cancel(CancelAnalysisRequest) returns (CancelAnalysisResponse);
  rpc Get(GetAnalysisRequest) returns (Analysis);
  rpc GetProgress(GetAnalysisProgressRequest) returns (AnalysisProgress);
  rpc GetSummary(GetAnalysisSummaryRequest) returns (AnalysisSummary);
  rpc Retry(RetryAnalysisRequest) returns (RetryAnalysisResponse);
}
```

---

## API 5.1 — Start

**RPC:** `AnalysisService.Start`  
**gRPC Method Type:** Unary


### Request

```json
{
  "source_id": "uuid",
  "mode": "PASSIVE_PCAP",
  "policy_id": "ietf-recommended-v1",
  "options": {
    "enable_security": true,
    "enable_ml": true,
    "enable_shap": true,
    "enable_metadata_exposure": true,
    "enable_fusion": true
  }
}
```

### Processing model

Run deterministic evidence collection and ML inference in parallel where
possible. Fusion consumes both streams, then the Security Engine evaluates the
fused conclusions.

```text
Sensor evidence
      │
      ├────────► Fusion pending evidence
      │
      └────────► ML orchestration ──► ML evidence
                                  │
                                  ▼
                               Fusion
                                  │
                                  ▼
                            Security / Risk
```

### Response

```json
{
  "analysis_id": "uuid",
  "state": "RUNNING"
}
```

---

## API 5.2 — Cancel

**RPC:** `AnalysisService.Cancel`  
**gRPC Method Type:** Unary


Cancels active work using Go context cancellation and propagates cancellation to ML/Fusion.

---

## API 5.3 — Get

**RPC:** `AnalysisService.Get`  
**gRPC Method Type:** Unary


Returns analysis lifecycle state and options.

---

## API 5.4 — GetProgress

**RPC:** `AnalysisService.GetProgress`  
**gRPC Method Type:** Unary


### Stages

```text
INITIALIZING
ACQUIRING
PROTOCOL_PROCESSING
SESSION_RECONSTRUCTION
FLOW_AGGREGATION
FEATURE_EXTRACTION
SECURITY_ANALYSIS
ML_INFERENCE
FUSION
FINALIZING
COMPLETED
```

### Response

```json
{
  "stage": "ML_INFERENCE",
  "percent": 72,
  "packets_processed": 8128192,
  "flows_processed": 1842,
  "sessions_found": 3,
  "sas_found": 6,
  "findings_generated": 4
}
```

---

## API 5.5 — GetSummary

**RPC:** `AnalysisService.GetSummary`  
**gRPC Method Type:** Unary


### Response

```json
{
  "ipsec_detected": true,
  "mode": "DEEP_ASSESSMENT",
  "protocol": {
    "ike_version": "IKEv2",
    "data_protocol": "ESP",
    "vpn_mode": "TUNNEL"
  },
  "traffic": {
    "class": "VIDEO",
    "confidence": 0.943,
    "state": "AVAILABLE"
  },
  "security": {
    "score": 82,
    "risk_level": "MODERATE"
  },
  "finding_counts": {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3
  },
  "fusion_state": "COMPLETE"
}
```

Unknown values are marked explicitly.

---

## API 5.6 — Retry

**RPC:** `AnalysisService.Retry`  
**gRPC Method Type:** Unary


Useful after transient ML/Fusion dependency failures.

---

# SERVICE 6 — ProtocolReadService

Go Core caches/normalizes Sensor evidence and exposes frontend-friendly views.

```protobuf
service ProtocolReadService {
  rpc GetSummary(GetProtocolSummaryRequest) returns (ProtocolSummary);
  rpc ListSessions(ListSessionsRequest) returns (ListSessionsResponse);
  rpc GetSession(GetSessionRequest) returns (VpnSession);
  rpc ListIkeExchanges(ListIkeExchangesRequest) returns (ListIkeExchangesResponse);
  rpc ListSecurityAssociations(ListSecurityAssociationsRequest) returns (ListSecurityAssociationsResponse);
  rpc GetSecurityAssociation(GetSecurityAssociationRequest) returns (SecurityAssociation);
  rpc ListCryptoProperties(ListCryptoPropertiesRequest) returns (ListCryptoPropertiesResponse);
  rpc GetNatTraversal(GetNatTraversalRequest) returns (NatTraversalSummary);
  rpc GetTimeline(GetTimelineRequest) returns (ProtocolTimeline);
  rpc ListEvidence(ListProtocolEvidenceRequest) returns (ListProtocolEvidenceResponse);
}
```

---

## API 6.1 — GetSummary

**RPC:** `ProtocolReadService.GetSummary`  
**gRPC Method Type:** Unary


Returns fused/normalized protocol facts currently available to the Go Core.

---

## API 6.2 — ListSessions

**RPC:** `ProtocolReadService.ListSessions`  
**gRPC Method Type:** Unary


Returns VPN sessions with evidence status.

---

## API 6.3 — GetSession

**RPC:** `ProtocolReadService.GetSession`  
**gRPC Method Type:** Unary


Returns one session and associated:

```text
IKE exchanges
SAs
SPIs
flows
evidence sources
```

---

## API 6.4 — ListIkeExchanges

**RPC:** `ProtocolReadService.ListIkeExchanges`  
**gRPC Method Type:** Unary


---

## API 6.5 — ListSecurityAssociations

**RPC:** `ProtocolReadService.ListSecurityAssociations`  
**gRPC Method Type:** Unary


---

## API 6.6 — GetSecurityAssociation

**RPC:** `ProtocolReadService.GetSecurityAssociation`  
**gRPC Method Type:** Unary


---

## API 6.7 — ListCryptoProperties

**RPC:** `ProtocolReadService.ListCryptoProperties`  
**gRPC Method Type:** Unary


Returns properties such as:

```text
IKE cipher
ESP cipher
integrity
PRF
DH group
key length
PFS evidence
SA lifetime
```

Each value includes:

```text
value
source
evidence_status
confidence
```

---

## API 6.8 — GetNatTraversal

**RPC:** `ProtocolReadService.GetNatTraversal`  
**gRPC Method Type:** Unary


---

## API 6.9 — GetTimeline

**RPC:** `ProtocolReadService.GetTimeline`  
**gRPC Method Type:** Unary


---

## API 6.10 — ListEvidence

**RPC:** `ProtocolReadService.ListEvidence`  
**gRPC Method Type:** Unary


Provides raw normalized evidence items for technical debugging.

---

# SERVICE 7 — SecurityAssessmentService

```protobuf
service SecurityAssessmentService {
  rpc Run(RunSecurityAssessmentRequest) returns (RunSecurityAssessmentResponse);
  rpc Get(GetSecurityAssessmentRequest) returns (SecurityAssessment);
  rpc ListFindings(ListFindingsRequest) returns (ListFindingsResponse);
  rpc GetFinding(GetFindingRequest) returns (SecurityFinding);
  rpc GetThreatMatrix(GetThreatMatrixRequest) returns (ThreatMatrix);
  rpc ListRecommendations(ListRecommendationsRequest) returns (ListRecommendationsResponse);
  rpc GetCompliance(GetComplianceRequest) returns (ComplianceSummary);
  rpc GetMetadataExposure(GetMetadataExposureRequest) returns (MetadataExposureAssessment);
  rpc Reevaluate(ReevaluateSecurityRequest) returns (ReevaluateSecurityResponse);
}
```

---

## API 7.1 — Run

**RPC:** `SecurityAssessmentService.Run`  
**gRPC Method Type:** Unary


### Request

```json
{
  "analysis_id": "uuid",
  "policy_id": "ietf-recommended-v1"
}
```

### Response

```json
{
  "assessment_id": "uuid",
  "state": "RUNNING"
}
```

---

## API 7.2 — Get

**RPC:** `SecurityAssessmentService.Get`  
**gRPC Method Type:** Unary


Returns complete deterministic assessment.

---

## API 7.3 — ListFindings

**RPC:** `SecurityAssessmentService.ListFindings`  
**gRPC Method Type:** Unary


### Filters

```text
severity
category
session_id
sa_id
status
```

---

## API 7.4 — GetFinding

**RPC:** `SecurityAssessmentService.GetFinding`  
**gRPC Method Type:** Unary


### Response

```text
finding_id
rule_id
title
severity
category
description
technical impact
affected resource
fused conclusion references
evidence references
evidence status
confidence
recommendation
standards references
remediation steps
unknown/unavailable evidence reason when applicable
```

---

## API 7.5 — GetThreatMatrix

**RPC:** `SecurityAssessmentService.GetThreatMatrix`  
**gRPC Method Type:** Unary


### Response rows

```text
threat
severity
affected object
evidence
impact
recommendation
```

---

## API 7.6 — ListRecommendations

**RPC:** `SecurityAssessmentService.ListRecommendations`  
**gRPC Method Type:** Unary


Priority:

```text
P0
P1
P2
P3
```

Deduplicate repeated remediation.

---

## API 7.7 — GetCompliance

**RPC:** `SecurityAssessmentService.GetCompliance`  
**gRPC Method Type:** Unary


Returns:

```text
policy used
rules passed
rules failed
rules unknown
rules not applicable
```

---

## API 7.8 — GetMetadataExposure

**RPC:** `SecurityAssessmentService.GetMetadataExposure`  
**gRPC Method Type:** Unary


Combines deterministic side-channel exposure indicators with ML inferability when available.

---

## API 7.9 — Reevaluate

**RPC:** `SecurityAssessmentService.Reevaluate`  
**gRPC Method Type:** Unary


Reruns rule evaluation against current evidence without reparsing source traffic.

Useful after switching security policy.

---

# SERVICE 8 — RiskService

Risk calculation is separated from finding generation for auditability and future tuning.

```protobuf
service RiskService {
  rpc Calculate(CalculateRiskRequest) returns (CalculateRiskResponse);
  rpc GetScore(GetRiskScoreRequest) returns (SecurityScore);
  rpc GetBreakdown(GetRiskBreakdownRequest) returns (RiskBreakdown);
  rpc GetCriticalOverrides(GetCriticalOverridesRequest) returns (CriticalOverridesResponse);
}
```

---

## API 8.1 — Calculate

**RPC:** `RiskService.Calculate`  
**gRPC Method Type:** Unary


### Request

```json
{
  "assessment_id": "uuid",
  "policy_id": "ietf-recommended-v1"
}
```

### Response

```json
{
  "score": 82,
  "risk_level": "MODERATE",
  "confidence": 0.91,
  "unknown_evidence_count": 2
}
```

Unknown or unavailable evidence must be scored deterministically according to
policy. It must never be silently treated as secure; policies may either apply
a conservative penalty, reduce score confidence, or trigger a review-required
state for properties such as replay protection, PFS, SA lifetime, or key length.

---

## API 8.2 — GetScore

**RPC:** `RiskService.GetScore`  
**gRPC Method Type:** Unary


---

## API 8.3 — GetBreakdown

**RPC:** `RiskService.GetBreakdown`  
**gRPC Method Type:** Unary


### Response

```json
{
  "cryptography": {"score": 22, "max": 25},
  "authentication": {"score": 14, "max": 15},
  "key_exchange": {"score": 12, "max": 15},
  "pfs": {"score": 5, "max": 10},
  "replay": {"score": 7, "max": 7},
  "lifecycle": {"score": 7, "max": 8},
  "metadata": {"score": 3, "max": 5},
  "unknowns": {"count": 2, "confidence_penalty": 0.06}
}
```

---

## API 8.4 — GetCriticalOverrides

**RPC:** `RiskService.GetCriticalOverrides`  
**gRPC Method Type:** Unary


Returns score caps triggered by critical findings.

Example:

```text
Deprecated critical cipher
→ score_cap = 40
```

---

# SERVICE 9 — PolicyService

Policies are local versioned YAML/JSON files.

```protobuf
service PolicyService {
  rpc List(ListPoliciesRequest) returns (ListPoliciesResponse);
  rpc Get(GetPolicyRequest) returns (SecurityPolicy);
  rpc GetActive(GetActivePolicyRequest) returns (SecurityPolicy);
  rpc SetActive(SetActivePolicyRequest) returns (SetActivePolicyResponse);
  rpc Validate(ValidatePolicyRequest) returns (ValidatePolicyResponse);
  rpc Reload(ReloadPoliciesRequest) returns (ReloadPoliciesResponse);
}
```

---

## API 9.1 — List

**RPC:** `PolicyService.List`  
**gRPC Method Type:** Unary


---

## API 9.2 — Get

**RPC:** `PolicyService.Get`  
**gRPC Method Type:** Unary


---

## API 9.3 — GetActive

**RPC:** `PolicyService.GetActive`  
**gRPC Method Type:** Unary


---

## API 9.4 — SetActive

**RPC:** `PolicyService.SetActive`  
**gRPC Method Type:** Unary


---

## API 9.5 — Validate

**RPC:** `PolicyService.Validate`  
**gRPC Method Type:** Unary


Checks:

```text
duplicate rule IDs
invalid weights
weights out of range
unknown severity
bad score caps
unsupported fields
```

---

## API 9.6 — Reload

**RPC:** `PolicyService.Reload`  
**gRPC Method Type:** Unary


Reloads disk policy definitions.

---

# SERVICE 10 — MLOrchestrationService

This service exposes ML state to frontend and orchestrates Python worker calls.

```protobuf
service MLOrchestrationService {
  rpc GetWorkerStatus(GetMLWorkerStatusRequest) returns (MLWorkerStatus);
  rpc GetModelInfo(GetModelInfoRequest) returns (ModelInfo);
  rpc RunInference(RunInferenceRequest) returns (RunInferenceResponse);
  rpc GetInferenceStatus(GetInferenceStatusRequest) returns (InferenceStatus);
  rpc ListPredictions(ListPredictionsRequest) returns (ListPredictionsResponse);
  rpc GetPrediction(GetPredictionRequest) returns (TrafficPrediction);
  rpc GetExplanation(GetPredictionExplanationRequest) returns (PredictionExplanation);
  rpc CancelInference(CancelInferenceRequest) returns (CancelInferenceResponse);
}
```

---

## API 10.1 — GetWorkerStatus

**RPC:** `MLOrchestrationService.GetWorkerStatus`  
**gRPC Method Type:** Unary


Output:

```text
available
latency
model_loaded
model version
feature schema version
```

---

## API 10.2 — GetModelInfo

**RPC:** `MLOrchestrationService.GetModelInfo`  
**gRPC Method Type:** Unary


Returns:

```text
model name
version
model family
classes
feature schema
sequence schema
trained-at
```

---

## API 10.3 — RunInference

**RPC:** `MLOrchestrationService.RunInference`  
**gRPC Method Type:** Unary


### Request

```json
{
  "analysis_id": "uuid",
  "use_sequence_model": false,
  "enable_shap": true
}
```

### Behavior

- retrieve ready Sensor feature windows
- validate schema compatibility
- batch windows
- send gRPC request to Python ML worker
- cache predictions
- emit ML events
- submit ML evidence to the internal Fusion Engine

---

## API 10.4 — GetInferenceStatus

**RPC:** `MLOrchestrationService.GetInferenceStatus`  
**gRPC Method Type:** Unary


---

## API 10.5 — ListPredictions

**RPC:** `MLOrchestrationService.ListPredictions`  
**gRPC Method Type:** Unary


Returns per-flow/window predictions.

---

## API 10.6 — GetPrediction

**RPC:** `MLOrchestrationService.GetPrediction`  
**gRPC Method Type:** Unary


### Response

```json
{
  "traffic_class": "VIDEO",
  "confidence": 0.943,
  "class_probabilities": {
    "VIDEO": 0.943,
    "WEB": 0.031,
    "FILE_TRANSFER": 0.016
  },
  "model_version": "xgb-1.0.0",
  "feature_schema_version": "flow.v1"
}
```

---

## API 10.7 — GetExplanation

**RPC:** `MLOrchestrationService.GetExplanation`  
**gRPC Method Type:** Unary


Returns SHAP explanation cached from Python worker.

---

## API 10.8 — CancelInference

**RPC:** `MLOrchestrationService.CancelInference`  
**gRPC Method Type:** Unary


---

# 10A. Go Server to Python ML Worker gRPC Contract

This is a real process boundary. Go Core is the gRPC client; the Python ML
Worker is the gRPC server. The frontend never calls this worker directly.

```protobuf
service MLWorkerService {
  rpc Health(MLHealthRequest) returns (MLHealthResponse);
  rpc GetModelInfo(GetWorkerModelInfoRequest) returns (WorkerModelInfo);
  rpc CheckSchemaCompatibility(CheckSchemaCompatibilityRequest) returns (CheckSchemaCompatibilityResponse);
  rpc PredictBatch(PredictBatchRequest) returns (PredictBatchResponse);
  rpc PredictSequenceBatch(PredictSequenceBatchRequest) returns (PredictBatchResponse);
  rpc ExplainBatch(ExplainBatchRequest) returns (ExplainBatchResponse);
}
```

## RPC — MLWorkerService.Health

gRPC Method Type:
Unary

Purpose:
Checks worker liveness, readiness, loaded model state, and inference capacity.

Request:

```protobuf
message MLHealthRequest {}
```

Response:

```protobuf
message MLHealthResponse {
  bool available = 1;
  bool model_loaded = 2;
  string model_version = 3;
  string feature_schema_version = 4;
  uint32 max_batch_size = 5;
  uint32 queue_depth = 6;
  string status_message = 7;
}
```

Errors:
`UNAVAILABLE` when the worker is unreachable; `DEADLINE_EXCEEDED` on health timeout.

## RPC — MLWorkerService.GetModelInfo

gRPC Method Type:
Unary

Purpose:
Returns model metadata needed for auditability and compatibility checks.

Response fields:

```text
model_id
model_name
model_family: XGBOOST | TCN | CNN1D | OTHER
model_version
feature_schema_version
sequence_schema_version
classes
calibration_method
trained_at
supports_batch_inference
supports_sequence_inference
supports_shap
abstention_threshold
```

Errors:
`FAILED_PRECONDITION` when no model is loaded.

## RPC — MLWorkerService.CheckSchemaCompatibility

gRPC Method Type:
Unary

Purpose:
Verifies that Sensor feature windows can be consumed by the loaded model before
Go Core starts an inference job.

Request fields:

```text
feature_schema_version
sequence_schema_version
feature_names
feature_count
normalization_profile
```

Response fields:

```text
compatible
missing_features
extra_features
expected_feature_schema_version
expected_sequence_schema_version
reason_code
```

Errors:
`INVALID_ARGUMENT` for malformed schema descriptions.

## RPC — MLWorkerService.PredictBatch

gRPC Method Type:
Unary

Purpose:
Runs XGBoost or another tabular model over finalized feature windows.

Request fields:

```text
analysis_id
model_version_constraint
feature_schema_version
windows[]
deadline_ms
enable_calibrated_confidence
abstain_below_confidence
```

Response fields:

```text
predictions[]
model_version
feature_schema_version
partial_failure
worker_warnings
```

Each prediction includes:

```text
flow_id
window_id
traffic_class
class_probabilities
confidence
calibrated_confidence
abstained
abstention_reason
model_version
inference_time_ms
```

Errors:
`INVALID_ARGUMENT` for incompatible features; `RESOURCE_EXHAUSTED` for oversized
batches; `DEADLINE_EXCEEDED` for inference timeout; `UNAVAILABLE` for worker
failure. Go Core must degrade gracefully and mark ML evidence unavailable
rather than failing deterministic analysis.

## RPC — MLWorkerService.PredictSequenceBatch

gRPC Method Type:
Unary

Purpose:
Optionally runs a sequence model over packet size/timing sketches.

Request fields:

```text
analysis_id
sequence_schema_version
sequence_windows[]
deadline_ms
```

Response:
Same prediction envelope as `PredictBatch`, with model family and schema
recorded per prediction.

Errors:
`UNIMPLEMENTED` when the deployed worker has no sequence model.

## RPC — MLWorkerService.ExplainBatch

gRPC Method Type:
Unary

Purpose:
Returns SHAP or equivalent deterministic feature-attribution explanations for
selected predictions.

Request fields:

```text
prediction_ids
feature_windows
top_k
```

Response fields:

```text
explanations[]
model_version
explanation_method
partial_failure
```

Each explanation includes:

```text
prediction_id
flow_id
window_id
base_value
top_features[]
class_explanations[]
```

Errors:
`UNIMPLEMENTED` when SHAP is not available; `FAILED_PRECONDITION` when the
prediction/model versions do not match.

Go Core must persist model version, schema version, calibrated confidence,
abstention state, and explanation provenance with every ML evidence item
submitted to Fusion.

---

# SERVICE 11 — FusionOrchestrationService

The Fusion Engine contract is specified separately as an internal Go module
contract. This service is the frontend-facing facade for selected fused
conclusions, evidence chains, completeness, and conflicts.

```protobuf
service FusionOrchestrationService {
  rpc Run(RunFusionRequest) returns (RunFusionResponse);
  rpc GetStatus(GetFusionStatusRequest) returns (FusionStatus);
  rpc GetSummary(GetFusionSummaryRequest) returns (FusionSummary);
  rpc ListConclusions(ListFusedConclusionsRequest) returns (ListFusedConclusionsResponse);
  rpc GetConclusion(GetFusedConclusionRequest) returns (FusedConclusion);
  rpc GetEvidenceChain(GetEvidenceChainRequest) returns (EvidenceChain);
  rpc Recompute(RecomputeFusionRequest) returns (RecomputeFusionResponse);
}
```

---

## API 11.1 — Run

**RPC:** `FusionOrchestrationService.Run`  
**gRPC Method Type:** Unary


### Request

```json
{
  "analysis_id": "uuid",
  "include_passive": true,
  "include_vici": true,
  "include_xfrm": true,
  "include_ml": true,
  "include_security_rules": true
}
```

### Response

```json
{
  "fusion_run_id": "uuid",
  "state": "RUNNING"
}
```

---

## API 11.2 — GetStatus

**RPC:** `FusionOrchestrationService.GetStatus`  
**gRPC Method Type:** Unary


---

## API 11.3 — GetSummary

**RPC:** `FusionOrchestrationService.GetSummary`  
**gRPC Method Type:** Unary


Returns fusion completeness and unresolved conflicts.

---

## API 11.4 — ListConclusions

**RPC:** `FusionOrchestrationService.ListConclusions`  
**gRPC Method Type:** Unary


Examples:

```text
ike_version = IKEv2
esp_cipher = AES_GCM_256
vpn_mode = TUNNEL
pfs = ENABLED
traffic_class = VIDEO
replay_protection = ENABLED
```

Each conclusion includes:

```text
value
confidence
evidence_status
winning sources
conflicts
```

---

## API 11.5 — GetConclusion

**RPC:** `FusionOrchestrationService.GetConclusion`  
**gRPC Method Type:** Unary


---

## API 11.6 — GetEvidenceChain

**RPC:** `FusionOrchestrationService.GetEvidenceChain`  
**gRPC Method Type:** Unary


Returns every evidence item that contributed to a conclusion.

---

## API 11.7 — Recompute

**RPC:** `FusionOrchestrationService.Recompute`  
**gRPC Method Type:** Unary


Re-fuses current evidence after new ML or Deep Assessment data arrives.

---

# SERVICE 12 — ReportService

```protobuf
service ReportService {
  rpc Generate(GenerateReportRequest) returns (GenerateReportResponse);
  rpc Get(GetReportRequest) returns (Report);
  rpc Download(DownloadReportRequest) returns (stream ReportChunk);
  rpc Delete(DeleteReportRequest) returns (DeleteReportResponse);
  rpc ListTypes(ListReportTypesRequest) returns (ListReportTypesResponse);
}
```

---

## API 12.1 — Generate

**RPC:** `ReportService.Generate`  
**gRPC Method Type:** Unary


### Request

```json
{
  "analysis_id": "uuid",
  "type": "TECHNICAL",
  "format": "PDF",
  "include_timeline": true,
  "include_threat_matrix": true,
  "include_shap": true,
  "include_evidence_chain": true
}
```

### Response

```json
{
  "report_id": "uuid",
  "state": "GENERATING"
}
```

---

## API 12.2 — Get

**RPC:** `ReportService.Get`  
**gRPC Method Type:** Unary


---

## API 12.3 — Download

**RPC:** `ReportService.Download`  
**gRPC Method Type:** Server Streaming

Streams report bytes.

---

## API 12.4 — Delete

**RPC:** `ReportService.Delete`  
**gRPC Method Type:** Unary


Deletes temporary report.

---

## API 12.5 — ListTypes

**RPC:** `ReportService.ListTypes`  
**gRPC Method Type:** Unary


Returns:

```text
EXECUTIVE_PDF
TECHNICAL_PDF
JSON
```

---

# SERVICE 13 — EventService

All live frontend updates use one server-streaming API.

```protobuf
service EventService {
  rpc Subscribe(SubscribeRequest) returns (stream CoreEvent);
}
```

---

## API 13.1 — Subscribe

**RPC:** `EventService.Subscribe`  
**gRPC Method Type:** Server Streaming

### Filters

```text
workspace_id
analysis_id
event categories
```

### Core events

```text
WORKSPACE_RESET

SENSOR_CONNECTED
SENSOR_DISCONNECTED
SENSOR_MODE_CHANGED

SOURCE_READY

CAPTURE_STARTED
CAPTURE_STATS
CAPTURE_STOPPED

IPSEC_DETECTED
IKE_DETECTED
ESP_DETECTED
SA_DISCOVERED

ANALYSIS_STARTED
ANALYSIS_PROGRESS
ANALYSIS_COMPLETED
ANALYSIS_FAILED

SECURITY_FINDING_CREATED
SECURITY_SCORE_UPDATED

ML_INFERENCE_STARTED
ML_PREDICTION_UPDATED
ML_UNAVAILABLE

FUSION_STARTED
FUSION_CONCLUSION_UPDATED
FUSION_CONFLICT
FUSION_COMPLETED

REPORT_READY
```

---

# SERVICE 14 — RuntimeConfigService

```protobuf
service RuntimeConfigService {
  rpc Get(GetRuntimeConfigRequest) returns (RuntimeConfig);
  rpc Update(UpdateRuntimeConfigRequest) returns (RuntimeConfig);
  rpc RestoreDefaults(RestoreDefaultsRequest) returns (RuntimeConfig);
}
```

---

## API 14.1 — Get

**RPC:** `RuntimeConfigService.Get`  
**gRPC Method Type:** Unary


Config includes:

```text
local sensor module options
ML endpoint
fusion policy
ML timeout
fusion recomputation timeout
event buffer
report temp directory
default policy
default analysis mode
```

---

## API 14.2 — Update

**RPC:** `RuntimeConfigService.Update`  
**gRPC Method Type:** Unary


Applies safe runtime configuration changes.

---

## API 14.3 — RestoreDefaults

**RPC:** `RuntimeConfigService.RestoreDefaults`  
**gRPC Method Type:** Unary


---

# SERVICE 15 — ArtifactService

Temporary artifact visibility/cleanup.

```protobuf
service ArtifactService {
  rpc List(ListArtifactsRequest) returns (ListArtifactsResponse);
  rpc Get(GetArtifactRequest) returns (Artifact);
  rpc Delete(DeleteArtifactRequest) returns (DeleteArtifactResponse);
  rpc Cleanup(CleanupArtifactsRequest) returns (CleanupArtifactsResponse);
}
```

---

## API 15.1 — List

**RPC:** `ArtifactService.List`  
**gRPC Method Type:** Unary


Returns temporary:

```text
PCAP
PCAPNG
report
debug export
```

metadata.

---

## API 15.2 — Get

**RPC:** `ArtifactService.Get`  
**gRPC Method Type:** Unary


---

## API 15.3 — Delete

**RPC:** `ArtifactService.Delete`  
**gRPC Method Type:** Unary


---

## API 15.4 — Cleanup

**RPC:** `ArtifactService.Cleanup`  
**gRPC Method Type:** Unary


Deletes expired/unreferenced temp artifacts.

---

# 6. Go Core API inventory

| Service | RPC count |
|---|---:|
| CoreSystemService | 5 |
| WorkspaceService | 4 |
| LocalSensorStatusService | 4 |
| InputService | 10 |
| AnalysisService | 6 |
| ProtocolReadService | 10 |
| SecurityAssessmentService | 9 |
| RiskService | 4 |
| PolicyService | 6 |
| MLOrchestrationService | 8 |
| FusionOrchestrationService | 7 |
| ReportService | 5 |
| EventService | 1 |
| RuntimeConfigService | 3 |
| ArtifactService | 4 |
| **Total** | **86 RPCs** |

This is the complete v1 surface. It is not the recommended first coding milestone.

---

# 7. Main runtime flows

## Passive Live

```text
ProbeModes
   ↓
StartLive
   ↓
Sensor observations stream
   ↓
ML inference where enabled
   ↓
Fusion
   ↓
Security / Risk
   ↓
GetSummary / EventService
```

## Passive PCAP

```text
BeginPcapUpload
UploadPcapChunk*
CompletePcapUpload
ValidatePcap
   ↓
StartAnalysis
   ↓
Sensor offline processing
   ↓
ML inference where enabled
   ↓
Fusion
   ↓
Security / Risk
   ↓
Summary
```

## Deep Assessment

```text
ProbeModes
   ↓
StartLive
   ↓
Passive evidence
+ VICI evidence
+ XFRM evidence
   ↓
ML inference where enabled
   ↓
Fusion
   ↓
Security / Risk
   ↓
Final assessment
```

---

# 8. In-memory state

The Go Core should have one synchronized owner of mutable state:

```text
WorkspaceState
├── InputSource
├── SensorSession
├── ProtocolEvidence
├── FlowSummaries
├── SecurityAssessment
├── MLResults
├── FusionResults
├── RiskScore
├── Reports
└── EventBuffer
```

Do not allow every package to mutate maps independently.

---

# 9. Internal package recommendation

```text
go-core/
├── cmd/core/main.go
├── api/proto/core/v1/
├── internal/
│   ├── transport/grpc/
│   ├── workspace/
│   ├── sensor/
│   ├── input/
│   ├── analysis/
│   ├── protocol/
│   ├── security/
│   ├── risk/
│   ├── policy/
│   ├── mlclient/
│   ├── fusion/
│   ├── reports/
│   ├── events/
│   ├── state/
│   ├── artifacts/
│   └── config/
└── tests/
```

---

# 10. Implementation order

## Phase 1
- system
- workspace
- attach Sensor
- sensor status

## Phase 2
- PCAP upload proxy
- live start/stop
- input status

## Phase 3
- start analysis
- consume Sensor telemetry
- protocol read APIs

## Phase 4
- deterministic security findings
- policy
- risk score

## Phase 5
- EventService

## Phase 6
- Python ML orchestration

## Phase 7
- Fusion orchestration

## Phase 8
- reports

At the end of Phase 4 the Go Core already provides a useful deterministic IPsec security analyzer even before ML/Fusion are complete.
