# IPsec Security Analyzer — Evidence Fusion Engine Internal Contract Specification v1.0

> **Scope:** This document specifies the **Evidence Fusion Engine logical module** inside the one Go Server.
>
> The Fusion Engine combines evidence produced by:
>
> - Passive packet analysis
> - StrongSwan VICI Deep Assessment
> - Linux XFRM Deep Assessment
> - Python ML traffic classification
> - SHAP explainability
> - Security-rule finding references for provenance/reporting
>
> **Deployment rule:** In v1 the Fusion Engine is compiled into the Go Server as a dedicated package. It is not a separate Go service and must not be called through gRPC from Go Core. The service/method names below define the internal Go interface contract. If the engine is extracted in a later release, these method names can map to protobuf/gRPC without redesigning the domain objects.
>
> **Critical principle:** Fusion does not invent facts. It resolves and explains evidence.

---

# 1. Fusion Engine responsibility

The Fusion Engine answers:

> **Given multiple observations from different sources, what should the platform believe, with what confidence, and why?**

Fusion runs after evidence is available. In the ML path, the order is:

```text
Sensor feature windows
      ↓
Python ML Worker inference
      ↓
ML prediction / confidence / SHAP evidence
      ↓
Fusion recomputation
      ↓
Security Engine / Risk Engine / Reports
```

During live analysis Fusion may run incrementally before ML finishes using
passive, VICI, or XFRM evidence. When ML evidence arrives, Fusion must
recompute the affected traffic-classification and metadata-exposure
conclusions.

Fusion does not modify VPN state, enforce policy, or perform remediation. It
produces fused conclusions for downstream security assessment.

Security-security finding references must not create a circular dependency. The primary
fusion pass consumes Sensor, VICI, XFRM, ML, and SHAP evidence to produce
protocol, configuration, traffic, and metadata conclusions. The Security
Engine then consumes those conclusions to create findings. Security-rule
references may be attached afterward for provenance/reporting, but they do not
override protocol facts such as `ike.version`, `child.mode`, `esp.spi`, or
`replay.window`.

Examples:

```text
Passive packet parser:
IKE Version = IKEv2
status = OBSERVED

VICI:
IKE Version = IKEv2
status = VERIFIED_GATEWAY

Fusion:
IKE Version = IKEv2
confidence = 1.0
status = VERIFIED_GATEWAY
sources = [PACKET_PARSER, STRONGSWAN_VICI]
```

Conflict example:

```text
Passive derived mode = TUNNEL (0.72)
VICI mode = TRANSPORT (verified)

Fusion:
mode = TRANSPORT
confidence = 1.0
winning_source = STRONGSWAN_VICI
conflict = true
```

---

# 2. Evidence sources

```protobuf
enum EvidenceSource {
  EVIDENCE_SOURCE_UNSPECIFIED = 0;

  PACKET_PARSER = 1;
  FLOW_ANALYZER = 2;

  STRONGSWAN_VICI = 10;
  LINUX_XFRM = 11;

  ML_XGBOOST = 20;
  ML_TCN = 21;
  SHAP = 22;

  SECURITY_RULE_ENGINE = 30; // finding/provenance references only

  OPERATOR_INPUT = 40;
}
```

---

# 3. Evidence status

```protobuf
enum EvidenceStatus {
  EVIDENCE_STATUS_UNSPECIFIED = 0;
  OBSERVED = 1;
  DERIVED = 2;
  INFERRED = 3;
  VERIFIED_GATEWAY = 4;
  UNKNOWN = 5;
}
```

Recommended trust precedence:

```text
VERIFIED_GATEWAY
    >
OBSERVED
    >
DERIVED
    >
INFERRED
```

But precedence alone is not enough; freshness, relevance and conflict policy also matter.

---

# 4. Core evidence object

Every evidence item must include:

```protobuf
message EvidenceItem {
  string evidence_id = 1;

  string analysis_id = 2;

  string property_key = 3;

  google.protobuf.Value value = 4;

  EvidenceSource source = 5;

  EvidenceStatus status = 6;

  double confidence = 7;

  google.protobuf.Timestamp observed_at = 8;

  string resource_type = 9;
  string resource_id = 10;

  string source_reference = 11;

  string schema_version = 12;

  map<string,string> metadata = 13;
}
```

Examples of `property_key`:

```text
ike.version
ike.encryption
ike.integrity
ike.prf
ike.dh_group

child.mode
child.esp_encryption
child.integrity
child.pfs

sa.lifetime
sa.rekey_time

esp.spi
replay.enabled
replay.window

traffic.class
traffic.confidence

metadata.exposure

security.rule.IPSEC_PFS_001
```

---

# 5. Fused conclusion object

```protobuf
message FusedConclusion {
  string conclusion_id = 1;

  string analysis_id = 2;

  string property_key = 3;

  google.protobuf.Value value = 4;

  double confidence = 5;

  EvidenceStatus status = 6;

  repeated string evidence_ids = 7;

  repeated EvidenceSource winning_sources = 8;

  bool has_conflict = 9;

  string conflict_id = 10;

  string rationale_code = 11;

  google.protobuf.Timestamp computed_at = 12;
}
```

---

# 6. Fusion service catalogue

| # | Service | Responsibility |
|---|---|---|
| 1 | `FusionSystemService` | Health, readiness, version, capabilities |
| 2 | `FusionSessionService` | Fusion run lifecycle |
| 3 | `EvidenceIngestService` | Ingest normalized evidence from Go Core |
| 4 | `EvidenceQueryService` | Query stored in-memory evidence |
| 5 | `CorrelationService` | Correlate flows, SPIs, IKE SAs, CHILD SAs, sessions |
| 6 | `ConflictResolutionService` | Detect and resolve contradictory evidence |
| 7 | `ConfidenceService` | Calculate fused confidence |
| 8 | `FusionService` | Execute fusion and expose final conclusions |
| 9 | `ProvenanceService` | Explain exactly how a conclusion was produced |
| 10 | `FusionPolicyService` | Source precedence, freshness, conflict and thresholds |
| 11 | `FusionEventService` | Live fusion event stream |

---

# SERVICE 1 — FusionSystemService

```protobuf
service FusionSystemService {
  rpc Health(HealthRequest) returns (HealthResponse);
  rpc Readiness(ReadinessRequest) returns (ReadinessResponse);
  rpc GetVersion(GetVersionRequest) returns (GetVersionResponse);
  rpc GetCapabilities(GetCapabilitiesRequest) returns (GetCapabilitiesResponse);
}
```

---

## API 1.1 — Health

**Internal Method:** `FusionSystemService.Health`  
**Internal Call Shape:** Unary

### Request

```json
{}
```

### Response

```json
{
  "status": "HEALTHY"
}
```

---

## API 1.2 — Readiness

**Internal Method:** `FusionSystemService.Readiness`  
**Internal Call Shape:** Unary


Checks:

```text
policy loaded
in-memory evidence store ready
correlator ready
conflict engine ready
confidence engine ready
```

---

## API 1.3 — GetVersion

**Internal Method:** `FusionSystemService.GetVersion`  
**Internal Call Shape:** Unary


Returns:

```text
fusion engine version
API schema
policy schema
build commit
```

---

## API 1.4 — GetCapabilities

**Internal Method:** `FusionSystemService.GetCapabilities`  
**Internal Call Shape:** Unary


Returns support for:

```text
passive evidence
VICI evidence
XFRM evidence
ML evidence
SHAP evidence
security finding references
conflict detection
confidence calculation
provenance
incremental recomputation
```

---

# SERVICE 2 — FusionSessionService

A Fusion Run is scoped to one Go Core analysis.

```protobuf
service FusionSessionService {
  rpc Create(CreateFusionRunRequest) returns (FusionRun);
  rpc Get(GetFusionRunRequest) returns (FusionRun);
  rpc Finalize(FinalizeFusionRunRequest) returns (FinalizeFusionRunResponse);
  rpc Cancel(CancelFusionRunRequest) returns (CancelFusionRunResponse);
  rpc Reset(ResetFusionRunRequest) returns (ResetFusionRunResponse);
}
```

---

## API 2.1 — Create

**Internal Method:** `FusionSessionService.Create`  
**Internal Call Shape:** Unary


### Request

```json
{
  "analysis_id": "uuid",
  "policy_id": "fusion-default-v1"
}
```

### Response

```json
{
  "fusion_run_id": "uuid",
  "state": "ACTIVE",
  "created_at": "..."
}
```

---

## API 2.2 — Get

**Internal Method:** `FusionSessionService.Get`  
**Internal Call Shape:** Unary


Returns:

```text
run ID
analysis ID
state
evidence count
conclusion count
conflict count
created/updated timestamps
```

---

## API 2.3 — Finalize

**Internal Method:** `FusionSessionService.Finalize`  
**Internal Call Shape:** Unary


### Purpose

Marks the current run complete after all required evidence sources have either:

```text
completed
failed
timed out
or been explicitly marked unavailable
```

### Response

Final summary.

---

## API 2.4 — Cancel

**Internal Method:** `FusionSessionService.Cancel`  
**Internal Call Shape:** Unary


---

## API 2.5 — Reset

**Internal Method:** `FusionSessionService.Reset`  
**Internal Call Shape:** Unary


Clears all evidence, correlations, conflicts and conclusions for the run.

---

# SERVICE 3 — EvidenceIngestService

```protobuf
service EvidenceIngestService {
  rpc Add(AddEvidenceRequest) returns (AddEvidenceResponse);
  rpc AddBatch(AddEvidenceBatchRequest) returns (AddEvidenceBatchResponse);
  rpc MarkSourceComplete(MarkSourceCompleteRequest) returns (MarkSourceCompleteResponse);
  rpc MarkSourceUnavailable(MarkSourceUnavailableRequest) returns (MarkSourceUnavailableResponse);
  rpc Remove(RemoveEvidenceRequest) returns (RemoveEvidenceResponse);
}
```

---

## API 3.1 — Add

**Internal Method:** `EvidenceIngestService.Add`  
**Internal Call Shape:** Unary


### Request

```json
{
  "fusion_run_id": "uuid",
  "evidence": {
    "property_key": "ike.version",
    "value": "IKEv2",
    "source": "PACKET_PARSER",
    "status": "OBSERVED",
    "confidence": 1.0,
    "resource_type": "IKE_SA",
    "resource_id": "ike-..."
  }
}
```

### Response

```json
{
  "evidence_id": "uuid",
  "accepted": true,
  "triggered_recompute": true
}
```

---

## API 3.2 — AddBatch

**Internal Method:** `EvidenceIngestService.AddBatch`  
**Internal Call Shape:** Unary


Preferred for:

```text
VICI snapshot
XFRM snapshot
many flow predictions
many protocol observations
```

### Response

```text
accepted count
rejected count
validation errors
recompute scheduled
```

---

## API 3.3 — MarkSourceComplete

**Internal Method:** `EvidenceIngestService.MarkSourceComplete`  
**Internal Call Shape:** Unary


### Request

```json
{
  "fusion_run_id": "uuid",
  "source": "STRONGSWAN_VICI"
}
```

This helps Finalize know no more VICI evidence is expected.

---

## API 3.4 — MarkSourceUnavailable

**Internal Method:** `EvidenceIngestService.MarkSourceUnavailable`  
**Internal Call Shape:** Unary


### Request

```json
{
  "fusion_run_id": "uuid",
  "source": "LINUX_XFRM",
  "reason_code": "XFRM_NOT_AVAILABLE"
}
```

The Fusion Engine must not treat unavailable evidence as negative evidence.

---

## API 3.5 — Remove

**Internal Method:** `EvidenceIngestService.Remove`  
**Internal Call Shape:** Unary


Useful when Go Core invalidates stale evidence during a live session.

---

# SERVICE 4 — EvidenceQueryService

```protobuf
service EvidenceQueryService {
  rpc List(ListEvidenceRequest) returns (ListEvidenceResponse);
  rpc Get(GetEvidenceRequest) returns (EvidenceItem);
  rpc ListByProperty(ListEvidenceByPropertyRequest) returns (ListEvidenceResponse);
  rpc ListByResource(ListEvidenceByResourceRequest) returns (ListEvidenceResponse);
  rpc GetSourceCoverage(GetSourceCoverageRequest) returns (SourceCoverage);
}
```

---

## API 4.1 — List

**Internal Method:** `EvidenceQueryService.List`  
**Internal Call Shape:** Unary


Filters:

```text
source
status
property_key
resource_type
resource_id
time range
```

---

## API 4.2 — Get

**Internal Method:** `EvidenceQueryService.Get`  
**Internal Call Shape:** Unary


---

## API 4.3 — ListByProperty

**Internal Method:** `EvidenceQueryService.ListByProperty`  
**Internal Call Shape:** Unary


Example:

```text
property_key = child.mode
```

returns every Passive/VICI/XFRM value for that property.

---

## API 4.4 — ListByResource

**Internal Method:** `EvidenceQueryService.ListByResource`  
**Internal Call Shape:** Unary


Example:

```text
resource_type = CHILD_SA
resource_id = child-123
```

---

## API 4.5 — GetSourceCoverage

**Internal Method:** `EvidenceQueryService.GetSourceCoverage`  
**Internal Call Shape:** Unary


### Response

```json
{
  "PACKET_PARSER": "COMPLETE",
  "STRONGSWAN_VICI": "COMPLETE",
  "LINUX_XFRM": "UNAVAILABLE",
  "ML_XGBOOST": "COMPLETE",
  "SECURITY_RULE_ENGINE": "COMPLETE"
}
```

---

# SERVICE 5 — CorrelationService

Correlation is one of the most important parts of Fusion.

The engine must determine which evidence items refer to the same logical object.

```protobuf
service CorrelationService {
  rpc Correlate(CorrelateRequest) returns (CorrelateResponse);
  rpc GetCorrelation(GetCorrelationRequest) returns (CorrelationGroup);
  rpc ListCorrelations(ListCorrelationsRequest) returns (ListCorrelationsResponse);
  rpc Rebuild(RebuildCorrelationsRequest) returns (RebuildCorrelationsResponse);
}
```

---

## API 5.1 — Correlate

**Internal Method:** `CorrelationService.Correlate`  
**Internal Call Shape:** Unary


### Correlation keys may include

```text
IKE initiator SPI
IKE responder SPI
ESP SPI
AH SPI
reqid
endpoint tuple
direction
time overlap
traffic selectors
StrongSwan unique ID
XFRM state identity
```

### Response

```json
{
  "correlation_groups_created": 8,
  "evidence_items_linked": 42,
  "ambiguous_items": 2
}
```

---

## API 5.2 — GetCorrelation

**Internal Method:** `CorrelationService.GetCorrelation`  
**Internal Call Shape:** Unary


Returns one logical resource and linked evidence.

---

## API 5.3 — ListCorrelations

**Internal Method:** `CorrelationService.ListCorrelations`  
**Internal Call Shape:** Unary


Filters:

```text
IKE_SA
CHILD_SA
ESP_STREAM
VPN_SESSION
FLOW
```

---

## API 5.4 — Rebuild

**Internal Method:** `CorrelationService.Rebuild`  
**Internal Call Shape:** Unary


Re-runs correlation after new Deep Assessment evidence arrives.

---

# SERVICE 6 — ConflictResolutionService

```protobuf
service ConflictResolutionService {
  rpc Detect(DetectConflictsRequest) returns (DetectConflictsResponse);
  rpc List(ListConflictsRequest) returns (ListConflictsResponse);
  rpc Get(GetConflictRequest) returns (EvidenceConflict);
  rpc Resolve(ResolveConflictRequest) returns (ResolveConflictResponse);
  rpc Reevaluate(ReevaluateConflictsRequest) returns (ReevaluateConflictsResponse);
}
```

---

## API 6.1 — Detect

**Internal Method:** `ConflictResolutionService.Detect`  
**Internal Call Shape:** Unary


### Example conflict

```text
Passive derived mode: TUNNEL, confidence 0.72
VICI mode: TRANSPORT, verified
```

### Response

```text
conflicts_found
affected conclusions
```

---

## API 6.2 — List

**Internal Method:** `ConflictResolutionService.List`  
**Internal Call Shape:** Unary


---

## API 6.3 — Get

**Internal Method:** `ConflictResolutionService.Get`  
**Internal Call Shape:** Unary


Returns:

```text
property
resource
candidate values
source
status
confidence
freshness
resolution state
```

---

## API 6.4 — Resolve

**Internal Method:** `ConflictResolutionService.Resolve`  
**Internal Call Shape:** Unary


### Modes

```text
POLICY
MANUAL_OPERATOR_OVERRIDE
```

Manual overrides are optional future functionality; v1 may accept only `POLICY`.

### Response

Winning evidence and rationale code.

---

## API 6.5 — Reevaluate

**Internal Method:** `ConflictResolutionService.Reevaluate`  
**Internal Call Shape:** Unary


Re-evaluates conflicts after new evidence arrives.

---

# SERVICE 7 — ConfidenceService

Confidence is deterministic and policy-driven.

```protobuf
service ConfidenceService {
  rpc Calculate(CalculateConfidenceRequest) returns (ConfidenceResult);
  rpc GetBreakdown(GetConfidenceBreakdownRequest) returns (ConfidenceBreakdown);
  rpc CalibrateML(CalibrateMLConfidenceRequest) returns (CalibratedConfidence);
}
```

---

## API 7.1 — Calculate

**Internal Method:** `ConfidenceService.Calculate`  
**Internal Call Shape:** Unary


### Inputs

```text
candidate evidence
source trust
evidence status
model confidence
agreement
freshness
correlation quality
```

### Response

```json
{
  "confidence": 0.98,
  "band": "VERY_HIGH"
}
```

---

## API 7.2 — GetBreakdown

**Internal Method:** `ConfidenceService.GetBreakdown`  
**Internal Call Shape:** Unary


### Example

```json
{
  "source_trust": 1.0,
  "agreement": 1.0,
  "freshness": 0.99,
  "correlation_quality": 0.96,
  "model_confidence": null,
  "final_confidence": 0.98
}
```

---

## API 7.3 — CalibrateML

**Internal Method:** `ConfidenceService.CalibrateML`  
**Internal Call Shape:** Unary


### Purpose

Consumes the Python ML worker's already calibrated probability plus model metadata and converts it to the platform's common confidence band.

It must not falsely transform a weak ML result into verified evidence.

---

# SERVICE 8 — FusionService

```protobuf
service FusionService {
  rpc Run(RunFusionRequest) returns (RunFusionResponse);
  rpc Recompute(RecomputeFusionRequest) returns (RecomputeFusionResponse);
  rpc GetStatus(GetFusionStatusRequest) returns (FusionStatus);
  rpc GetSummary(GetFusionSummaryRequest) returns (FusionSummary);
  rpc ListConclusions(ListFusedConclusionsRequest) returns (ListFusedConclusionsResponse);
  rpc GetConclusion(GetFusedConclusionRequest) returns (FusedConclusion);
  rpc GetCompleteness(GetFusionCompletenessRequest) returns (FusionCompleteness);
}
```

---

## API 8.1 — Run

**Internal Method:** `FusionService.Run`  
**Internal Call Shape:** Unary


### Request

```json
{
  "fusion_run_id": "uuid",
  "incremental": true
}
```

### Processing

1. validate evidence
2. correlate resources
3. group by property
4. detect conflicts
5. apply source/status policy
6. calculate confidence
7. create/update conclusions
8. emit events

### Response

```json
{
  "state": "RUNNING"
}
```

---

## API 8.2 — Recompute

**Internal Method:** `FusionService.Recompute`  
**Internal Call Shape:** Unary


Designed for live mode.

Example:

```text
new VICI CHILD SA event
        ↓
Add evidence
        ↓
Recompute affected properties only
```

Avoid full recomputation when possible.

---

## API 8.3 — GetStatus

**Internal Method:** `FusionService.GetStatus`  
**Internal Call Shape:** Unary


---

## API 8.4 — GetSummary

**Internal Method:** `FusionService.GetSummary`  
**Internal Call Shape:** Unary


### Response

```json
{
  "state": "COMPLETE",
  "evidence_count": 92,
  "conclusion_count": 31,
  "conflict_count": 1,
  "unresolved_conflicts": 0,
  "source_coverage": {
    "passive": true,
    "vici": true,
    "xfrm": true,
    "ml": true,
    "security_rules": true
  }
}
```

---

## API 8.5 — ListConclusions

**Internal Method:** `FusionService.ListConclusions`  
**Internal Call Shape:** Unary


Filters:

```text
property prefix
resource type
resource ID
status
has_conflict
minimum confidence
```

---

## API 8.6 — GetConclusion

**Internal Method:** `FusionService.GetConclusion`  
**Internal Call Shape:** Unary


### Example

```json
{
  "property_key": "child.mode",
  "value": "TUNNEL",
  "confidence": 1.0,
  "status": "VERIFIED_GATEWAY",
  "winning_sources": [
    "STRONGSWAN_VICI",
    "LINUX_XFRM"
  ],
  "evidence_ids": ["e1", "e2", "e3"],
  "has_conflict": false
}
```

---

## API 8.7 — GetCompleteness

**Internal Method:** `FusionService.GetCompleteness`  
**Internal Call Shape:** Unary


### Purpose

Tells Go Core whether the final result is complete enough for reporting.

### Response

```json
{
  "overall": 0.91,
  "required_properties": 22,
  "resolved_properties": 20,
  "unknown_properties": 2,
  "missing_sources": []
}
```

---

# SERVICE 9 — ProvenanceService

This is the "How do we know this?" API.

```protobuf
service ProvenanceService {
  rpc GetEvidenceChain(GetEvidenceChainRequest) returns (EvidenceChain);
  rpc ExplainDecision(ExplainFusionDecisionRequest) returns (FusionDecisionExplanation);
  rpc GetSourceContribution(GetSourceContributionRequest) returns (SourceContribution);
  rpc GetTimeline(GetFusionTimelineRequest) returns (FusionTimeline);
}
```

---

## API 9.1 — GetEvidenceChain

**Internal Method:** `ProvenanceService.GetEvidenceChain`  
**Internal Call Shape:** Unary


### Response

```text
final conclusion
↓
winning evidence
↓
supporting evidence
↓
conflicting evidence
↓
source references
```

---

## API 9.2 — ExplainDecision

**Internal Method:** `ProvenanceService.ExplainDecision`  
**Internal Call Shape:** Unary


No LLM is required.

Example output:

```json
{
  "rationale_code": "VERIFIED_OVERRIDES_DERIVED",
  "summary": "Gateway-verified VICI evidence was selected over a passive derived value.",
  "winning_evidence_ids": ["e2"],
  "rejected_evidence_ids": ["e1"]
}
```

This should use deterministic templates.

---

## API 9.3 — GetSourceContribution

**Internal Method:** `ProvenanceService.GetSourceContribution`  
**Internal Call Shape:** Unary


Example:

```json
{
  "PACKET_PARSER": 0.31,
  "STRONGSWAN_VICI": 0.41,
  "LINUX_XFRM": 0.17,
  "ML_XGBOOST": 0.11
}
```

This is descriptive provenance, not a security score.

---

## API 9.4 — GetTimeline

**Internal Method:** `ProvenanceService.GetTimeline`  
**Internal Call Shape:** Unary


Shows how a conclusion evolved during live analysis.

Example:

```text
12:00:01 child.mode = UNKNOWN
12:00:03 child.mode = TUNNEL (derived 0.72)
12:00:04 VICI arrives
12:00:04 child.mode = TUNNEL (verified 1.0)
```

---

# SERVICE 10 — FusionPolicyService

Fusion policy is distinct from security policy.

Security policy answers:

> Is this configuration secure?

Fusion policy answers:

> Which evidence should I trust when sources disagree?

```protobuf
service FusionPolicyService {
  rpc List(ListFusionPoliciesRequest) returns (ListFusionPoliciesResponse);
  rpc Get(GetFusionPolicyRequest) returns (FusionPolicy);
  rpc GetActive(GetActiveFusionPolicyRequest) returns (FusionPolicy);
  rpc SetActive(SetActiveFusionPolicyRequest) returns (SetActiveFusionPolicyResponse);
  rpc Validate(ValidateFusionPolicyRequest) returns (ValidateFusionPolicyResponse);
  rpc Reload(ReloadFusionPoliciesRequest) returns (ReloadFusionPoliciesResponse);
}
```

---

## API 10.1 — List

**Internal Method:** `FusionPolicyService.List`  
**Internal Call Shape:** Unary


---

## API 10.2 — Get

**Internal Method:** `FusionPolicyService.Get`  
**Internal Call Shape:** Unary


### Policy fields

```text
source trust weights
status precedence
freshness windows
minimum confidence
conflict thresholds
correlation thresholds
required sources
property-specific overrides
```

---

## API 10.3 — GetActive

**Internal Method:** `FusionPolicyService.GetActive`  
**Internal Call Shape:** Unary


---

## API 10.4 — SetActive

**Internal Method:** `FusionPolicyService.SetActive`  
**Internal Call Shape:** Unary


---

## API 10.5 — Validate

**Internal Method:** `FusionPolicyService.Validate`  
**Internal Call Shape:** Unary


Checks:

```text
invalid trust values
missing source definition
bad precedence
unknown property
negative freshness interval
conflicting overrides
```

---

## API 10.6 — Reload

**Internal Method:** `FusionPolicyService.Reload`  
**Internal Call Shape:** Unary


Policies are loaded from local versioned files.

---

# SERVICE 11 — FusionEventService

```protobuf
service FusionEventService {
  rpc Subscribe(SubscribeFusionEventsRequest)
      returns (stream FusionEvent);
}
```

---

## API 11.1 — Subscribe

**Internal Method:** `FusionEventService.Subscribe`  
**Internal Call Shape:** Server Streaming

### Events

```text
FUSION_RUN_CREATED

EVIDENCE_ADDED
EVIDENCE_REMOVED
SOURCE_COMPLETED
SOURCE_UNAVAILABLE

CORRELATION_CREATED
CORRELATION_CHANGED

CONFLICT_DETECTED
CONFLICT_RESOLVED

CONFIDENCE_UPDATED

CONCLUSION_CREATED
CONCLUSION_UPDATED

FUSION_COMPLETENESS_UPDATED

FUSION_FINALIZED
FUSION_FAILED
```

Go Core can subscribe and forward relevant events to Next.js.

---

# 7. Fusion API inventory

| Service | Method count |
|---|---:|
| FusionSystemService | 4 |
| FusionSessionService | 5 |
| EvidenceIngestService | 5 |
| EvidenceQueryService | 5 |
| CorrelationService | 4 |
| ConflictResolutionService | 5 |
| ConfidenceService | 3 |
| FusionService | 7 |
| ProvenanceService | 4 |
| FusionPolicyService | 6 |
| FusionEventService | 1 |
| **Total** | **49 internal methods** |

---

# 8. Recommended source-trust semantics

These are conceptual defaults only and should live in policy files.

## Verified gateway sources

```text
STRONGSWAN_VICI
LINUX_XFRM
```

Highest trust for properties they directly expose.

## Passive protocol parser

High trust for directly observable packet facts:

```text
IKE version
SPI
protocol
endpoint
exchange type
```

Lower authority for hidden/configuration-derived claims.

## ML

ML may only create `INFERRED` evidence.

Example:

```text
traffic.class = VIDEO
confidence = 0.943
status = INFERRED
```

It must never become `VERIFIED_GATEWAY`.

## Security rule engine

Rules create security findings, not protocol facts.

Example:

```text
security.rule.IPSEC_PFS_001 = FAIL
```

This should reference the fused `child.pfs` evidence rather than replace it.

---

# 9. Property-specific fusion rules

Do not use one global precedence rule blindly.

Example:

## IKE version

```text
VICI verified
or
packet-observed
```

Both are strong.

## CHILD SA mode

```text
VICI/XFRM verified
>
passive derived
```

## Traffic class

```text
ML only
```

unless a trusted ground-truth source exists in the testbed.

## Replay protection

```text
XFRM verified
>
gateway/VICI evidence if available
>
passive sequence anomaly observation
```

A duplicate ESP sequence observation is not equivalent to verified replay-policy state.

---

# 10. Conflict examples

## Example A — no conflict

```text
Packet:
IKEv2 observed

VICI:
IKEv2 verified
```

Fusion:

```text
IKEv2
confidence 1.0
VERIFIED_GATEWAY
```

---

## Example B — conflict resolved by authority

```text
Passive:
mode = TUNNEL
confidence = 0.72
DERIVED

VICI:
mode = TRANSPORT
confidence = 1.0
VERIFIED_GATEWAY
```

Fusion:

```text
mode = TRANSPORT
confidence = 1.0
has_conflict = true
resolution = VERIFIED_OVERRIDES_DERIVED
```

---

## Example C — ML uncertainty

```text
XGBoost:
VIDEO 0.46
FILE_TRANSFER 0.41
```

Fusion should not return:

```text
VIDEO — high confidence
```

Instead:

```text
traffic.class = VIDEO
confidence = 0.46
status = INFERRED
ambiguity = HIGH
```

or policy may return:

```text
traffic.class = UNKNOWN
```

when below threshold.

---

# 11. Live incremental fusion

Do not wait for the entire session to finish.

Example:

```text
T0
Packet parser finds IKEv2
→ conclusion created

T1
ESP SPI discovered
→ SA correlation created

T2
ML returns VIDEO 0.91
→ traffic conclusion created

T3
VICI snapshot arrives
→ crypto/mode conclusions upgraded to VERIFIED_GATEWAY

T4
XFRM replay window arrives
→ replay conclusion created

T5
Security rule engine runs
→ final assessment updates
```

Use affected-property recomputation rather than recomputing everything on every event.

---

# 12. Internal Go package structure

If Fusion runs inside Go Core:

```text
internal/fusion/
├── model/
├── ingest/
├── store/
├── correlation/
├── conflict/
├── confidence/
├── policy/
├── engine/
├── provenance/
└── events/
```

If extracted later:

```text
fusion-service/
├── cmd/fusion/
├── api/proto/fusion/v1/
└── internal/...
```

The domain objects should stay identical.

---

# 13. In-memory state

```text
FusionRunState
├── EvidenceByID
├── EvidenceByProperty
├── EvidenceByResource
├── SourceCoverage
├── CorrelationGroups
├── Conflicts
├── ConfidenceResults
├── Conclusions
├── ProvenanceGraph
└── EventBuffer
```

All state disappears on process/workspace reset in v1.

---

# 14. Fusion should not perform security scoring

Keep boundaries clean.

Fusion:

```text
"What is the best-supported value?"
```

Security Engine:

```text
"Is that value secure under policy?"
```

Risk Engine:

```text
"What score should those findings produce?"
```

Example:

```text
Fusion:
child.pfs = false
verified

Security rule:
PFS disabled → HIGH finding

Risk engine:
apply penalty / score cap
```

Do not merge these responsibilities.

---

# 15. Fusion should not call an LLM

The Fusion decision must remain:

```text
deterministic
auditable
reproducible
```

An optional LLM may later consume:

```text
fused conclusions
findings
provenance
```

to produce natural-language explanations.

The LLM must not alter Fusion output.

---

# 16. Completion criteria

Fusion v1 is complete when it can:

- accept Passive evidence
- accept VICI evidence
- accept XFRM evidence
- accept ML evidence
- accept security finding references for provenance/reporting
- correlate evidence to sessions/SAs/flows
- detect conflicting values
- resolve conflicts using policy
- calculate common confidence
- preserve provenance
- emit fused conclusions
- mark unknown/unavailable values explicitly
- recompute incrementally
- expose live fusion events
- provide evidence chain for every conclusion
- finalize only when required sources are complete/unavailable/timeout
- operate entirely in memory for v1

---

# 17. Recommended implementation order

## Phase 1
- FusionSystemService
- FusionSessionService
- basic in-memory evidence store

## Phase 2
- EvidenceIngestService
- EvidenceQueryService

## Phase 3
- CorrelationService

## Phase 4
- basic property fusion
- FusionService

## Phase 5
- ConflictResolutionService

## Phase 6
- ConfidenceService

## Phase 7
- ProvenanceService

## Phase 8
- FusionPolicyService

## Phase 9
- FusionEventService
- incremental recomputation

At the end of Phase 4 the engine can already combine Passive + VICI/XFRM + ML evidence into useful conclusions. Later phases make the result production-grade and explainable.
