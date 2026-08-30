package fusion

import (
	"context"

	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/confidence"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/conflict"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/correlation"
	fusionengine "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/engine"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/event"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/ingest"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/policy"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/provenance"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/query"
	fusionsession "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/session"
	fusionsystem "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/system"
)

// FusionSystemService is the in-process service 1 contract. It deliberately
// has no protobuf dependency because Fusion is compiled into Go Core in v1.
type FusionSystemService interface {
	Health(context.Context) (fusionsystem.HealthResponse, error)
	Readiness(context.Context) (fusionsystem.ReadinessResponse, error)
	GetVersion(context.Context) (fusionsystem.Version, error)
	GetCapabilities(context.Context) (fusionsystem.Capabilities, error)
}

// FusionSessionService is the in-process service 2 contract.
type FusionSessionService interface {
	Create(context.Context, fusionsession.CreateRequest) (model.Run, error)
	Get(context.Context, string) (model.Run, error)
	Finalize(context.Context, string) (fusionsession.FinalizeResponse, error)
	Cancel(context.Context, string) (fusionsession.CancelResponse, error)
	Reset(context.Context, string) (fusionsession.ResetResponse, error)
}

type EvidenceIngestService interface {
	Add(context.Context, ingest.AddRequest) (ingest.AddResponse, error)
	AddBatch(context.Context, ingest.AddBatchRequest) (ingest.AddBatchResponse, error)
	MarkSourceComplete(context.Context, ingest.MarkSourceRequest) (ingest.MarkSourceResponse, error)
	MarkSourceUnavailable(context.Context, ingest.MarkSourceUnavailableRequest) (ingest.MarkSourceResponse, error)
	Remove(context.Context, ingest.RemoveRequest) (ingest.RemoveResponse, error)
}

type EvidenceQueryService interface {
	List(context.Context, query.ListRequest) (query.ListResponse, error)
	Get(context.Context, query.GetRequest) (model.EvidenceItem, error)
	ListByProperty(context.Context, query.ListByPropertyRequest) (query.ListResponse, error)
	ListByResource(context.Context, query.ListByResourceRequest) (query.ListResponse, error)
	GetSourceCoverage(context.Context, string) (query.SourceCoverageResponse, error)
}

type CorrelationService interface {
	Correlate(context.Context, correlation.CorrelateRequest) (correlation.CorrelateResponse, error)
	GetCorrelation(context.Context, correlation.GetRequest) (correlation.CorrelationDetail, error)
	ListCorrelations(context.Context, correlation.ListRequest) (correlation.ListResponse, error)
	Rebuild(context.Context, string) (correlation.RebuildResponse, error)
}

type ConflictResolutionService interface {
	Detect(context.Context, conflict.DetectRequest) (conflict.DetectResponse, error)
	List(context.Context, conflict.ListRequest) (conflict.ListResponse, error)
	Get(context.Context, conflict.GetRequest) (conflict.Detail, error)
	Resolve(context.Context, conflict.ResolveRequest) (conflict.ResolveResponse, error)
	Reevaluate(context.Context, conflict.DetectRequest) (conflict.ReevaluateResponse, error)
}

type ConfidenceService interface {
	Calculate(context.Context, confidence.CalculateRequest) (confidence.Result, error)
	GetBreakdown(context.Context, confidence.GetBreakdownRequest) (model.ConfidenceBreakdown, error)
	CalibrateML(context.Context, confidence.CalibrateMLRequest) (confidence.CalibratedConfidence, error)
}

type FusionService interface {
	Run(context.Context, fusionengine.RunRequest) (fusionengine.RunResponse, error)
	Recompute(context.Context, fusionengine.RecomputeRequest) (fusionengine.RecomputeResponse, error)
	GetStatus(context.Context, string) (fusionengine.Status, error)
	GetSummary(context.Context, string) (fusionengine.Summary, error)
	ListConclusions(context.Context, fusionengine.ListConclusionsRequest) (fusionengine.ListConclusionsResponse, error)
	GetConclusion(context.Context, fusionengine.GetConclusionRequest) (model.FusedConclusion, error)
	GetCompleteness(context.Context, string) (fusionengine.Completeness, error)
}

type ProvenanceService interface {
	GetEvidenceChain(context.Context, provenance.ConclusionRequest) (provenance.EvidenceChain, error)
	ExplainDecision(context.Context, provenance.ConclusionRequest) (provenance.DecisionExplanation, error)
	GetSourceContribution(context.Context, provenance.ConclusionRequest) (provenance.SourceContribution, error)
	GetTimeline(context.Context, provenance.ConclusionRequest) (provenance.FusionTimeline, error)
}

type FusionPolicyService interface {
	List(context.Context, policy.ListRequest) (policy.ListResponse, error)
	Get(context.Context, policy.GetRequest) (policy.Definition, error)
	GetActive(context.Context) (policy.Definition, error)
	SetActive(context.Context, policy.SetActiveRequest) (policy.SetActiveResponse, error)
	Validate(context.Context, policy.ValidateRequest) (policy.ValidateResponse, error)
	Reload(context.Context, policy.ReloadRequest) (policy.ReloadResponse, error)
}

type FusionEventService interface {
	Subscribe(context.Context, event.SubscribeRequest) (event.Subscription, error)
}

var (
	_ FusionSystemService       = (*fusionsystem.Service)(nil)
	_ FusionSessionService      = (*fusionsession.Service)(nil)
	_ EvidenceIngestService     = (*ingest.Service)(nil)
	_ EvidenceQueryService      = (*query.Service)(nil)
	_ CorrelationService        = (*correlation.Service)(nil)
	_ ConflictResolutionService = (*conflict.Service)(nil)
	_ ConfidenceService         = (*confidence.Service)(nil)
	_ FusionService             = (*fusionengine.Service)(nil)
	_ ProvenanceService         = (*provenance.Service)(nil)
	_ FusionPolicyService       = (*policy.Service)(nil)
	_ FusionEventService        = (*event.Service)(nil)
)
