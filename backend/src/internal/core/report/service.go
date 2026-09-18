// Package report creates bounded, temporary exports from existing Core views.
package report

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	artifactv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/artifact"
	eventv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/event"
	fusionv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/fusion"
	reportv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/report"
	flowv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/flow"
	coreanalysis "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/analysis"
	coreartifact "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/artifact"
	corefusion "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/fusion"
	coreinput "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/input"
	coreml "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/ml"
	coreprotocol "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/protocolread"
	corerisk "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/risk"
	coresecurity "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/security"
	coresystem "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/system"
	coreworkspace "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/workspace"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/query"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/flow"
	"google.golang.org/protobuf/proto"
)

const ttl = 24 * time.Hour

type Record struct {
	ID, AnalysisID, ArtifactID, Failure string
	Type                                reportv1.ReportType
	Format                              reportv1.ReportFormat
	State                               reportv1.ReportState
	CreatedAt, UpdatedAt, ExpiresAt     time.Time
}
type Service struct {
	mu        sync.RWMutex
	records   map[string]*Record
	analysis  *coreanalysis.Service
	fusion    *corefusion.Service
	artifacts *coreartifact.Service
	workspace *coreworkspace.Service
	security  *coresecurity.Service
	risk      *corerisk.Service
	ml        *coreml.Service
	protocol  *coreprotocol.Service
	flows     *flow.Service
	system    coresystem.Service
	events    interface {
		Publish(context.Context, string, eventv1.CoreEventCategory)
	}
}

func New(analysis *coreanalysis.Service, fusion *corefusion.Service, artifacts *coreartifact.Service, workspace *coreworkspace.Service, security *coresecurity.Service, risk *corerisk.Service, ml *coreml.Service, events interface {
	Publish(context.Context, string, eventv1.CoreEventCategory)
}) *Service {
	return &Service{records: map[string]*Record{}, analysis: analysis, fusion: fusion, artifacts: artifacts, workspace: workspace, security: security, risk: risk, ml: ml, events: events}
}

// SetDashboardSources adds the read models used by the dashboard so a PDF can
// carry the same analysis detail without coupling report generation to HTTP.
func (s *Service) SetDashboardSources(protocol *coreprotocol.Service, flows *flow.Service, system coresystem.Service) {
	s.protocol, s.flows, s.system = protocol, flows, system
}
func (s *Service) Generate(ctx context.Context, request *reportv1.GenerateReportRequest) (Record, error) {
	if err := contextError(ctx); err != nil {
		return Record{}, err
	}
	if s == nil || s.analysis == nil || s.fusion == nil || s.artifacts == nil {
		return Record{}, shared.NewError(shared.Internal, "", "report service is not configured")
	}
	if request == nil || strings.TrimSpace(request.GetAnalysisId()) == "" {
		return Record{}, shared.NewError(shared.InvalidArgument, "", "analysis_id is required")
	}
	if request.GetType() == reportv1.ReportType_REPORT_TYPE_UNSPECIFIED || request.GetFormat() == reportv1.ReportFormat_REPORT_FORMAT_UNSPECIFIED {
		return Record{}, shared.NewError(shared.InvalidArgument, "", "type and format are required")
	}
	if (request.GetType() == reportv1.ReportType_JSON) != (request.GetFormat() == reportv1.ReportFormat_JSON_FORMAT) {
		return Record{}, shared.NewError(shared.InvalidArgument, "", "JSON reports require JSON format; executive and technical reports require PDF format")
	}
	if _, err := s.analysis.Get(ctx, request.GetAnalysisId()); err != nil {
		return Record{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Record{}, err
	}
	now := time.Now().UTC()
	record := &Record{ID: id.String(), AnalysisID: request.GetAnalysisId(), Type: request.GetType(), Format: request.GetFormat(), State: reportv1.ReportState_GENERATING, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(ttl)}
	s.mu.Lock()
	s.records[record.ID] = record
	s.mu.Unlock()
	s.bindWorkspace(record, "GENERATING")
	if s.events != nil {
		s.events.Publish(context.Background(), record.AnalysisID, eventv1.CoreEventCategory_REPORT_GENERATION_STARTED)
	}
	requestCopy := proto.Clone(request).(*reportv1.GenerateReportRequest)
	go s.renderReport(record.ID, requestCopy)
	return *record, nil
}
func (s *Service) renderReport(id string, request *reportv1.GenerateReportRequest) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conclusions, _, err := s.fusion.List(ctx, request.GetAnalysisId(), &fusionv1.ListFusedConclusionsRequest{PageSize: 1000})
	if err == nil {
		body, mime, name := s.render(ctx, request, conclusions)
		var artifact coreartifact.Record
		artifact, err = s.artifacts.Create(ctx, request.GetAnalysisId(), name, mime, artifactv1.ArtifactType_REPORT, body, ttl)
		if err == nil {
			_ = s.artifacts.SetReferenced(ctx, artifact.ID, true)
			s.mu.Lock()
			if r := s.records[id]; r != nil {
				if r.State == reportv1.ReportState_DELETED {
					s.mu.Unlock()
					_, _ = s.artifacts.Delete(ctx, artifact.ID)
					return
				}
				r.ArtifactID = artifact.ID
				r.State = reportv1.ReportState_READY
				r.UpdatedAt = time.Now().UTC()
				s.bindWorkspace(r, "READY")
				if s.events != nil {
					s.events.Publish(context.Background(), r.AnalysisID, eventv1.CoreEventCategory_REPORT_READY)
				}
			}
			s.mu.Unlock()
			return
		}
	}
	s.mu.Lock()
	if r := s.records[id]; r != nil {
		r.State = reportv1.ReportState_FAILED
		r.Failure = err.Error()
		r.UpdatedAt = time.Now().UTC()
		s.bindWorkspace(r, "FAILED")
	}
	s.mu.Unlock()
}
func (s *Service) Get(ctx context.Context, id string) (Record, error) {
	if err := contextError(ctx); err != nil {
		return Record{}, err
	}
	s.mu.RLock()
	r := s.records[id]
	if r != nil {
		c := *r
		r = &c
	}
	s.mu.RUnlock()
	if r == nil {
		return Record{}, shared.NewError(shared.NotFound, "", "report was not found")
	}
	return *r, nil
}
func (s *Service) Delete(ctx context.Context, id string) (bool, error) {
	r, err := s.Get(ctx, id)
	if err != nil {
		return false, err
	}
	if r.ArtifactID != "" {
		if _, err = s.artifacts.Delete(ctx, r.ArtifactID); err != nil {
			return false, err
		}
	}
	s.mu.Lock()
	if current := s.records[id]; current != nil {
		current.State = reportv1.ReportState_DELETED
		current.UpdatedAt = time.Now().UTC()
		s.bindWorkspace(current, "DELETED")
	}
	s.mu.Unlock()
	return true, nil
}
func (s *Service) Open(ctx context.Context, id string) (*coreartifact.Record, error) {
	r, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if r.State != reportv1.ReportState_READY {
		return nil, shared.NewError(shared.FailedPrecondition, "", "report is not ready")
	}
	a, err := s.artifacts.Get(ctx, r.ArtifactID)
	return &a, err
}
func (s *Service) Artifact(ctx context.Context, id string) (coreartifact.Record, error) {
	r, err := s.Get(ctx, id)
	if err != nil {
		return coreartifact.Record{}, err
	}
	if r.ArtifactID == "" {
		return coreartifact.Record{}, nil
	}
	return s.artifacts.Get(ctx, r.ArtifactID)
}
func (s *Service) ArtifactOpen(ctx context.Context, id string) (io.ReadCloser, coreartifact.Record, error) {
	return s.artifacts.Open(ctx, id)
}
func (s *Service) render(ctx context.Context, r *reportv1.GenerateReportRequest, conclusions []*fusionv1.FusedConclusion) ([]byte, string, string) {
	generatedAt := time.Now().UTC()
	analysisRecord, _ := s.analysis.Get(ctx, r.GetAnalysisId())
	inputSource, sourceErr := s.analysis.Source(ctx, r.GetAnalysisId())
	payload := map[string]interface{}{"analysis_id": r.GetAnalysisId(), "report_type": r.GetType().String(), "generated_at": generatedAt.Format(time.RFC3339), "analysis_mode": analysisRecord.Mode.String(), "analysis_state": analysisRecord.State.String(), "analysis_stage": analysisRecord.Stage.String(), "source_id": analysisRecord.SourceID, "options": map[string]bool{"include_timeline": r.GetIncludeTimeline(), "include_threat_matrix": r.GetIncludeThreatMatrix(), "include_shap": r.GetIncludeShap(), "include_evidence_chain": r.GetIncludeEvidenceChain()}, "fused_conclusions": conclusions}
	if progress, err := s.analysis.ProgressDetails(ctx, r.GetAnalysisId()); err == nil {
		payload["analysis_progress"] = progress
	}
	if summary, err := s.analysis.SummaryDetails(ctx, r.GetAnalysisId()); err == nil {
		payload["analysis_summary"] = summary
	}
	if sourceErr == nil {
		payload["input"] = map[string]interface{}{"mode": inputSource.Mode.String(), "filename": inputSource.Filename, "size_bytes": inputSource.Size, "packets_total": inputSource.Counters.PacketsTotal, "bytes_total": inputSource.Counters.BytesTotal, "ike_packets": inputSource.Counters.IKEPackets, "esp_packets": inputSource.Counters.ESPPackets, "ah_packets": inputSource.Counters.AHPackets, "nat_t_packets": inputSource.Counters.NATTPackets, "packet_drops": inputSource.Counters.PacketDrops}
	}
	if r.GetIncludeTimeline() {
		timeline := make([]map[string]interface{}, 0, len(conclusions))
		for _, conclusion := range conclusions {
			timeline = append(timeline, map[string]interface{}{"time": conclusion.GetComputedAt().AsTime(), "property_key": conclusion.GetPropertyKey(), "resource_id": conclusion.GetResourceId(), "rationale": conclusion.GetRationaleCode()})
		}
		payload["fusion_timeline"] = timeline
	}
	if s.security != nil {
		if assessment, err := s.security.LatestForAnalysis(ctx, r.GetAnalysisId()); err == nil {
			payload["security_assessment"] = assessment.Result
			payload["security_assessment_revision"] = assessment.Revision
			payload["security_assessment_updated_at"] = assessment.UpdatedAt
			payload["per_sa_assessments"] = assessment.PerSAAssessments
			payload["incomplete_sa_resource_ids"] = assessment.IncompleteSAResourceIDs
			payload["unknown_evidence_count"] = assessment.UnknownEvidence
			payload["metadata_exposure"] = assessment.MetadataExposure
			if s.risk != nil {
				if score, scoreErr := s.risk.Score(ctx, assessment.ID); scoreErr == nil {
					payload["risk_score"] = score
				}
				if breakdown, breakdownErr := s.risk.Breakdown(ctx, assessment.ID); breakdownErr == nil {
					payload["risk_breakdown"] = breakdown
				}
				if overrides, overridesErr := s.risk.Overrides(ctx, assessment.ID); overridesErr == nil {
					payload["critical_overrides"] = overrides
				}
				if r.GetIncludeThreatMatrix() {
					payload["threat_matrix"] = assessment.Result.ThreatMatrix
				}
			}
		}
	}
	if status, err := s.fusion.Status(ctx, r.GetAnalysisId()); err == nil {
		payload["fusion_status"] = status
	}
	if summary, err := s.fusion.Summary(ctx, r.GetAnalysisId()); err == nil {
		payload["fusion_summary"] = summary
	}
	if s.protocol != nil {
		if sessions, _, err := s.protocol.Sessions(ctx, r.GetAnalysisId(), 1000, ""); err == nil {
			payload["vpn_sessions"] = sessions
		}
		if exchanges, _, err := s.protocol.IKE(ctx, r.GetAnalysisId(), "", 1000, ""); err == nil {
			payload["ike_exchanges"] = exchanges
		}
		if associations, _, err := s.protocol.SAs(ctx, r.GetAnalysisId(), "", 1000, ""); err == nil {
			payload["security_associations"] = associations
		}
		if nat, err := s.protocol.NAT(ctx, r.GetAnalysisId(), ""); err == nil {
			payload["nat_traversal"] = nat
		}
		if evidence, _, err := s.protocol.Evidence(ctx, r.GetAnalysisId(), query.Filter{}, 1000, ""); err == nil {
			payload["protocol_evidence"] = evidence
		}
	}
	if inputSource.SessionID != "" && s.flows != nil {
		if records, _, err := s.flows.List(ctx, &flowv1.ListFlowsRequest{SensorSessionId: inputSource.SessionID, PageSize: 1000}); err == nil {
			flows := make([]reportFlow, 0, len(records))
			for _, record := range records {
				flows = append(flows, reportFlow{Flow: flow.ToProto(record), Stats: flow.Stats(record)})
			}
			payload["flow_records"] = flows
		}
	}
	if r.GetIncludeEvidenceChain() {
		chains := make(map[string]*fusionv1.EvidenceChain, len(conclusions))
		for _, conclusion := range conclusions {
			if chain, err := s.fusion.Chain(ctx, r.GetAnalysisId(), conclusion.GetConclusionId()); err == nil {
				chains[conclusion.GetConclusionId()] = chain
			}
		}
		payload["evidence_chains"] = chains
	}
	if s.ml != nil {
		if worker, err := s.ml.WorkerStatus(ctx); err == nil {
			payload["ml_worker"] = worker
		}
		if inferenceID, predictions, explanations, err := s.ml.LatestForAnalysis(ctx, r.GetAnalysisId()); err == nil {
			payload["ml_inference_id"] = inferenceID
			payload["ml_predictions"] = predictions
			if r.GetIncludeShap() {
				payload["shap_explanations"] = explanations
			}
		}
	}
	if s.system != nil {
		if readiness, err := s.system.Readiness(ctx); err == nil {
			payload["system_readiness"] = readiness
		}
		if capabilities, err := s.system.Capabilities(ctx); err == nil {
			payload["system_capabilities"] = capabilities
		}
		if stats, err := s.system.RuntimeStats(ctx); err == nil {
			payload["system_runtime"] = stats
		}
	}
	raw, _ := json.MarshalIndent(payload, "", "  ")
	if r.GetFormat() == reportv1.ReportFormat_JSON_FORMAT {
		return raw, "application/json", "analysis-report.json"
	}
	var source *coreinput.Source
	if sourceErr == nil {
		source = &inputSource
	}
	document := buildReportDocumentForType(analysisRecord, source, conclusions, payload, r.GetType(), generatedAt)
	return buildReportPDF(document), "application/pdf", "alchemist-ipsec-analysis-report.pdf"
}

type reportFlow struct {
	Flow  *flowv1.Flow
	Stats *flowv1.FlowStats
}

// reportPDF deliberately uses a small, dependency-free PDF writer. It keeps
// reports readable when a heavier rendering runtime is unavailable and avoids
// exposing raw evidence payloads or key material.
func reportPDF(analysisID string, conclusions []*fusionv1.FusedConclusion, payload map[string]interface{}) []byte {
	record := coreanalysis.Record{ID: analysisID, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	return buildReportPDF(buildReportDocument(record, nil, conclusions, payload, time.Now().UTC()))
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return shared.NewError(shared.InvalidArgument, "", "context is required")
	}
	return ctx.Err()
}
func (s *Service) bindWorkspace(report *Record, status string) {
	if s.workspace == nil {
		return
	}
	workspaceID, generation, err := s.workspace.CurrentOwnership(context.Background())
	if err != nil {
		return
	}
	s.workspace.UpdateIfCurrent(workspaceID, generation, func(current *coreworkspace.Record) {
		if current.AnalysisID == report.AnalysisID {
			if status == "DELETED" && current.ReportID == report.ID {
				current.ReportID, current.ReportStatus = "", ""
				return
			}
			current.ReportID, current.ReportStatus = report.ID, status
		}
	})
}
