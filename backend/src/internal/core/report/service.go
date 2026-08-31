// Package report creates bounded, temporary exports from existing Core views.
package report

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	artifactv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/artifact"
	eventv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/event"
	fusionv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/fusion"
	reportv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/report"
	coreanalysis "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/analysis"
	coreartifact "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/artifact"
	corefusion "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/fusion"
	coreml "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/ml"
	corerisk "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/risk"
	coresecurity "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/security"
	coreworkspace "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/workspace"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
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
	events    interface {
		Publish(context.Context, string, eventv1.CoreEventCategory)
	}
}

func New(analysis *coreanalysis.Service, fusion *corefusion.Service, artifacts *coreartifact.Service, workspace *coreworkspace.Service, security *coresecurity.Service, risk *corerisk.Service, ml *coreml.Service, events interface {
	Publish(context.Context, string, eventv1.CoreEventCategory)
}) *Service {
	return &Service{records: map[string]*Record{}, analysis: analysis, fusion: fusion, artifacts: artifacts, workspace: workspace, security: security, risk: risk, ml: ml, events: events}
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
	payload := map[string]interface{}{"analysis_id": r.GetAnalysisId(), "report_type": r.GetType().String(), "generated_at": time.Now().UTC().Format(time.RFC3339), "options": map[string]bool{"include_timeline": r.GetIncludeTimeline(), "include_threat_matrix": r.GetIncludeThreatMatrix(), "include_shap": r.GetIncludeShap(), "include_evidence_chain": r.GetIncludeEvidenceChain()}, "fused_conclusions": conclusions}
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
			payload["unknown_evidence_count"] = assessment.UnknownEvidence
			payload["metadata_exposure"] = assessment.MetadataExposure
			if s.risk != nil {
				if score, scoreErr := s.risk.Score(ctx, assessment.ID); scoreErr == nil {
					payload["risk_score"] = score
				}
				if breakdown, breakdownErr := s.risk.Breakdown(ctx, assessment.ID); breakdownErr == nil {
					payload["risk_breakdown"] = breakdown
				}
				if r.GetIncludeThreatMatrix() {
					payload["threat_matrix"] = assessment.Result.ThreatMatrix
				}
			}
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
		if inferenceID, predictions, explanations, err := s.ml.LatestForAnalysis(ctx, r.GetAnalysisId()); err == nil {
			payload["ml_inference_id"] = inferenceID
			payload["ml_predictions"] = predictions
			if r.GetIncludeShap() {
				payload["shap_explanations"] = explanations
			}
		}
	}
	raw, _ := json.MarshalIndent(payload, "", "  ")
	if r.GetFormat() == reportv1.ReportFormat_JSON_FORMAT {
		return raw, "application/json", "analysis-report.json"
	}
	return reportPDF(r.GetAnalysisId(), conclusions, payload), "application/pdf", "analysis-report.pdf"
}

// reportPDF deliberately uses a small, dependency-free PDF writer. It keeps
// reports readable when a heavier rendering runtime is unavailable and avoids
// exposing raw evidence payloads or key material.
func reportPDF(analysisID string, conclusions []*fusionv1.FusedConclusion, payload map[string]interface{}) []byte {
	sections := []pdfSection{
		{"Executive Summary", []string{"Analysis: " + analysisID, "Generated: " + time.Now().UTC().Format(time.RFC3339), fmt.Sprintf("Fused conclusions: %d", len(conclusions)), "This report is based on Fusion winning conclusions; raw source precedence is not re-evaluated here."}},
		{"Protocol / IPsec Details", conclusionLines(conclusions, []string{"ike.", "child.", "esp.", "ah.", "nat_"})},
		{"Security Findings", payloadLines(payload, "security_assessment", "No completed security assessment was available.")},
		{"Risk Score", payloadLines(payload, "risk_score", "No risk score was available.")},
		{"Fusion / Evidence Table", conclusionLines(conclusions, nil)},
		{"Traffic Summary", conclusionLines(conclusions, []string{"traffic."})},
		{"ML Results", payloadLines(payload, "ml_predictions", "No ML predictions were available.")},
		{"Technical Appendix", []string{"Evidence chains, source availability, and optional timelines are included according to the requested report options.", compactJSON(payload)}},
	}
	return buildPDF(sections)
}

type pdfSection struct {
	title string
	lines []string
}

func conclusionLines(conclusions []*fusionv1.FusedConclusion, prefixes []string) []string {
	lines := make([]string, 0, len(conclusions))
	for _, conclusion := range conclusions {
		if conclusion == nil {
			continue
		}
		if len(prefixes) > 0 {
			matched := false
			for _, prefix := range prefixes {
				if strings.HasPrefix(conclusion.GetPropertyKey(), prefix) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		value := conclusion.GetValue()
		lines = append(lines, fmt.Sprintf("%-38s %-20s confidence %.2f (%s)", conclusion.GetPropertyKey(), value, conclusion.GetConfidence(), conclusion.GetRationaleCode()))
	}
	if len(lines) == 0 {
		return []string{"No data available."}
	}
	return lines
}
func payloadLines(payload map[string]interface{}, key, fallback string) []string {
	value, ok := payload[key]
	if !ok {
		return []string{fallback}
	}
	return wrapPDFText(compactJSON(value), 100)
}
func compactJSON(value interface{}) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	return string(raw)
}
func buildPDF(sections []pdfSection) []byte {
	pages := [][]string{}
	current := []string{}
	appendLine := func(line string) {
		if len(current) >= 45 {
			pages = append(pages, current)
			current = []string{}
		}
		current = append(current, line)
	}
	for _, section := range sections {
		appendLine("# " + section.title)
		for _, line := range section.lines {
			for _, wrapped := range wrapPDFText(line, 100) {
				appendLine(wrapped)
			}
		}
		appendLine("")
	}
	if len(current) > 0 {
		pages = append(pages, current)
	}
	if len(pages) == 0 {
		pages = append(pages, []string{"# Report", "No content available."})
	}
	objects := []string{"<</Type/Catalog/Pages 2 0 R>>"}
	kids := make([]string, len(pages))
	for index := range pages {
		kids[index] = fmt.Sprintf("%d 0 R", 3+index*2)
	}
	objects = append(objects, fmt.Sprintf("<</Type/Pages/Count %d/Kids[%s]>>", len(pages), strings.Join(kids, " ")))
	fontObject := 3 + len(pages)*2
	for index, lines := range pages {
		pageObject := 3 + index*2
		contentObject := pageObject + 1
		objects = append(objects, fmt.Sprintf("<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<</Font<</F1 %d 0 R/F2 %d 0 R>>>>/Contents %d 0 R>>", fontObject, fontObject+1, contentObject))
		stream := pdfStream(lines)
		objects = append(objects, fmt.Sprintf("<</Length %d>>stream\n%s\nendstream", len(stream), stream))
	}
	objects = append(objects, "<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>", "<</Type/Font/Subtype/Type1/BaseFont/Helvetica-Bold>>")
	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objects)+1)
	for index, object := range objects {
		offsets[index+1] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", index+1, object)
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, offset := range offsets[1:] {
		fmt.Fprintf(&out, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&out, "trailer\n<</Size %d/Root 1 0 R>>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return out.Bytes()
}
func pdfStream(lines []string) string {
	var builder strings.Builder
	builder.WriteString("BT\n40 760 Td\n")
	for _, line := range lines {
		font := "/F1 9 Tf"
		if strings.HasPrefix(line, "# ") {
			font = "/F2 14 Tf"
			line = strings.TrimPrefix(line, "# ")
		}
		fmt.Fprintf(&builder, "%s (%s) Tj 0 -15 Td\n", font, escapePDF(line))
	}
	builder.WriteString("ET")
	return builder.String()
}
func escapePDF(value string) string {
	value = strings.ToValidUTF8(value, "?")
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "(", "\\(")
	return strings.ReplaceAll(value, ")", "\\)")
}
func wrapPDFText(value string, width int) []string {
	if width <= 0 || len(value) <= width {
		return []string{value}
	}
	out := []string{}
	for len(value) > width {
		cut := strings.LastIndex(value[:width], " ")
		if cut <= 0 {
			cut = width
		}
		out = append(out, value[:cut])
		value = strings.TrimSpace(value[cut:])
	}
	return append(out, value)
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
