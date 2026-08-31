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
	coreworkspace "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/workspace"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
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
	events    interface {
		Publish(context.Context, string, eventv1.CoreEventCategory)
	}
}

func New(analysis *coreanalysis.Service, fusion *corefusion.Service, artifacts *coreartifact.Service, workspace *coreworkspace.Service, events interface {
	Publish(context.Context, string, eventv1.CoreEventCategory)
}) *Service {
	return &Service{records: map[string]*Record{}, analysis: analysis, fusion: fusion, artifacts: artifacts, workspace: workspace, events: events}
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
	copy := *request
	go s.render(record.ID, &copy)
	return *record, nil
}
func (s *Service) render(id string, request *reportv1.GenerateReportRequest) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conclusions, _, err := s.fusion.List(ctx, request.GetAnalysisId(), &fusionv1.ListFusedConclusionsRequest{PageSize: 1000})
	if err == nil {
		body, mime, name := render(request, conclusions)
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
func render(r *reportv1.GenerateReportRequest, conclusions []*fusionv1.FusedConclusion) ([]byte, string, string) {
	payload := map[string]interface{}{"analysis_id": r.GetAnalysisId(), "report_type": r.GetType().String(), "generated_at": time.Now().UTC().Format(time.RFC3339), "options": map[string]bool{"include_timeline": r.GetIncludeTimeline(), "include_threat_matrix": r.GetIncludeThreatMatrix(), "include_shap": r.GetIncludeShap(), "include_evidence_chain": r.GetIncludeEvidenceChain()}, "conclusions": conclusions}
	raw, _ := json.MarshalIndent(payload, "", "  ")
	if r.GetFormat() == reportv1.ReportFormat_JSON_FORMAT {
		return raw, "application/json", "analysis-report.json"
	}
	return minimalPDF(string(raw)), "application/pdf", "analysis-report.pdf"
}
func minimalPDF(content string) []byte {
	content = strings.ReplaceAll(content, "\\", "\\\\")
	content = strings.ReplaceAll(content, "(", "\\(")
	content = strings.ReplaceAll(content, ")", "\\)")
	content = strings.ReplaceAll(content, "\n", " ")
	if len(content) > 3000 {
		content = content[:3000]
	}
	stream := "BT /F1 9 Tf 40 780 Td (" + content + ") Tj ET"
	objects := []string{"<</Type/Catalog/Pages 2 0 R>>", "<</Type/Pages/Count 1/Kids[3 0 R]>>", "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<</Font<</F1 4 0 R>>>>/Contents 5 0 R>>", "<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>", fmt.Sprintf("<</Length %d>>stream\n%s\nendstream", len(stream), stream)}
	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objects)+1)
	for i, object := range objects {
		offsets[i+1] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i+1, object)
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, offset := range offsets[1:] {
		fmt.Fprintf(&out, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&out, "trailer\n<</Size %d/Root 1 0 R>>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return out.Bytes()
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
