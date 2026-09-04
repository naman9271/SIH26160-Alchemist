package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"

	analysisv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/analysis"
	fusionv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/fusion"
	inputv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/input"
	reportv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/report"
	workspacev1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/workspace"
	flowv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/flow"
	coreanalysis "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/analysis"
	corefusion "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/fusion"
	coreinput "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/input"
	coreml "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/ml"
	coreprotocol "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/protocolread"
	corereport "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/report"
	corerisk "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/risk"
	coresecurity "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/security"
	coreworkspace "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/workspace"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/query"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/flow"
)

const maxHTTPPCAPBytes = 4 << 30

func registerWorkflowAPI(mux *http.ServeMux, input *coreinput.Service, analysis *coreanalysis.Service, reports *corereport.Service, workspace *coreworkspace.Service, protocol *coreprotocol.Service, fusion *corefusion.Service, security *coresecurity.Service, risk *corerisk.Service, ml *coreml.Service, flows *flow.Service) {
	mux.HandleFunc("POST /api/v1/pcap", func(w http.ResponseWriter, r *http.Request) { uploadPCAP(w, r, input, workspace) })
	mux.HandleFunc("POST /api/v1/analyses", func(w http.ResponseWriter, r *http.Request) { startAnalysis(w, r, analysis) })
	mux.HandleFunc("GET /api/v1/analyses/{analysisID}", func(w http.ResponseWriter, r *http.Request) { getAnalysis(w, r, analysis) })
	mux.HandleFunc("GET /api/v1/analyses/{analysisID}/insights", func(w http.ResponseWriter, r *http.Request) {
		getAnalysisInsights(w, r, input, analysis, protocol, fusion, security, risk, ml, flows)
	})
	mux.HandleFunc("POST /api/v1/analyses/{analysisID}/report", func(w http.ResponseWriter, r *http.Request) { generateReport(w, r, reports) })
	mux.HandleFunc("GET /api/v1/reports/{reportID}", func(w http.ResponseWriter, r *http.Request) { getReport(w, r, reports) })
	mux.HandleFunc("GET /api/v1/reports/{reportID}/download", func(w http.ResponseWriter, r *http.Request) { downloadReport(w, r, reports) })
}

// getAnalysisInsights is deliberately a read-only, browser-oriented view of
// the current analysis. Native gRPC remains the complete trusted-client API;
// this endpoint exposes the data needed by the dashboard without publishing a
// generic gRPC proxy to browsers.
func getAnalysisInsights(w http.ResponseWriter, r *http.Request, input *coreinput.Service, analysis *coreanalysis.Service, protocol *coreprotocol.Service, fusion *corefusion.Service, security *coresecurity.Service, risk *corerisk.Service, ml *coreml.Service, flows *flow.Service) {
	analysisID := r.PathValue("analysisID")
	record, err := analysis.Get(r.Context(), analysisID)
	if err != nil {
		writeWorkflowError(w, err)
		return
	}
	progress, _ := analysis.ProgressDetails(r.Context(), analysisID)
	summary, _ := analysis.SummaryDetails(r.Context(), analysisID)

	result := map[string]any{
		"analysis": map[string]any{"analysis_id": record.ID, "source_id": record.SourceID, "state": record.State.String(), "stage": record.Stage.String(), "failure_reason": record.Failure, "created_at": record.CreatedAt, "updated_at": record.UpdatedAt},
		"progress": progress,
		"summary":  summary,
	}

	if protocol != nil {
		section := map[string]any{}
		if value, sectionErr := protocol.Summary(r.Context(), analysisID); sectionErr == nil {
			section["summary"] = value
		}
		if value, _, sectionErr := protocol.Sessions(r.Context(), analysisID, 100, ""); sectionErr == nil {
			section["sessions"] = value
		}
		if value, _, sectionErr := protocol.IKE(r.Context(), analysisID, "", 100, ""); sectionErr == nil {
			section["ike_exchanges"] = value
		}
		if value, _, sectionErr := protocol.SAs(r.Context(), analysisID, "", 100, ""); sectionErr == nil {
			section["security_associations"] = value
		}
		if value, _, sectionErr := protocol.Crypto(r.Context(), analysisID, "", 100, ""); sectionErr == nil {
			section["crypto_properties"] = value
		}
		if value, sectionErr := protocol.NAT(r.Context(), analysisID, ""); sectionErr == nil {
			section["nat_traversal"] = value
		}
		if value, _, sectionErr := protocol.Timeline(r.Context(), analysisID, "", 200, ""); sectionErr == nil {
			section["timeline"] = value
		}
		if value, _, sectionErr := protocol.Evidence(r.Context(), analysisID, query.Filter{}, 200, ""); sectionErr == nil {
			section["evidence"] = value
		}
		result["protocol"] = section
	}

	if fusion != nil {
		section := map[string]any{}
		if value, sectionErr := fusion.Status(r.Context(), analysisID); sectionErr == nil {
			section["status"] = value
		}
		if value, sectionErr := fusion.Summary(r.Context(), analysisID); sectionErr == nil {
			section["summary"] = value
		}
		if value, _, sectionErr := fusion.List(r.Context(), analysisID, &fusionv1.ListFusedConclusionsRequest{PageSize: 200}); sectionErr == nil {
			section["conclusions"] = value
		}
		result["fusion"] = section
	}

	if security != nil {
		section := map[string]any{}
		if assessment, sectionErr := security.LatestForAnalysis(r.Context(), analysisID); sectionErr == nil {
			findings, _ := security.Findings(r.Context(), assessment.ID, "")
			recommendations, _ := security.Recommendations(r.Context(), assessment.ID)
			section["assessment"] = map[string]any{"assessment_id": assessment.ID, "policy_id": assessment.PolicyID, "state": assessment.State.String(), "score": assessment.Result.Score, "grade": assessment.Result.Grade, "findings": findings, "threat_matrix": assessment.Result.ThreatMatrix, "rules_evaluated": assessment.Result.EvaluatedRule, "unknown_evidence_count": assessment.UnknownEvidence, "metadata_exposure": assessment.MetadataExposure, "recommendations": recommendations}
			if risk != nil {
				if value, scoreErr := risk.Score(r.Context(), assessment.ID); scoreErr == nil {
					section["risk_score"] = value
				}
				if value, breakdownErr := risk.Breakdown(r.Context(), assessment.ID); breakdownErr == nil {
					section["risk_breakdown"] = value
				}
				if value, overridesErr := risk.Overrides(r.Context(), assessment.ID); overridesErr == nil {
					section["critical_overrides"] = value
				}
			}
		}
		result["security"] = section
	}

	if ml != nil {
		section := map[string]any{}
		if inferenceID, predictions, explanations, sectionErr := ml.LatestForAnalysis(r.Context(), analysisID); sectionErr == nil {
			section["inference_id"], section["predictions"], section["explanations"] = inferenceID, predictions, explanations
		}
		if worker, sectionErr := ml.WorkerStatus(r.Context()); sectionErr == nil {
			section["worker"] = worker
		}
		result["ml"] = section
	}

	// Flow telemetry is collected by the in-process Sensor service. Keep it in
	// this analysis-scoped response so browsers never need direct access to the
	// Sensor gRPC API or its session identifiers.
	if input != nil && flows != nil {
		section := map[string]any{}
		if source, sourceErr := input.Get(r.Context(), record.SourceID); sourceErr == nil && source.SessionID != "" {
			if records, next, flowErr := flows.List(r.Context(), &flowv1.ListFlowsRequest{SensorSessionId: source.SessionID, PageSize: 200}); flowErr == nil {
				items := make([]any, 0, len(records))
				for _, item := range records {
					items = append(items, map[string]any{"flow": flow.ToProto(item), "stats": flow.Stats(item)})
				}
				section["items"], section["next_page_token"] = items, next
			}
		}
		result["flows"] = section
	}

	writeJSON(w, http.StatusOK, result)
}

func uploadPCAP(w http.ResponseWriter, r *http.Request, input *coreinput.Service, workspace *coreworkspace.Service) {
	r.Body = http.MaxBytesReader(w, r.Body, maxHTTPPCAPBytes)
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		writeWorkflowError(w, err)
		return
	}
	file, header, err := r.FormFile("pcap")
	if err != nil {
		writeWorkflowError(w, shared.NewError(shared.InvalidArgument, shared.InvalidPCAP, "a pcap file is required"))
		return
	}
	defer file.Close()
	if header.Size <= 0 {
		writeWorkflowError(w, shared.NewError(shared.InvalidArgument, shared.InvalidPCAP, "PCAP file must not be empty"))
		return
	}
	if header.Size > maxHTTPPCAPBytes {
		writeWorkflowError(w, shared.NewError(shared.ResourceExhausted, shared.InvalidPCAP, "PCAP exceeds 4 GiB upload limit"))
		return
	}
	if workspace != nil {
		if _, err := workspace.Create(r.Context(), "PCAP: "+filepath.Base(header.Filename), "http-upload-"+filepath.Base(header.Filename)); err != nil {
			writeWorkflowError(w, err)
			return
		}
	}
	uploadID, err := input.BeginUpload(r.Context(), &inputv1.BeginPcapUploadRequest{Filename: header.Filename, SizeBytes: uint64(header.Size)})
	if err != nil {
		writeWorkflowError(w, err)
		return
	}
	buffer := make([]byte, coreinput.ChunkSize)
	for index := uint64(0); ; index++ {
		count, readErr := file.Read(buffer)
		if count > 0 {
			if _, err := input.UploadChunk(r.Context(), &inputv1.UploadPcapChunkRequest{UploadId: uploadID, ChunkIndex: index, Data: buffer[:count]}); err != nil {
				writeWorkflowError(w, err)
				return
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			writeWorkflowError(w, readErr)
			return
		}
	}
	source, err := input.CompleteUpload(r.Context(), uploadID)
	if err != nil {
		writeWorkflowError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"source_id": source.ID, "pcap_id": source.PCAPID, "filename": source.Filename, "state": source.State.String(), "packets": source.Counters.PacketsTotal, "bytes": source.Counters.BytesTotal, "ike_packets": source.Counters.IKEPackets, "esp_packets": source.Counters.ESPPackets, "ah_packets": source.Counters.AHPackets, "nat_t_packets": source.Counters.NATTPackets})
}

func startAnalysis(w http.ResponseWriter, r *http.Request, analysis *coreanalysis.Service) {
	var request struct {
		SourceID string `json:"source_id"`
		EnableML bool   `json:"enable_ml"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeWorkflowError(w, shared.NewError(shared.InvalidArgument, "", "invalid JSON request"))
		return
	}
	record, err := analysis.Start(r.Context(), request.SourceID, workspacev1.AnalysisMode_OFFLINE_PCAP, "", &analysisv1.AnalysisOptions{EnableSecurity: true, EnableFusion: true, EnableMetadataExposure: true, EnableMl: request.EnableML})
	if err != nil {
		writeWorkflowError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"analysis_id": record.ID, "state": record.State.String(), "stage": record.Stage.String()})
}

func getAnalysis(w http.ResponseWriter, r *http.Request, analysis *coreanalysis.Service) {
	id := r.PathValue("analysisID")
	record, err := analysis.Get(r.Context(), id)
	if err != nil {
		writeWorkflowError(w, err)
		return
	}
	progress, _ := analysis.ProgressDetails(r.Context(), id)
	summary, _ := analysis.SummaryDetails(r.Context(), id)
	writeJSON(w, http.StatusOK, map[string]any{"analysis_id": record.ID, "source_id": record.SourceID, "state": record.State.String(), "stage": record.Stage.String(), "failure_reason": record.Failure, "progress": progress, "summary": summary})
}

func generateReport(w http.ResponseWriter, r *http.Request, reports *corereport.Service) {
	record, err := reports.Generate(r.Context(), &reportv1.GenerateReportRequest{AnalysisId: r.PathValue("analysisID"), Type: reportv1.ReportType_EXECUTIVE, Format: reportv1.ReportFormat_PDF, IncludeTimeline: true, IncludeThreatMatrix: true, IncludeEvidenceChain: true})
	if err != nil {
		writeWorkflowError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"report_id": record.ID, "state": record.State.String()})
}

func getReport(w http.ResponseWriter, r *http.Request, reports *corereport.Service) {
	record, err := reports.Get(r.Context(), r.PathValue("reportID"))
	if err != nil {
		writeWorkflowError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"report_id": record.ID, "analysis_id": record.AnalysisID, "state": record.State.String(), "failure_reason": record.Failure, "download_url": "/api/v1/reports/" + record.ID + "/download"})
}

func downloadReport(w http.ResponseWriter, r *http.Request, reports *corereport.Service) {
	record, err := reports.Get(r.Context(), r.PathValue("reportID"))
	if err != nil {
		writeWorkflowError(w, err)
		return
	}
	if record.State != reportv1.ReportState_READY {
		writeWorkflowError(w, shared.NewError(shared.FailedPrecondition, "", "report is not ready"))
		return
	}
	artifact, err := reports.Artifact(r.Context(), record.ID)
	if err != nil {
		writeWorkflowError(w, err)
		return
	}
	reader, _, err := reports.ArtifactOpen(r.Context(), artifact.ID)
	if err != nil {
		writeWorkflowError(w, err)
		return
	}
	defer reader.Close()
	w.Header().Set("Content-Type", artifact.MIMEType)
	w.Header().Set("Content-Disposition", "attachment; filename=analysis-report.pdf")
	_, _ = io.Copy(w, reader)
}

func writeWorkflowError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	message := "internal server error"
	var sensorErr *shared.Error
	if errors.As(err, &sensorErr) {
		message = sensorErr.Message
		switch sensorErr.Category {
		case shared.InvalidArgument:
			status = http.StatusBadRequest
		case shared.NotFound:
			status = http.StatusNotFound
		case shared.AlreadyExists:
			status = http.StatusConflict
		case shared.FailedPrecondition:
			status = http.StatusPreconditionFailed
		case shared.ResourceExhausted:
			status = http.StatusRequestEntityTooLarge
		case shared.Unavailable:
			status = http.StatusServiceUnavailable
		case shared.DeadlineExceeded:
			status = http.StatusGatewayTimeout
		}
	}
	writeJSON(w, status, map[string]string{"error": message})
}
