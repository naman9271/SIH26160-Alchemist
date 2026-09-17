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
	sensorv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1"
	flowv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/flow"
	coreanalysis "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/analysis"
	corefusion "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/fusion"
	coreinput "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/input"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/localsensor"
	coreml "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/ml"
	coreprotocol "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/protocolread"
	corereport "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/report"
	corerisk "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/risk"
	coresecurity "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/security"
	coresystem "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/system"
	coreworkspace "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/workspace"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/query"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/capture"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/flow"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/network"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/session"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/vici"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/xfrm"
)

const maxHTTPPCAPBytes = 4 << 30

func registerWorkflowAPI(mux *http.ServeMux, input *coreinput.Service, analysis *coreanalysis.Service, reports *corereport.Service, workspace *coreworkspace.Service, protocol *coreprotocol.Service, fusion *corefusion.Service, security *coresecurity.Service, risk *corerisk.Service, ml *coreml.Service, flows *flow.Service, system coresystem.Service, localSensor *localsensor.Service, sessions *session.Service, interfaces *network.Service, captures *capture.Service, viciService *vici.Service, xfrmService *xfrm.Service) {
	mux.HandleFunc("GET /api/v1/system/overview", func(w http.ResponseWriter, r *http.Request) { getSystemOverview(w, r, system, localSensor) })
	mux.HandleFunc("GET /api/v1/live-capture/interfaces", func(w http.ResponseWriter, r *http.Request) { listCaptureInterfaces(w, r, interfaces) })
	mux.HandleFunc("POST /api/v1/live-captures", func(w http.ResponseWriter, r *http.Request) {
		startLiveCapture(w, r, input, sessions, captures, viciService, xfrmService, workspace)
	})
	mux.HandleFunc("GET /api/v1/live-captures/{sourceID}", func(w http.ResponseWriter, r *http.Request) {
		getLiveCapture(w, r, input, sessions, captures, viciService, xfrmService)
	})
	mux.HandleFunc("POST /api/v1/live-captures/{sourceID}/stop", func(w http.ResponseWriter, r *http.Request) { stopLiveCapture(w, r, input, analysis) })
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

// The browser bridge deliberately exposes only a small, passive capture
// workflow. It cannot pass arbitrary tcpdump arguments or invoke gateway
// commands. Deep mode is opt-in and can only read sanitized VICI/XFRM state.
func listCaptureInterfaces(w http.ResponseWriter, r *http.Request, interfaces *network.Service) {
	if interfaces == nil {
		writeWorkflowError(w, shared.NewError(shared.Unavailable, "", "network interface service is unavailable"))
		return
	}
	items, err := interfaces.List(r.Context())
	if err != nil {
		writeWorkflowError(w, err)
		return
	}
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		result = append(result, map[string]any{"name": item.Name, "addresses": item.Addresses, "up": item.Up, "loopback": item.Loopback, "capture_supported": item.CaptureSupported})
	}
	writeJSON(w, http.StatusOK, map[string]any{"interfaces": result})
}

func startLiveCapture(w http.ResponseWriter, r *http.Request, input *coreinput.Service, sessions *session.Service, captures *capture.Service, viciService *vici.Service, xfrmService *xfrm.Service, workspace *coreworkspace.Service) {
	if sessions == nil || captures == nil {
		writeWorkflowError(w, shared.NewError(shared.Unavailable, "", "live capture service is unavailable"))
		return
	}
	var request struct {
		InterfaceName string `json:"interface_name"`
		Mode          string `json:"mode"`
		Authorized    bool   `json:"authorized"`
		EnableVICI    bool   `json:"enable_vici"`
		EnableXFRM    bool   `json:"enable_xfrm"`
		SavePCAP      bool   `json:"save_pcap"`
		Consent       bool   `json:"consent"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeWorkflowError(w, shared.NewError(shared.InvalidArgument, "", "invalid JSON request"))
		return
	}
	mode := inputv1.InputMode_PASSIVE_LIVE
	if !request.Consent {
		writeWorkflowError(w, shared.NewError(shared.FailedPrecondition, "", "Capture consent is required"))
		return
	}
	if request.Mode != "live" && request.Mode != "deep" {
		writeWorkflowError(w, shared.NewError(shared.InvalidArgument, "", "Choose live or deep mode"))
		return
	}
	if captures.Active() {
		writeWorkflowError(w, shared.NewError(shared.FailedPrecondition, "", "Stop the active capture first"))
		return
	}
	if request.Mode == "deep" {
		if !request.Authorized {
			writeWorkflowError(w, shared.NewError(shared.FailedPrecondition, "", "Deep Assessment requires explicit authorization"))
			return
		}
		if !request.EnableVICI && !request.EnableXFRM {
			writeWorkflowError(w, shared.NewError(shared.InvalidArgument, "", "select VICI and/or XFRM for Deep Assessment"))
			return
		}
		mode = inputv1.InputMode_DEEP_ASSESSMENT
	}
	if workspace != nil {
		if _, err := workspace.Create(r.Context(), "Capture: "+request.InterfaceName, ""); err != nil {
			writeWorkflowError(w, err)
			return
		}
	}
	source, err := input.StartLive(r.Context(), &inputv1.StartLiveInputRequest{Mode: mode, InterfaceName: request.InterfaceName, FilterMode: inputv1.CaptureFilterMode_IPSEC_ONLY, SavePcap: request.SavePCAP, EnableVici: request.EnableVICI, EnableXfrm: request.EnableXFRM, MaxDurationSeconds: 300, MaxCaptureBytes: 64 << 20})
	if err != nil {
		writeWorkflowError(w, err)
		return
	}
	record, err := captures.Status(r.Context(), source.CaptureID)
	if err != nil {
		writeWorkflowError(w, err)
		return
	}
	writeLiveCapture(w, r, record, source.ID, sessions, captures, viciService, xfrmService)
}

func getLiveCapture(w http.ResponseWriter, r *http.Request, input *coreinput.Service, sessions *session.Service, captures *capture.Service, viciService *vici.Service, xfrmService *xfrm.Service) {
	if captures == nil {
		writeWorkflowError(w, shared.NewError(shared.Unavailable, "", "live capture service is unavailable"))
		return
	}
	source, _, _, _, err := input.LiveStatus(r.Context(), r.PathValue("sourceID"))
	if err != nil {
		writeWorkflowError(w, err)
		return
	}
	record, err := captures.Status(r.Context(), source.CaptureID)
	if err != nil {
		writeWorkflowError(w, err)
		return
	}
	writeLiveCapture(w, r, record, source.ID, sessions, captures, viciService, xfrmService)
}

func stopLiveCapture(w http.ResponseWriter, r *http.Request, input *coreinput.Service, analysis *coreanalysis.Service) {
	if input == nil || analysis == nil {
		writeWorkflowError(w, shared.NewError(shared.Unavailable, "", "live capture service is unavailable"))
		return
	}
	source, err := input.StopLive(r.Context(), r.PathValue("sourceID"))
	if err != nil {
		writeWorkflowError(w, err)
		return
	}
	mode := workspacev1.AnalysisMode_PASSIVE_LIVE
	if source.Mode == inputv1.InputMode_DEEP_ASSESSMENT {
		mode = workspacev1.AnalysisMode_DEEP_ASSESSMENT
	}
	record, err := analysis.Start(r.Context(), source.ID, mode, "", &analysisv1.AnalysisOptions{EnableSecurity: true, EnableFusion: true, EnableMetadataExposure: true, EnableMl: true})
	if err != nil {
		writeWorkflowError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"source_id": source.ID, "capture_id": source.CaptureID, "state": source.State.String(), "analysis_id": record.ID, "analysis_state": record.State.String(), "stage": record.Stage.String()})
}

func writeLiveCapture(w http.ResponseWriter, r *http.Request, record interface {
	CaptureID() string
	SessionID() string
	InterfaceName() string
	State() string
}, sourceID string, sessions *session.Service, captures *capture.Service, viciService *vici.Service, xfrmService *xfrm.Service) {
	counters, flows, vpnSessions, elapsed, err := captures.Stats(r.Context(), record.CaptureID())
	if err != nil {
		writeWorkflowError(w, err)
		return
	}
	result := map[string]any{"source_id": sourceID, "capture_id": record.CaptureID(), "session_id": record.SessionID(), "interface_name": record.InterfaceName(), "state": record.State(), "duration_seconds": uint64(elapsed.Seconds()), "packets_total": counters.PacketsTotal, "bytes_total": counters.BytesTotal, "ike_packets": counters.IKEPackets, "esp_packets": counters.ESPPackets, "ah_packets": counters.AHPackets, "nat_t_packets": counters.NATTPackets, "packet_drops": counters.PacketDrops, "active_flows": flows, "active_vpn_sessions": vpnSessions}
	if elapsed > 0 {
		result["packets_per_second"] = float64(counters.PacketsTotal) / elapsed.Seconds()
	}
	if sessions != nil {
		if item, sessionErr := sessions.Get(r.Context(), record.SessionID()); sessionErr == nil && item.Mode == sensorv1.SensorMode_DEEP_ASSESSMENT {
			gateway := map[string]any{"authorized": true}
			if item.DeepOptions.EnableVICI && viciService != nil {
				if snapshot, snapshotErr := viciService.Snapshot(r.Context(), vici.DefaultSocketURI); snapshotErr == nil {
					gateway["vici"] = snapshot
				} else {
					gateway["vici_error"] = snapshotErr.Error()
				}
			}
			if item.DeepOptions.EnableXFRM && xfrmService != nil {
				if snapshot, snapshotErr := xfrmService.Snapshot(r.Context()); snapshotErr == nil {
					gateway["xfrm"] = snapshot
				} else {
					gateway["xfrm_error"] = snapshotErr.Error()
				}
			}
			result["gateway"] = gateway
		}
	}
	writeJSON(w, http.StatusOK, result)
}

// getSystemOverview intentionally exposes only readiness/capability data. It
// gives the dashboard a real view of every local dependency without exposing
// privileged VICI/XFRM commands or raw Sensor control APIs to a browser.
func getSystemOverview(w http.ResponseWriter, r *http.Request, system coresystem.Service, localSensor *localsensor.Service) {
	if system == nil {
		writeWorkflowError(w, shared.NewError(shared.Unavailable, "", "Core system service is unavailable"))
		return
	}
	result := map[string]any{}
	if value, err := system.Version(r.Context()); err == nil {
		result["version"] = value
	}
	if value, err := system.Readiness(r.Context()); err == nil {
		result["readiness"] = value
	}
	if value, err := system.Capabilities(r.Context()); err == nil {
		result["capabilities"] = value
	}
	if value, err := system.RuntimeStats(r.Context()); err == nil {
		result["runtime"] = value
	}
	if localSensor != nil {
		local := map[string]any{}
		if value, err := localSensor.Status(r.Context()); err == nil {
			local["status"] = value
		}
		if value, err := localSensor.Capabilities(r.Context()); err == nil {
			local["capabilities"] = value
		}
		if value, err := localSensor.Probe(r.Context()); err == nil {
			local["mode_availability"] = value
		}
		result["local_sensor"] = local
	}
	writeJSON(w, http.StatusOK, result)
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
			configurationFacts := len(model.SecurityConfigurationProperties)
			evaluated := configurationFacts - int(assessment.UnknownEvidence)
			if evaluated < 0 {
				evaluated = 0
			}
			coverage := evaluated * 100 / configurationFacts
			section["assessment"] = map[string]any{"assessment_id": assessment.ID, "policy_id": assessment.PolicyID, "state": assessment.State.String(), "score": assessment.Result.Score, "grade": assessment.Result.Grade, "findings": findings, "threat_matrix": assessment.Result.ThreatMatrix, "rules_evaluated": assessment.Result.EvaluatedRule, "unknown_evidence_count": assessment.UnknownEvidence, "configuration_facts": configurationFacts, "configuration_facts_evaluated": evaluated, "coverage_percent": coverage, "metadata_exposure": assessment.MetadataExposure, "recommendations": recommendations}
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
	record, err := reports.Generate(r.Context(), &reportv1.GenerateReportRequest{AnalysisId: r.PathValue("analysisID"), Type: reportv1.ReportType_EXECUTIVE, Format: reportv1.ReportFormat_PDF, IncludeTimeline: true, IncludeThreatMatrix: true, IncludeShap: true, IncludeEvidenceChain: true})
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
	w.Header().Set("Content-Disposition", "attachment; filename=alchemist-ipsec-analysis-report.pdf")
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
