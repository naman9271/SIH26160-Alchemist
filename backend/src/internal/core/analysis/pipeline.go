package analysis

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	analysisv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/analysis"
	eventv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/event"
	inputv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/input"
	mlv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/ml"
	workspacev1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/workspace"
	flowv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/flow"
	viciv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/vici"
	xfrmv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/xfrm"
	coreevents "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/events"
	coreinput "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/input"
	coreml "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/ml"
	corerisk "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/risk"
	coresecurity "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/security"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/engine"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/ingest"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	rules "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/security"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/acquisition"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/capture"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/flow"
	"google.golang.org/protobuf/types/known/structpb"
)

// Pipeline is the production coordinator. Each stage works solely from
// payload-free Sensor records and records source coverage instead of treating
// an unavailable optional dependency as a passing result.
type Pipeline struct {
	Sensor   acquisition.Services
	Input    *coreinput.Service
	Ingest   *ingest.Service
	Fusion   *engine.Service
	ML       *coreml.Service
	Security *coresecurity.Service
	Risk     *corerisk.Service
	Events   *coreevents.Service
	VICI     interface {
		Snapshot(context.Context, string) (*viciv1.GatewaySnapshot, error)
	}
	XFRM interface {
		Snapshot(context.Context) (*xfrmv1.KernelSnapshot, error)
	}
	VICIURI string
	// Deep assessments take repeated point-in-time samples so short-lived
	// rekeys and stale gateway state are represented explicitly.
	TelemetrySnapshotCount    int
	TelemetrySnapshotInterval time.Duration
	TelemetryStaleAfter       time.Duration
	LiveRefreshInterval       time.Duration
}

func (p *Pipeline) Run(ctx context.Context, record Record, advance func(analysisv1.AnalysisStage), snapshot func() uint64) error {
	if p == nil || p.Ingest == nil || p.Fusion == nil {
		return fmt.Errorf("analysis pipeline is not configured")
	}
	if p.Input != nil {
		if source, err := p.Input.Get(ctx, record.SourceID); err == nil && source.State == inputv1.InputState_CAPTURING {
			return p.runLive(ctx, record, source.SessionID, advance, snapshot)
		}
	}
	p.publish(ctx, record.ID, eventv1.CoreEventCategory_ANALYSIS_STARTED)
	advance(analysisv1.AnalysisStage_PROTOCOL_PROCESSING)
	p.publish(ctx, record.ID, eventv1.CoreEventCategory_ANALYSIS_PROGRESS)
	if err := p.exportSensor(ctx, record); err != nil {
		return err
	}
	if _, err := p.Ingest.MarkSourceComplete(ctx, ingest.MarkSourceRequest{FusionRunID: record.FusionRunID, Source: model.SourcePacketParser}); err != nil {
		return err
	}
	if _, err := p.Ingest.MarkSourceComplete(ctx, ingest.MarkSourceRequest{FusionRunID: record.FusionRunID, Source: model.SourceFlowAnalyzer}); err != nil {
		return err
	}
	if err := p.collectDeepTelemetry(ctx, record); err != nil {
		return err
	}
	advance(analysisv1.AnalysisStage_FEATURE_EXTRACTION)
	if record.Options.GetEnableMl() && p.ML != nil {
		advance(analysisv1.AnalysisStage_ML_INFERENCE)
		p.publish(ctx, record.ID, eventv1.CoreEventCategory_ML_INFERENCE_STARTED)
		job, err := p.ML.Start(ctx, record.ID, false, record.Options.GetEnableShap())
		if err != nil {
			p.publish(ctx, record.ID, eventv1.CoreEventCategory_ML_UNAVAILABLE)
			_, markErr := p.Ingest.MarkSourceUnavailable(ctx, ingest.MarkSourceUnavailableRequest{FusionRunID: record.FusionRunID, Source: model.SourceMLClassifier, ReasonCode: "ML_UNAVAILABLE"})
			if markErr != nil {
				return markErr
			}
			_, _ = p.Ingest.MarkSourceUnavailable(ctx, ingest.MarkSourceUnavailableRequest{FusionRunID: record.FusionRunID, Source: model.SourceSHAP, ReasonCode: "ML_UNAVAILABLE"})
		} else if err := p.ingestML(ctx, record, job.GetInferenceId()); err != nil {
			return err
		}
	} else {
		for _, source := range []model.Source{model.SourceMLClassifier, model.SourceSHAP} {
			if _, err := p.Ingest.MarkSourceUnavailable(ctx, ingest.MarkSourceUnavailableRequest{FusionRunID: record.FusionRunID, Source: source, ReasonCode: "DISABLED_BY_REQUEST"}); err != nil {
				return err
			}
		}
	}
	advance(analysisv1.AnalysisStage_FUSION)
	p.publish(ctx, record.ID, eventv1.CoreEventCategory_FUSION_STARTED)
	if _, err := p.Fusion.Run(ctx, engine.RunRequest{FusionRunID: record.FusionRunID}); err != nil {
		return err
	}
	p.publish(ctx, record.ID, eventv1.CoreEventCategory_FUSION_COMPLETED)
	if record.Options.GetEnableSecurity() && p.Security != nil {
		advance(analysisv1.AnalysisStage_SECURITY_ANALYSIS)
		assessment, err := p.Security.Run(ctx, record.ID, rules.SIHBaselinePolicyID)
		if err != nil {
			return err
		}
		if p.Risk != nil {
			_, _ = p.Risk.Score(ctx, assessment.ID)
			p.publish(ctx, record.ID, eventv1.CoreEventCategory_SECURITY_SCORE_UPDATED)
		}
		for range assessment.Result.Findings {
			p.publish(ctx, record.ID, eventv1.CoreEventCategory_SECURITY_FINDING_CREATED)
		}
	}
	p.publish(ctx, record.ID, eventv1.CoreEventCategory_ANALYSIS_COMPLETED)
	p.publishSnapshot(ctx, record.ID, snapshot, "completed")
	return nil
}

// runLive consumes only finalized feature windows and newly observed packet
// metadata while capture continues. It never blocks acquisition: backpressure
// is accounted for by Sensor and exposed with each dashboard snapshot.
func (p *Pipeline) runLive(ctx context.Context, record Record, sessionID string, advance func(analysisv1.AnalysisStage), snapshot func() uint64) error {
	if p.Sensor.Observations == nil || p.Sensor.Flows == nil || p.Input == nil {
		return fmt.Errorf("live sensor observation services are not configured")
	}
	if strings.TrimSpace(sessionID) == "" {
		return fmt.Errorf("live source has no sensor session")
	}
	p.publish(ctx, record.ID, eventv1.CoreEventCategory_ANALYSIS_STARTED)
	advance(analysisv1.AnalysisStage_ACQUIRING)
	p.publishSnapshot(ctx, record.ID, snapshot, "acquiring")
	windows, cancel, err := p.Sensor.Flows.Subscribe(ctx, sessionID, flowv1.FeatureBackpressurePolicy_DROP_FEATURE_WINDOW, 64)
	if err != nil {
		return err
	}
	defer cancel()

	var observationCursor uint64
	mlID, mlUnavailable := "", !record.Options.GetEnableMl() || p.ML == nil
	if !mlUnavailable {
		if mlID, err = p.ML.BeginLive(ctx, record.ID); err != nil {
			mlUnavailable = true
			p.publish(ctx, record.ID, eventv1.CoreEventCategory_ML_UNAVAILABLE)
		}
	}
	if mlUnavailable {
		reason := "DISABLED_BY_REQUEST"
		if record.Options.GetEnableMl() {
			reason = "ML_UNAVAILABLE"
		}
		if _, err := p.Ingest.MarkSourceUnavailable(ctx, ingest.MarkSourceUnavailableRequest{FusionRunID: record.FusionRunID, Source: model.SourceMLClassifier, ReasonCode: reason}); err != nil {
			return err
		}
		_, _ = p.Ingest.MarkSourceUnavailable(ctx, ingest.MarkSourceUnavailableRequest{FusionRunID: record.FusionRunID, Source: model.SourceSHAP, ReasonCode: reason})
	}

	viciSamples, xfrmSamples := 0, 0
	dirty, ended := true, false
	refresh := time.NewTicker(p.liveRefreshInterval())
	defer refresh.Stop()
	for !ended {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case windowID, ok := <-windows:
			if !ok {
				ended = true
				continue
			}
			if err := p.classifyLiveWindow(ctx, record, mlID, mlUnavailable, windowID); err != nil {
				// ML failure is a degraded result, never a reason to discard
				// protocol or deterministic security updates.
				if mlID != "" {
					mlUnavailable = true
					p.publish(ctx, record.ID, eventv1.CoreEventCategory_ML_UNAVAILABLE)
					_, _ = p.Ingest.MarkSourceUnavailable(ctx, ingest.MarkSourceUnavailableRequest{FusionRunID: record.FusionRunID, Source: model.SourceMLClassifier, ReasonCode: "ML_UNAVAILABLE"})
					_, _ = p.Ingest.MarkSourceUnavailable(ctx, ingest.MarkSourceUnavailableRequest{FusionRunID: record.FusionRunID, Source: model.SourceSHAP, ReasonCode: "ML_UNAVAILABLE"})
					continue
				}
				return err
			}
			dirty = true
		case <-refresh.C:
			changed, missed, next, exportErr := p.exportLivePacketDelta(ctx, record, sessionID, observationCursor)
			if exportErr != nil {
				return exportErr
			}
			observationCursor = next
			dirty = dirty || changed || missed > 0
			vici, xfrm, telemetryErr := p.collectLiveTelemetry(ctx, record)
			if telemetryErr != nil {
				return telemetryErr
			}
			viciSamples += vici
			xfrmSamples += xfrm
			if dirty {
				if err := p.refreshLiveAssessment(ctx, record, advance); err != nil {
					return err
				}
				p.publishSnapshot(ctx, record.ID, snapshot, "live_update")
				dirty = false
			}
		}
	}

	changed, missed, next, err := p.exportLivePacketDelta(ctx, record, sessionID, observationCursor)
	if err != nil {
		return err
	}
	_ = changed
	_ = missed
	observationCursor = next
	_ = observationCursor
	vici, xfrm, err := p.collectLiveTelemetry(ctx, record)
	if err != nil {
		return err
	}
	viciSamples += vici
	xfrmSamples += xfrm
	if err := p.exportLiveFlowCounters(ctx, record, sessionID); err != nil {
		return err
	}
	if err := p.completeLiveSources(ctx, record, mlID, mlUnavailable, viciSamples, xfrmSamples); err != nil {
		return err
	}
	advance(analysisv1.AnalysisStage_FINALIZING)
	if err := p.refreshLiveAssessment(ctx, record, advance); err != nil {
		return err
	}
	p.publish(ctx, record.ID, eventv1.CoreEventCategory_ANALYSIS_COMPLETED)
	p.publishSnapshot(ctx, record.ID, snapshot, "final")
	return nil
}

func (p *Pipeline) liveRefreshInterval() time.Duration {
	if p.LiveRefreshInterval > 0 {
		return p.LiveRefreshInterval
	}
	return 10 * time.Second
}

func (p *Pipeline) exportLivePacketDelta(ctx context.Context, record Record, sessionID string, after uint64) (bool, uint64, uint64, error) {
	packets, next, missed := p.Sensor.Observations.ListSince(ctx, sessionID, after)
	items := make([]ingest.EvidenceInput, 0, len(packets)*2+1)
	for _, packet := range packets {
		if packet.IKE {
			p.publish(ctx, record.ID, eventv1.CoreEventCategory_IKE_DETECTED)
			p.publish(ctx, record.ID, eventv1.CoreEventCategory_IPSEC_DETECTED)
		}
		if packet.Protocol == 50 || packet.EncapsulatedESP {
			p.publish(ctx, record.ID, eventv1.CoreEventCategory_ESP_DETECTED)
			p.publish(ctx, record.ID, eventv1.CoreEventCategory_SA_DISCOVERED)
		}
		items = append(items, packetEvidence(packet)...)
	}
	if missed > 0 {
		meta := map[string]string{"sensor_session_id": sessionID, "uncertainty_reason": "PACKET_METADATA_RETENTION_LIMIT", "dropped_packet_metadata": fmt.Sprint(missed)}
		unknown := stringEvidence("protocol.capture_retention", "INCOMPLETE", "SENSOR_SESSION", sessionID, time.Now().UTC(), meta)
		unknown.Status, unknown.Confidence = commonv1.EvidenceStatus_UNKNOWN, 0
		items = append(items, unknown)
	}
	if len(items) > 0 {
		if _, err := p.Ingest.AddBatch(ctx, ingest.AddBatchRequest{FusionRunID: record.FusionRunID, Evidence: items}); err != nil {
			return false, missed, next, err
		}
	}
	return len(packets) > 0, missed, next, nil
}

func (p *Pipeline) exportLiveFlowCounters(ctx context.Context, record Record, sessionID string) error {
	flows, _, err := p.Sensor.Flows.List(ctx, &flowv1.ListFlowsRequest{SensorSessionId: sessionID, PageSize: 1000})
	if err != nil {
		return err
	}
	items := make([]ingest.EvidenceInput, 0, len(flows)*2)
	for _, item := range flows {
		value := flow.ToProto(item)
		items = append(items, numberEvidence("traffic.packet_count", float64(value.GetPacketCount()), "FLOW", value.GetFlowId(), value.GetLastSeen().AsTime()), numberEvidence("traffic.bytes", float64(value.GetByteCount()), "FLOW", value.GetFlowId(), value.GetLastSeen().AsTime()))
	}
	if len(items) == 0 {
		return nil
	}
	_, err = p.Ingest.AddBatch(ctx, ingest.AddBatchRequest{FusionRunID: record.FusionRunID, Evidence: items})
	return err
}

func (p *Pipeline) classifyLiveWindow(ctx context.Context, record Record, inferenceID string, unavailable bool, windowID string) error {
	if unavailable {
		return nil
	}
	window, err := p.Sensor.Flows.Window(ctx, windowID)
	if err != nil || !window.IsMLReady() {
		return nil
	}
	flowRecord, err := p.Sensor.Flows.Flow(ctx, flow.ToFeature(window).GetFlowId())
	if err != nil || !isClassifierProtocol(flow.ToProto(flowRecord).GetProtocol()) {
		return nil
	}
	p.publish(ctx, record.ID, eventv1.CoreEventCategory_ML_INFERENCE_STARTED)
	prediction, explanation, err := p.ML.PredictLiveWindow(ctx, inferenceID, flow.ToFeature(window), record.Options.GetEnableShap())
	if err != nil {
		return err
	}
	return p.ingestLivePrediction(ctx, record, inferenceID, prediction, explanation)
}

func isClassifierProtocol(protocol flowv1.FlowProtocol) bool {
	return protocol == flowv1.FlowProtocol_ESP || protocol == flowv1.FlowProtocol_NAT_T
}

func (p *Pipeline) ingestLivePrediction(ctx context.Context, record Record, inferenceID string, prediction interface {
	GetPredictionId() string
	GetFlowId() string
	GetWindowId() string
	GetAggregationScope() string
	GetTrafficClass() string
	GetConfidence() float64
	GetModelVersion() string
	GetFeatureSchemaVersion() string
}, explanation interface {
	GetFeatures() []*mlv1.FeatureAttribution
}) error {
	if prediction == nil {
		return nil
	}
	at := time.Now().UTC()
	reference := fmt.Sprintf("ml:%s/%s", inferenceID, prediction.GetPredictionId())
	metadata := map[string]string{"inference_id": inferenceID, "model_version": prediction.GetModelVersion(), "feature_schema_version": prediction.GetFeatureSchemaVersion(), "window_id": prediction.GetWindowId(), "aggregation_scope": prediction.GetAggregationScope(), "classification_semantics": "DOMINANT_WINDOW_BEHAVIOR", "evidence_reference": reference, "uncertainty_reason": "MODEL_INFERENCE"}
	items := []ingest.EvidenceInput{
		{PropertyKey: "traffic.class", Value: structpb.NewStringValue(prediction.GetTrafficClass()), Source: model.SourceMLClassifier, Status: commonv1.EvidenceStatus_INFERRED, Confidence: prediction.GetConfidence(), ObservedAt: at, ResourceType: "FLOW", ResourceID: prediction.GetFlowId(), SourceReference: reference, SchemaVersion: model.EvidenceSchemaVersion, Metadata: metadata},
		{PropertyKey: "traffic.confidence", Value: structpb.NewNumberValue(prediction.GetConfidence()), Source: model.SourceMLClassifier, Status: commonv1.EvidenceStatus_INFERRED, Confidence: prediction.GetConfidence(), ObservedAt: at, ResourceType: "FLOW", ResourceID: prediction.GetFlowId(), SourceReference: reference, SchemaVersion: model.EvidenceSchemaVersion, Metadata: metadata},
	}
	if explanation != nil {
		for _, feature := range explanation.GetFeatures() {
			items = append(items, ingest.EvidenceInput{PropertyKey: "shap." + feature.GetFeatureName(), Value: structpb.NewNumberValue(feature.GetAttribution()), Source: model.SourceSHAP, Status: commonv1.EvidenceStatus_INFERRED, Confidence: prediction.GetConfidence(), ObservedAt: at, ResourceType: "FLOW", ResourceID: prediction.GetFlowId(), SourceReference: reference, SchemaVersion: model.EvidenceSchemaVersion, Metadata: metadata})
		}
	}
	if _, err := p.Ingest.AddBatch(ctx, ingest.AddBatchRequest{FusionRunID: record.FusionRunID, Evidence: items}); err != nil {
		return err
	}
	p.publish(ctx, record.ID, eventv1.CoreEventCategory_ML_PREDICTION_UPDATED)
	return nil
}

func (p *Pipeline) collectDeepTelemetry(ctx context.Context, record Record) error {
	if record.Mode != workspacev1.AnalysisMode_DEEP_ASSESSMENT || !record.EnableVICI || !record.EnableXFRM || p.VICI == nil || p.XFRM == nil {
		if err := p.collectVICI(ctx, record); err != nil {
			return err
		}
		return p.collectXFRM(ctx, record)
	}
	p.publish(ctx, record.ID, eventv1.CoreEventCategory_VICI_COLLECTION_STARTED)
	p.publish(ctx, record.ID, eventv1.CoreEventCategory_XFRM_COLLECTION_STARTED)
	viciCollected, xfrmCollected := 0, 0
	for index := 0; index < p.telemetrySnapshotCount(); index++ {
		// Read gateway and kernel state back-to-back in every interval. This
		// keeps correlation bounded to one sampling interval during rekeys.
		if snapshot, err := p.VICI.Snapshot(ctx, p.VICIURI); err == nil {
			items := decorateTelemetry(VICIEvidence(snapshot), index, snapshotTime(snapshot.GetSnapshotTimestamp(), time.Now().UTC()), p.telemetryStaleAfter())
			if len(items) > 0 {
				if _, err = p.Ingest.AddBatch(ctx, ingest.AddBatchRequest{FusionRunID: record.FusionRunID, Evidence: items}); err != nil {
					return err
				}
			}
			viciCollected++
		}
		if snapshot, err := p.XFRM.Snapshot(ctx); err == nil {
			items := decorateTelemetry(XFRMEvidence(snapshot), index, snapshotTime(snapshot.GetSnapshotTimestamp(), time.Now().UTC()), p.telemetryStaleAfter())
			if len(items) > 0 {
				if _, err = p.Ingest.AddBatch(ctx, ingest.AddBatchRequest{FusionRunID: record.FusionRunID, Evidence: items}); err != nil {
					return err
				}
			}
			xfrmCollected++
		}
		if index+1 < p.telemetrySnapshotCount() && !waitTelemetry(ctx, p.telemetrySnapshotInterval()) {
			return ctx.Err()
		}
	}
	for _, result := range []struct {
		source    model.Source
		collected int
		reason    string
	}{{model.SourceVICI, viciCollected, "VICI_UNAVAILABLE"}, {model.SourceXFRM, xfrmCollected, "XFRM_UNAVAILABLE"}} {
		if result.collected == 0 {
			if _, err := p.Ingest.MarkSourceUnavailable(ctx, ingest.MarkSourceUnavailableRequest{FusionRunID: record.FusionRunID, Source: result.source, ReasonCode: result.reason}); err != nil {
				return err
			}
		} else if _, err := p.Ingest.MarkSourceComplete(ctx, ingest.MarkSourceRequest{FusionRunID: record.FusionRunID, Source: result.source}); err != nil {
			return err
		}
	}
	p.publish(ctx, record.ID, eventv1.CoreEventCategory_VICI_COLLECTION_COMPLETED)
	p.publish(ctx, record.ID, eventv1.CoreEventCategory_XFRM_COLLECTION_COMPLETED)
	return nil
}

// collectLiveTelemetry records one time-bounded gateway/kernel sample. Source
// coverage is finalized only when the capture closes, so a transient outage is
// not mislabeled as a completed or healthy telemetry source.
func (p *Pipeline) collectLiveTelemetry(ctx context.Context, record Record) (int, int, error) {
	if record.Mode != workspacev1.AnalysisMode_DEEP_ASSESSMENT {
		return 0, 0, nil
	}
	viciSamples, xfrmSamples := 0, 0
	if record.EnableVICI && p.VICI != nil {
		p.publish(ctx, record.ID, eventv1.CoreEventCategory_VICI_COLLECTION_STARTED)
		if snapshot, err := p.VICI.Snapshot(ctx, p.VICIURI); err == nil {
			items := decorateTelemetry(VICIEvidence(snapshot), viciSamples, snapshotTime(snapshot.GetSnapshotTimestamp(), time.Now().UTC()), p.telemetryStaleAfter())
			if len(items) > 0 {
				if _, err = p.Ingest.AddBatch(ctx, ingest.AddBatchRequest{FusionRunID: record.FusionRunID, Evidence: items}); err != nil {
					return 0, 0, err
				}
			}
			viciSamples++
		}
		p.publish(ctx, record.ID, eventv1.CoreEventCategory_VICI_COLLECTION_COMPLETED)
	}
	if record.EnableXFRM && p.XFRM != nil {
		p.publish(ctx, record.ID, eventv1.CoreEventCategory_XFRM_COLLECTION_STARTED)
		if snapshot, err := p.XFRM.Snapshot(ctx); err == nil {
			items := decorateTelemetry(XFRMEvidence(snapshot), xfrmSamples, snapshotTime(snapshot.GetSnapshotTimestamp(), time.Now().UTC()), p.telemetryStaleAfter())
			if len(items) > 0 {
				if _, err = p.Ingest.AddBatch(ctx, ingest.AddBatchRequest{FusionRunID: record.FusionRunID, Evidence: items}); err != nil {
					return 0, 0, err
				}
			}
			xfrmSamples++
		}
		p.publish(ctx, record.ID, eventv1.CoreEventCategory_XFRM_COLLECTION_COMPLETED)
	}
	return viciSamples, xfrmSamples, nil
}

func (p *Pipeline) completeLiveSources(ctx context.Context, record Record, inferenceID string, mlUnavailable bool, viciSamples, xfrmSamples int) error {
	for _, source := range []model.Source{model.SourcePacketParser, model.SourceFlowAnalyzer} {
		if _, err := p.Ingest.MarkSourceComplete(ctx, ingest.MarkSourceRequest{FusionRunID: record.FusionRunID, Source: source}); err != nil {
			return err
		}
	}
	if !mlUnavailable && inferenceID != "" {
		if err := p.ML.CompleteLive(ctx, inferenceID); err != nil {
			return err
		}
		if _, err := p.Ingest.MarkSourceComplete(ctx, ingest.MarkSourceRequest{FusionRunID: record.FusionRunID, Source: model.SourceMLClassifier}); err != nil {
			return err
		}
		if _, err := p.Ingest.MarkSourceComplete(ctx, ingest.MarkSourceRequest{FusionRunID: record.FusionRunID, Source: model.SourceSHAP}); err != nil {
			return err
		}
	}
	for _, source := range []struct {
		name      model.Source
		enabled   bool
		collected int
		reason    string
	}{{model.SourceVICI, record.EnableVICI, viciSamples, "VICI_UNAVAILABLE"}, {model.SourceXFRM, record.EnableXFRM, xfrmSamples, "XFRM_UNAVAILABLE"}} {
		if record.Mode != workspacev1.AnalysisMode_DEEP_ASSESSMENT {
			_, _ = p.Ingest.MarkSourceUnavailable(ctx, ingest.MarkSourceUnavailableRequest{FusionRunID: record.FusionRunID, Source: source.name, ReasonCode: "PASSIVE_MODE"})
			continue
		}
		if !source.enabled {
			_, _ = p.Ingest.MarkSourceUnavailable(ctx, ingest.MarkSourceUnavailableRequest{FusionRunID: record.FusionRunID, Source: source.name, ReasonCode: "DISABLED_BY_AUTHORIZED_REQUEST"})
			continue
		}
		if source.collected == 0 {
			if _, err := p.Ingest.MarkSourceUnavailable(ctx, ingest.MarkSourceUnavailableRequest{FusionRunID: record.FusionRunID, Source: source.name, ReasonCode: source.reason}); err != nil {
				return err
			}
			continue
		}
		if _, err := p.Ingest.MarkSourceComplete(ctx, ingest.MarkSourceRequest{FusionRunID: record.FusionRunID, Source: source.name}); err != nil {
			return err
		}
	}
	return nil
}

func (p *Pipeline) refreshLiveAssessment(ctx context.Context, record Record, advance func(analysisv1.AnalysisStage)) error {
	advance(analysisv1.AnalysisStage_FUSION)
	p.publish(ctx, record.ID, eventv1.CoreEventCategory_FUSION_STARTED)
	if _, err := p.Fusion.Run(ctx, engine.RunRequest{FusionRunID: record.FusionRunID, Incremental: true}); err != nil {
		return err
	}
	p.publish(ctx, record.ID, eventv1.CoreEventCategory_FUSION_COMPLETED)
	if !record.Options.GetEnableSecurity() || p.Security == nil {
		return nil
	}
	advance(analysisv1.AnalysisStage_SECURITY_ANALYSIS)
	assessment, err := p.Security.Run(ctx, record.ID, rules.SIHBaselinePolicyID)
	if err != nil {
		return err
	}
	if p.Risk != nil {
		_, _ = p.Risk.Score(ctx, assessment.ID)
	}
	p.publish(ctx, record.ID, eventv1.CoreEventCategory_SECURITY_SCORE_UPDATED)
	for range assessment.Result.Findings {
		p.publish(ctx, record.ID, eventv1.CoreEventCategory_SECURITY_FINDING_CREATED)
	}
	return nil
}

func (p *Pipeline) collectVICI(ctx context.Context, record Record) error {
	if record.Mode != workspacev1.AnalysisMode_DEEP_ASSESSMENT {
		_, err := p.Ingest.MarkSourceUnavailable(ctx, ingest.MarkSourceUnavailableRequest{FusionRunID: record.FusionRunID, Source: model.SourceVICI, ReasonCode: "PASSIVE_MODE"})
		return err
	}
	if !record.EnableVICI {
		_, err := p.Ingest.MarkSourceUnavailable(ctx, ingest.MarkSourceUnavailableRequest{FusionRunID: record.FusionRunID, Source: model.SourceVICI, ReasonCode: "DISABLED_BY_AUTHORIZED_REQUEST"})
		return err
	}
	p.publish(ctx, record.ID, eventv1.CoreEventCategory_VICI_COLLECTION_STARTED)
	if p.VICI == nil {
		_, err := p.Ingest.MarkSourceUnavailable(ctx, ingest.MarkSourceUnavailableRequest{FusionRunID: record.FusionRunID, Source: model.SourceVICI, ReasonCode: "VICI_NOT_CONFIGURED"})
		p.publish(ctx, record.ID, eventv1.CoreEventCategory_VICI_COLLECTION_COMPLETED)
		return err
	}
	collected := 0
	for index := 0; index < p.telemetrySnapshotCount(); index++ {
		snapshot, snapshotErr := p.VICI.Snapshot(ctx, p.VICIURI)
		if snapshotErr == nil {
			items := decorateTelemetry(VICIEvidence(snapshot), index, snapshotTime(snapshot.GetSnapshotTimestamp(), time.Now().UTC()), p.telemetryStaleAfter())
			if len(items) > 0 {
				if _, snapshotErr = p.Ingest.AddBatch(ctx, ingest.AddBatchRequest{FusionRunID: record.FusionRunID, Evidence: items}); snapshotErr != nil {
					return snapshotErr
				}
			}
			collected++
		}
		if index+1 < p.telemetrySnapshotCount() && !waitTelemetry(ctx, p.telemetrySnapshotInterval()) {
			return ctx.Err()
		}
	}
	if collected == 0 {
		_, markErr := p.Ingest.MarkSourceUnavailable(ctx, ingest.MarkSourceUnavailableRequest{FusionRunID: record.FusionRunID, Source: model.SourceVICI, ReasonCode: "VICI_UNAVAILABLE"})
		if markErr != nil {
			return markErr
		}
		p.publish(ctx, record.ID, eventv1.CoreEventCategory_VICI_COLLECTION_COMPLETED)
		return nil
	}
	_, err := p.Ingest.MarkSourceComplete(ctx, ingest.MarkSourceRequest{FusionRunID: record.FusionRunID, Source: model.SourceVICI})
	p.publish(ctx, record.ID, eventv1.CoreEventCategory_VICI_COLLECTION_COMPLETED)
	return err
}

func (p *Pipeline) collectXFRM(ctx context.Context, record Record) error {
	if record.Mode != workspacev1.AnalysisMode_DEEP_ASSESSMENT {
		_, err := p.Ingest.MarkSourceUnavailable(ctx, ingest.MarkSourceUnavailableRequest{FusionRunID: record.FusionRunID, Source: model.SourceXFRM, ReasonCode: "PASSIVE_MODE"})
		return err
	}
	if !record.EnableXFRM {
		_, err := p.Ingest.MarkSourceUnavailable(ctx, ingest.MarkSourceUnavailableRequest{FusionRunID: record.FusionRunID, Source: model.SourceXFRM, ReasonCode: "DISABLED_BY_AUTHORIZED_REQUEST"})
		return err
	}
	p.publish(ctx, record.ID, eventv1.CoreEventCategory_XFRM_COLLECTION_STARTED)
	if p.XFRM == nil {
		_, err := p.Ingest.MarkSourceUnavailable(ctx, ingest.MarkSourceUnavailableRequest{FusionRunID: record.FusionRunID, Source: model.SourceXFRM, ReasonCode: "XFRM_NOT_CONFIGURED"})
		p.publish(ctx, record.ID, eventv1.CoreEventCategory_XFRM_COLLECTION_COMPLETED)
		return err
	}
	collected := 0
	for index := 0; index < p.telemetrySnapshotCount(); index++ {
		snapshot, snapshotErr := p.XFRM.Snapshot(ctx)
		if snapshotErr == nil {
			items := decorateTelemetry(XFRMEvidence(snapshot), index, snapshotTime(snapshot.GetSnapshotTimestamp(), time.Now().UTC()), p.telemetryStaleAfter())
			if len(items) > 0 {
				if _, snapshotErr = p.Ingest.AddBatch(ctx, ingest.AddBatchRequest{FusionRunID: record.FusionRunID, Evidence: items}); snapshotErr != nil {
					return snapshotErr
				}
			}
			collected++
		}
		if index+1 < p.telemetrySnapshotCount() && !waitTelemetry(ctx, p.telemetrySnapshotInterval()) {
			return ctx.Err()
		}
	}
	if collected == 0 {
		_, markErr := p.Ingest.MarkSourceUnavailable(ctx, ingest.MarkSourceUnavailableRequest{FusionRunID: record.FusionRunID, Source: model.SourceXFRM, ReasonCode: "XFRM_UNAVAILABLE"})
		if markErr != nil {
			return markErr
		}
		p.publish(ctx, record.ID, eventv1.CoreEventCategory_XFRM_COLLECTION_COMPLETED)
		return nil
	}
	_, err := p.Ingest.MarkSourceComplete(ctx, ingest.MarkSourceRequest{FusionRunID: record.FusionRunID, Source: model.SourceXFRM})
	p.publish(ctx, record.ID, eventv1.CoreEventCategory_XFRM_COLLECTION_COMPLETED)
	return err
}

func (p *Pipeline) telemetrySnapshotCount() int {
	if p.TelemetrySnapshotCount > 0 {
		return p.TelemetrySnapshotCount
	}
	return 3
}

func (p *Pipeline) telemetrySnapshotInterval() time.Duration {
	if p.TelemetrySnapshotInterval > 0 {
		return p.TelemetrySnapshotInterval
	}
	return 250 * time.Millisecond
}

func (p *Pipeline) telemetryStaleAfter() time.Duration {
	if p.TelemetryStaleAfter > 0 {
		return p.TelemetryStaleAfter
	}
	return 30 * time.Second
}

func waitTelemetry(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func decorateTelemetry(items []ingest.EvidenceInput, index int, capturedAt time.Time, staleAfter time.Duration) []ingest.EvidenceInput {
	freshness := "FRESH"
	if capturedAt.IsZero() || time.Since(capturedAt) > staleAfter || capturedAt.After(time.Now().Add(staleAfter)) {
		freshness = "STALE"
	}
	for itemIndex := range items {
		items[itemIndex].Metadata = cloneMetadata(items[itemIndex].Metadata)
		items[itemIndex].Metadata["telemetry_snapshot_index"] = fmt.Sprint(index)
		items[itemIndex].Metadata["telemetry_captured_at"] = capturedAt.UTC().Format(time.RFC3339Nano)
		items[itemIndex].Metadata["telemetry_freshness"] = freshness
		if freshness == "STALE" {
			items[itemIndex].Metadata["uncertainty_reason"] = "STALE_TELEMETRY"
		}
	}
	return items
}

func (p *Pipeline) publish(ctx context.Context, analysisID string, category eventv1.CoreEventCategory) {
	if p.Events != nil {
		p.Events.Publish(ctx, analysisID, category)
	}
}

func (p *Pipeline) publishSnapshot(ctx context.Context, analysisID string, next func() uint64, state string) {
	if p.Events == nil || next == nil {
		return
	}
	version := next()
	if version == 0 {
		return
	}
	p.Events.PublishPayload(ctx, analysisID, eventv1.CoreEventCategory_ANALYSIS_PROGRESS, map[string]any{"snapshot_version": version, "snapshot_state": state})
}

func (p *Pipeline) exportSensor(ctx context.Context, record Record) error {
	if p.Sensor.Observations == nil || p.Sensor.Flows == nil {
		return fmt.Errorf("sensor observation services are not configured")
	}
	if p.Input == nil {
		return fmt.Errorf("input service is not configured")
	}
	source, err := p.Input.Get(ctx, record.SourceID)
	if err != nil {
		return err
	}
	items := make([]ingest.EvidenceInput, 0)
	saObserved := false
	packets := annotatePassiveSAEpochs(p.Sensor.Observations.List(ctx, source.SessionID))
	for _, packet := range packets {
		if packet.IKE {
			p.publish(ctx, record.ID, eventv1.CoreEventCategory_IKE_DETECTED)
			p.publish(ctx, record.ID, eventv1.CoreEventCategory_IPSEC_DETECTED)
		}
		if packet.Protocol == 50 || packet.EncapsulatedESP {
			p.publish(ctx, record.ID, eventv1.CoreEventCategory_ESP_DETECTED)
			saObserved = true
		}
		if packet.Protocol == 51 {
			saObserved = true
		}
		items = append(items, packetEvidence(packet)...)
	}
	items = append(items, passiveSALifecycleEvidence(packets)...)
	if err := p.Sensor.Flows.StopForSession(ctx, source.SessionID); err != nil {
		return err
	}
	flows, _, err := p.Sensor.Flows.List(ctx, &flowv1.ListFlowsRequest{SensorSessionId: source.SessionID, PageSize: 1000})
	if err != nil {
		return err
	}
	for _, item := range flows {
		v := flow.ToProto(item)
		items = append(items, numberEvidence("traffic.packet_count", float64(v.GetPacketCount()), "FLOW", v.GetFlowId(), v.GetLastSeen().AsTime()), numberEvidence("traffic.bytes", float64(v.GetByteCount()), "FLOW", v.GetFlowId(), v.GetLastSeen().AsTime()))
	}
	if saObserved {
		p.publish(ctx, record.ID, eventv1.CoreEventCategory_SA_DISCOVERED)
	}
	if len(items) == 0 {
		return nil
	}
	_, err = p.Ingest.AddBatch(ctx, ingest.AddBatchRequest{FusionRunID: record.FusionRunID, Evidence: items})
	return err
}

func (p *Pipeline) ingestML(ctx context.Context, record Record, inferenceID string) error {
	predictions, _, err := p.ML.Predictions(ctx, inferenceID, 1000, "")
	if err != nil {
		return err
	}
	items := make([]ingest.EvidenceInput, 0, len(predictions)*2)
	for _, prediction := range predictions {
		at := time.Now().UTC()
		reference := fmt.Sprintf("ml:%s/%s", inferenceID, prediction.GetPredictionId())
		metadata := map[string]string{"inference_id": inferenceID, "model_version": prediction.GetModelVersion(), "feature_schema_version": prediction.GetFeatureSchemaVersion(), "window_id": prediction.GetWindowId(), "aggregation_scope": prediction.GetAggregationScope(), "classification_semantics": "DOMINANT_WINDOW_BEHAVIOR", "evidence_reference": reference, "uncertainty_reason": "MODEL_INFERENCE"}
		items = append(items,
			ingest.EvidenceInput{PropertyKey: "traffic.class", Value: structpb.NewStringValue(prediction.GetTrafficClass()), Source: model.SourceMLClassifier, Status: commonv1.EvidenceStatus_INFERRED, Confidence: prediction.GetConfidence(), ObservedAt: at, ResourceType: "FLOW", ResourceID: prediction.GetFlowId(), SourceReference: reference, SchemaVersion: model.EvidenceSchemaVersion, Metadata: metadata},
			ingest.EvidenceInput{PropertyKey: "traffic.confidence", Value: structpb.NewNumberValue(prediction.GetConfidence()), Source: model.SourceMLClassifier, Status: commonv1.EvidenceStatus_INFERRED, Confidence: prediction.GetConfidence(), ObservedAt: at, ResourceType: "FLOW", ResourceID: prediction.GetFlowId(), SourceReference: reference, SchemaVersion: model.EvidenceSchemaVersion, Metadata: metadata},
		)
		if explanation, explanationErr := p.ML.Explanation(ctx, inferenceID, prediction.GetPredictionId()); explanationErr == nil && len(explanation.GetFeatures()) > 0 {
			for _, feature := range explanation.GetFeatures() {
				items = append(items, ingest.EvidenceInput{PropertyKey: "shap." + feature.GetFeatureName(), Value: structpb.NewNumberValue(feature.GetAttribution()), Source: model.SourceSHAP, Status: commonv1.EvidenceStatus_INFERRED, Confidence: prediction.GetConfidence(), ObservedAt: at, ResourceType: "FLOW", ResourceID: prediction.GetFlowId(), SourceReference: reference, SchemaVersion: model.EvidenceSchemaVersion, Metadata: metadata})
			}
		}
	}
	if len(items) > 0 {
		if _, err := p.Ingest.AddBatch(ctx, ingest.AddBatchRequest{FusionRunID: record.FusionRunID, Evidence: items}); err != nil {
			return err
		}
	}
	p.publish(ctx, record.ID, eventv1.CoreEventCategory_ML_PREDICTION_UPDATED)
	if _, err := p.Ingest.MarkSourceComplete(ctx, ingest.MarkSourceRequest{FusionRunID: record.FusionRunID, Source: model.SourceMLClassifier}); err != nil {
		return err
	}
	if _, err := p.Ingest.MarkSourceComplete(ctx, ingest.MarkSourceRequest{FusionRunID: record.FusionRunID, Source: model.SourceSHAP}); err != nil {
		return err
	}
	return nil
}

func packetEvidence(packet capture.PacketMetadata) []ingest.EvidenceInput {
	at := packet.SeenAt
	endpointPair := canonicalEndpointPair(packet.SourceAddress, packet.DestinationAddress)
	reference := fmt.Sprintf("capture:%s:%d:%s>%s", packet.SessionID, at.UnixNano(), packet.SourceAddress, packet.DestinationAddress)
	meta := map[string]string{
		"sensor_session_id":    packet.SessionID,
		"capture_context":      packet.SessionID,
		"source_endpoint":      packet.SourceAddress,
		"destination_endpoint": packet.DestinationAddress,
		"endpoint_pair":        endpointPair,
		"endpoint_tuple":       packet.SourceAddress + ">" + packet.DestinationAddress,
		"evidence_reference":   reference,
		"uncertainty_reason":   "DIRECT_WIRE_OBSERVATION",
	}
	items := []ingest.EvidenceInput{}
	if packet.IKE {
		meta["ike_initiator_spi"] = fmt.Sprintf("0x%016x", packet.IKEInitiatorSPI)
		meta["ike_responder_spi"] = fmt.Sprintf("0x%016x", packet.IKEResponderSPI)
	}
	if packet.ProtocolIncomplete {
		incomplete := stringEvidence("protocol.parse_status", "INCOMPLETE", "PACKET", reference, at, meta)
		incomplete.Status = commonv1.EvidenceStatus_UNKNOWN
		incomplete.Confidence = 0
		incomplete.Metadata = cloneMetadata(meta)
		incomplete.Metadata["uncertainty_reason"] = packet.IncompleteReason
		items = append(items, incomplete)
	}
	ikeID := fmt.Sprintf("ike:%s:%s:%016x-%016x", packet.SessionID, endpointPair, packet.IKEInitiatorSPI, packet.IKEResponderSPI)
	if packet.IKE && packet.IKEVersion != "" {
		ikeMeta := cloneMetadata(meta)
		ikeMeta["ike_initiator_spi"] = fmt.Sprintf("0x%016x", packet.IKEInitiatorSPI)
		ikeMeta["ike_responder_spi"] = fmt.Sprintf("0x%016x", packet.IKEResponderSPI)
		ikeMeta["ike_exchange_type"] = fmt.Sprint(packet.IKEExchangeType)
		ikeMeta["ike_message_id"] = fmt.Sprint(packet.IKEMessageID)
		role := "UNSPECIFIED"
		if strings.HasPrefix(strings.ToUpper(packet.IKEVersion), "IKEV2") {
			role = map[bool]string{true: "RESPONSE", false: "REQUEST"}[packet.IKEIsResponse]
		}
		items = append(items,
			stringEvidence("ike.version", packet.IKEVersion, "IKE_SA", ikeID, at, ikeMeta),
			stringEvidence("ike.initiator_spi", ikeMeta["ike_initiator_spi"], "IKE_SA", ikeID, at, ikeMeta),
			stringEvidence("ike.responder_spi", ikeMeta["ike_responder_spi"], "IKE_SA", ikeID, at, ikeMeta),
			stringEvidence("ike.exchange_type", fmt.Sprint(packet.IKEExchangeType), "IKE_SA", ikeID, at, ikeMeta),
			stringEvidence("ike.message_role", role, "IKE_SA", ikeID, at, ikeMeta),
			numberEvidenceWithMetadata("ike.message_id", float64(packet.IKEMessageID), "IKE_SA", ikeID, at, ikeMeta),
		)
	}
	if packet.IKE {
		items = append(items, proposalEvidence(packet, ikeID, at, meta)...)
		for _, value := range packet.IKEAuthMethods {
			items = append(items, stringEvidence("ike.authentication_method", value, "IKE_SA", ikeID, at, meta))
		}
		for _, value := range packet.IKECertificateTypes {
			items = append(items, stringEvidence("ike.certificate.type", value, "IKE_SA", ikeID, at, meta))
		}
		for _, value := range packet.IKETrafficSelectors {
			items = append(items, stringEvidence("child.traffic_selector", value, "IKE_SA", ikeID, at, meta))
		}
	}
	if packet.Protocol == 50 || packet.EncapsulatedESP {
		// A SPI is scoped by protocol and destination. Keeping outer endpoints
		// prevents unrelated gateways that reuse a SPI from being merged.
		id := passiveSAID(packet)
		espMeta := cloneMetadata(meta)
		espMeta["esp_spi"] = fmt.Sprintf("0x%08x", packet.SPI)
		espMeta["esp_destination"] = packet.DestinationAddress
		espMeta["esp_protocol"] = "ESP"
		espMeta["sa_lifetime_epoch"] = fmt.Sprint(packet.SALifetimeEpoch)
		espMeta["esp_directional_identity"] = fmt.Sprintf("esp|%s|%s|0x%08x|%d", packet.SessionID, packet.DestinationAddress, packet.SPI, packet.SALifetimeEpoch)
		if packet.CurrentSAEpoch {
			espMeta["esp_directional_wire"] = fmt.Sprintf("esp|%s|0x%08x", packet.DestinationAddress, packet.SPI)
		}
		espMeta["uncertainty_reason"] = "PASSIVE_SA_IDENTITY_NO_GATEWAY_CORROBORATION"
		items = append(items,
			stringEvidence("child.protocol", "ESP", "ESP_STREAM", id, at, espMeta),
			stringEvidence("esp.spi", espMeta["esp_spi"], "ESP_STREAM", id, at, espMeta),
			numberEvidenceWithMetadata("esp.sequence", float64(packet.ESPSequence), "ESP_STREAM", id, at, espMeta),
			stringEvidence("metadata.exposure", "outer endpoints, timing, direction and volume", "ESP_STREAM", id, at, espMeta),
		)
	}
	if packet.Protocol == 51 {
		id := fmt.Sprintf("ah:%s:%s:0x%08x", packet.SessionID, packet.DestinationAddress, packet.SPI)
		ahMeta := cloneMetadata(meta)
		ahMeta["ah_spi"] = fmt.Sprintf("0x%08x", packet.SPI)
		ahMeta["ah_destination"] = packet.DestinationAddress
		ahMeta["ah_directional_identity"] = fmt.Sprintf("ah|%s|%s|0x%08x", packet.SessionID, packet.DestinationAddress, packet.SPI)
		items = append(items, stringEvidence("child.protocol", "AH", "AH_STREAM", id, at, ahMeta), stringEvidence("ah.spi", ahMeta["ah_spi"], "AH_STREAM", id, at, ahMeta))
	}
	if packet.NATT {
		items = append(items, stringEvidence("nat_traversal.detected", "true", "NAT_TRAVERSAL", packet.SessionID, at, meta))
	}
	return items
}

func cloneMetadata(input map[string]string) map[string]string {
	out := make(map[string]string, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func proposalEvidence(packet capture.PacketMetadata, ikeID string, at time.Time, metadata map[string]string) []ingest.EvidenceInput {
	items := make([]ingest.EvidenceInput, 0)
	for _, proposal := range packet.IKEProposals {
		proposalMeta := make(map[string]string, len(metadata)+4)
		for k, v := range metadata {
			proposalMeta[k] = v
		}
		proposalMeta["proposal_number"] = fmt.Sprint(proposal.Number)
		proposalMeta["proposal_protocol_id"] = fmt.Sprint(proposal.ProtocolID)
		proposalMeta["proposal_disposition"] = map[bool]string{true: "selected", false: "offered"}[proposal.Selected]
		for _, transform := range proposal.Transforms {
			transformMeta := cloneMetadata(proposalMeta)
			transformMeta["transform_type_id"] = fmt.Sprint(transform.Type)
			transformMeta["transform_id"] = fmt.Sprint(transform.ID)
			transformMeta["transform_name"] = transform.Name
			transformMeta["key_length_bits"] = fmt.Sprint(transform.KeyLengthBits)
			key := "ike.proposal.transform"
			unsupported := strings.HasPrefix(transform.Name, "UNKNOWN-") || strings.HasPrefix(transform.Name, "IKEV1-ENCR-") || strings.HasPrefix(transform.Name, "IKEV1-HASH-")
			transformMeta["transform_supported"] = fmt.Sprint(!unsupported)
			if unsupported {
				key = "ike.unsupported_transform"
				transformMeta["uncertainty_reason"] = "UNSUPPORTED_TRANSFORM_IDENTIFIER"
			} else if proposal.Selected && proposal.ProtocolID == 1 {
				switch transform.Type {
				case 1:
					key = "ike.encryption"
				case 2:
					key = "ike.prf"
				case 3:
					key = "ike.integrity"
				case 4:
					key = "ike.dh_group"
				default:
					continue
				}
			} else {
				// Clear offers are valuable audit evidence, but explicitly not a
				// negotiated suite. Do not use canonical assessment keys here.
				key = fmt.Sprintf("ike.proposal.transform.%d", transform.Type)
			}
			items = append(items, stringEvidence(key, transform.Name, "IKE_PROPOSAL", fmt.Sprintf("%s:%d", ikeID, proposal.Number), at, transformMeta))
		}
	}
	return items
}

func stringEvidence(key, value, typ, id string, at time.Time, metadata map[string]string) ingest.EvidenceInput {
	return ingest.EvidenceInput{PropertyKey: key, Value: structpb.NewStringValue(value), Source: model.SourcePacketParser, Status: commonv1.EvidenceStatus_OBSERVED, Confidence: .95, ObservedAt: at.UTC(), ResourceType: typ, ResourceID: id, SourceReference: metadata["evidence_reference"], SchemaVersion: model.EvidenceSchemaVersion, Metadata: metadata}
}

func numberEvidence(key string, value float64, typ, id string, at time.Time) ingest.EvidenceInput {
	reference := "flow:" + id
	metadata := map[string]string{"evidence_reference": reference, "uncertainty_reason": "DERIVED_FLOW_AGGREGATE"}
	return ingest.EvidenceInput{PropertyKey: key, Value: structpb.NewNumberValue(value), Source: model.SourceFlowAnalyzer, Status: commonv1.EvidenceStatus_DERIVED, Confidence: .9, ObservedAt: at.UTC(), ResourceType: typ, ResourceID: id, SourceReference: reference, SchemaVersion: model.EvidenceSchemaVersion, Metadata: metadata}
}

func numberEvidenceWithMetadata(key string, value float64, typ, id string, at time.Time, metadata map[string]string) ingest.EvidenceInput {
	return ingest.EvidenceInput{PropertyKey: key, Value: structpb.NewNumberValue(value), Source: model.SourcePacketParser, Status: commonv1.EvidenceStatus_OBSERVED, Confidence: .95, ObservedAt: at.UTC(), ResourceType: typ, ResourceID: id, SourceReference: metadata["evidence_reference"], SchemaVersion: model.EvidenceSchemaVersion, Metadata: metadata}
}

func canonicalEndpointPair(left, right string) string {
	values := []string{strings.TrimSpace(left), strings.TrimSpace(right)}
	sort.Strings(values)
	return values[0] + "<>" + values[1]
}

type passiveSAObservation struct {
	id, lineage                  string
	first, last                  time.Time
	spi                          uint32
	source, destination, session string
	epoch                        uint32
}

func passiveSALifecycleEvidence(packets []capture.PacketMetadata) []ingest.EvidenceInput {
	byID := make(map[string]*passiveSAObservation)
	for _, packet := range packets {
		if packet.SPI == 0 || packet.Protocol != 50 && !packet.EncapsulatedESP {
			continue
		}
		id := passiveSAID(packet)
		item := byID[id]
		if item == nil {
			item = &passiveSAObservation{id: id, lineage: packet.SessionID + "|" + packet.SourceAddress + ">" + packet.DestinationAddress, first: packet.SeenAt, last: packet.SeenAt, spi: packet.SPI, source: packet.SourceAddress, destination: packet.DestinationAddress, session: packet.SessionID, epoch: packet.SALifetimeEpoch}
			byID[id] = item
		}
		if packet.SeenAt.Before(item.first) {
			item.first = packet.SeenAt
		}
		if packet.SeenAt.After(item.last) {
			item.last = packet.SeenAt
		}
	}
	groups := make(map[string][]*passiveSAObservation)
	for _, item := range byID {
		groups[item.lineage] = append(groups[item.lineage], item)
	}
	result := make([]ingest.EvidenceInput, 0, len(byID)*3)
	for _, group := range groups {
		sort.Slice(group, func(i, j int) bool {
			if group[i].first.Equal(group[j].first) {
				return group[i].spi < group[j].spi
			}
			return group[i].first.Before(group[j].first)
		})
		for index, item := range group {
			reference := fmt.Sprintf("capture:%s:sa:0x%08x", item.session, item.spi)
			metadata := map[string]string{
				"sensor_session_id":        item.session,
				"capture_context":          item.session,
				"source_endpoint":          item.source,
				"destination_endpoint":     item.destination,
				"esp_spi":                  fmt.Sprintf("0x%08x", item.spi),
				"esp_destination":          item.destination,
				"esp_protocol":             "ESP",
				"sa_lifetime_epoch":        fmt.Sprint(item.epoch),
				"esp_directional_identity": fmt.Sprintf("esp|%s|%s|0x%08x|%d", item.session, item.destination, item.spi, item.epoch),
				"evidence_reference":       reference,
				"uncertainty_reason":       "PASSIVE_OBSERVATION_INTERVAL",
			}
			result = append(result,
				stringEvidence("sa.first_observed_at", item.first.UTC().Format(time.RFC3339Nano), "ESP_STREAM", item.id, item.first, metadata),
				stringEvidence("sa.last_observed_at", item.last.UTC().Format(time.RFC3339Nano), "ESP_STREAM", item.id, item.last, metadata),
				stringEvidence("sa.lifecycle_state", "OBSERVED", "ESP_STREAM", item.id, item.last, metadata),
			)
			if index > 0 {
				possible := stringEvidence("sa.possible_rekey_of", group[index-1].id, "ESP_STREAM", item.id, item.first, metadata)
				possible.Status = commonv1.EvidenceStatus_DERIVED
				possible.Confidence = .6
				possible.Metadata = cloneMetadata(metadata)
				possible.Metadata["uncertainty_reason"] = "PASSIVE_SPI_CHANGE_REQUIRES_GATEWAY_CORROBORATION"
				possible.Metadata["previous_spi"] = fmt.Sprintf("0x%08x", group[index-1].spi)
				result = append(result, possible)
			}
		}
	}
	return result
}

func passiveSAID(packet capture.PacketMetadata) string {
	return fmt.Sprintf("esp:%s:%s:0x%08x:epoch-%d", packet.SessionID, packet.DestinationAddress, packet.SPI, packet.SALifetimeEpoch)
}

func annotatePassiveSAEpochs(packets []capture.PacketMetadata) []capture.PacketMetadata {
	result := append([]capture.PacketMetadata(nil), packets...)
	groups := make(map[string][]int)
	for index, packet := range result {
		if packet.SPI == 0 || packet.Protocol != 50 && !packet.EncapsulatedESP {
			continue
		}
		key := fmt.Sprintf("%s|%s|%d|%08x", packet.SessionID, packet.DestinationAddress, packet.Protocol, packet.SPI)
		groups[key] = append(groups[key], index)
	}
	for _, indices := range groups {
		sort.Slice(indices, func(i, j int) bool { return result[indices[i]].SeenAt.Before(result[indices[j]].SeenAt) })
		epoch := uint32(1)
		for position, index := range indices {
			if position > 0 {
				previous := result[indices[position-1]]
				current := result[index]
				sequenceReset := current.ESPSequence <= 16 && previous.ESPSequence > current.ESPSequence+64
				longGap := current.SeenAt.Sub(previous.SeenAt) > 24*time.Hour
				if sequenceReset || longGap {
					epoch++
				}
			}
			result[index].SALifetimeEpoch = epoch
		}
		for _, index := range indices {
			result[index].CurrentSAEpoch = result[index].SALifetimeEpoch == epoch
		}
	}
	return result
}
