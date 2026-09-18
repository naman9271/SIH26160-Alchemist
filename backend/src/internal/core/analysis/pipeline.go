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
}

func (p *Pipeline) Run(ctx context.Context, record Record, advance func(analysisv1.AnalysisStage)) error {
	if p == nil || p.Ingest == nil || p.Fusion == nil {
		return fmt.Errorf("analysis pipeline is not configured")
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
		assessment, err := p.Security.Run(ctx, record.ID, record.PolicyID)
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
