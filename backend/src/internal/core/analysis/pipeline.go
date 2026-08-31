package analysis

import (
	"context"
	"fmt"
	"time"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	analysisv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/analysis"
	eventv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/event"
	flowv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/flow"
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
	for _, source := range []model.Source{model.SourceVICI, model.SourceXFRM} {
		if _, err := p.Ingest.MarkSourceUnavailable(ctx, ingest.MarkSourceUnavailableRequest{FusionRunID: record.FusionRunID, Source: source, ReasonCode: "NOT_CONFIGURED"}); err != nil {
			return err
		}
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
	}
	p.publish(ctx, record.ID, eventv1.CoreEventCategory_ANALYSIS_COMPLETED)
	return nil
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
	for _, packet := range p.Sensor.Observations.List(ctx, source.SessionID) {
		items = append(items, packetEvidence(packet)...)
	}
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
		metadata := map[string]string{"inference_id": inferenceID, "model_version": prediction.GetModelVersion(), "feature_schema_version": prediction.GetFeatureSchemaVersion()}
		items = append(items,
			ingest.EvidenceInput{PropertyKey: "traffic.class", Value: structpb.NewStringValue(prediction.GetTrafficClass()), Source: model.SourceMLClassifier, Status: commonv1.EvidenceStatus_INFERRED, Confidence: prediction.GetConfidence(), ObservedAt: at, ResourceType: "FLOW", ResourceID: prediction.GetFlowId(), SchemaVersion: model.EvidenceSchemaVersion, Metadata: metadata},
			ingest.EvidenceInput{PropertyKey: "traffic.confidence", Value: structpb.NewNumberValue(prediction.GetConfidence()), Source: model.SourceMLClassifier, Status: commonv1.EvidenceStatus_INFERRED, Confidence: prediction.GetConfidence(), ObservedAt: at, ResourceType: "FLOW", ResourceID: prediction.GetFlowId(), SchemaVersion: model.EvidenceSchemaVersion, Metadata: metadata},
		)
		if explanation, explanationErr := p.ML.Explanation(ctx, inferenceID, prediction.GetPredictionId()); explanationErr == nil && len(explanation.GetFeatures()) > 0 {
			for _, feature := range explanation.GetFeatures() {
				items = append(items, ingest.EvidenceInput{PropertyKey: "shap." + feature.GetFeatureName(), Value: structpb.NewNumberValue(feature.GetAttribution()), Source: model.SourceSHAP, Status: commonv1.EvidenceStatus_INFERRED, Confidence: prediction.GetConfidence(), ObservedAt: at, ResourceType: "FLOW", ResourceID: prediction.GetFlowId(), SchemaVersion: model.EvidenceSchemaVersion, Metadata: metadata})
			}
		}
	}
	if len(items) > 0 {
		if _, err := p.Ingest.AddBatch(ctx, ingest.AddBatchRequest{FusionRunID: record.FusionRunID, Evidence: items}); err != nil {
			return err
		}
	}
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
	meta := map[string]string{"sensor_session_id": packet.SessionID}
	items := []ingest.EvidenceInput{}
	ikeID := fmt.Sprintf("%016x-%016x", packet.IKEInitiatorSPI, packet.IKEResponderSPI)
	if packet.IKE && packet.IKEVersion != "" {
		items = append(items, stringEvidence("ike.version", packet.IKEVersion, "IKE_SA", ikeID, at, meta), stringEvidence("ike.initiator_spi", fmt.Sprintf("0x%016x", packet.IKEInitiatorSPI), "IKE_SA", ikeID, at, meta), stringEvidence("ike.responder_spi", fmt.Sprintf("0x%016x", packet.IKEResponderSPI), "IKE_SA", ikeID, at, meta))
	}
	if packet.Protocol == 50 || packet.EncapsulatedESP {
		id := fmt.Sprintf("0x%08x", packet.SPI)
		items = append(items, stringEvidence("child.protocol", "ESP", "ESP_STREAM", id, at, meta), stringEvidence("esp.spi", id, "ESP_STREAM", id, at, meta), stringEvidence("metadata.exposure", "outer endpoints, timing, direction and volume", "ESP_STREAM", id, at, meta))
	}
	if packet.Protocol == 51 {
		id := fmt.Sprintf("0x%08x", packet.SPI)
		items = append(items, stringEvidence("child.protocol", "AH", "AH_STREAM", id, at, meta), stringEvidence("ah.spi", id, "AH_STREAM", id, at, meta))
	}
	if packet.NATT {
		items = append(items, stringEvidence("nat_traversal.detected", "true", "NAT_TRAVERSAL", packet.SessionID, at, meta))
	}
	return items
}

func stringEvidence(key, value, typ, id string, at time.Time, metadata map[string]string) ingest.EvidenceInput {
	return ingest.EvidenceInput{PropertyKey: key, Value: structpb.NewStringValue(value), Source: model.SourcePacketParser, Status: commonv1.EvidenceStatus_OBSERVED, Confidence: .95, ObservedAt: at.UTC(), ResourceType: typ, ResourceID: id, SchemaVersion: model.EvidenceSchemaVersion, Metadata: metadata}
}

func numberEvidence(key string, value float64, typ, id string, at time.Time) ingest.EvidenceInput {
	return ingest.EvidenceInput{PropertyKey: key, Value: structpb.NewNumberValue(value), Source: model.SourceFlowAnalyzer, Status: commonv1.EvidenceStatus_DERIVED, Confidence: .9, ObservedAt: at.UTC(), ResourceType: typ, ResourceID: id, SchemaVersion: model.EvidenceSchemaVersion}
}
