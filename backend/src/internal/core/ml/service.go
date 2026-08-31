// Package ml provides the frontend-facing lifecycle/read facade while keeping
// the Python TrafficClassifier contract authoritative for prediction semantics.
package ml

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	mlv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/ml"
	flowv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/flow"
	worker "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/ml/v1"
	coreinput "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/input"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/workspace"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/mlclient"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/flow"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Service struct {
	client    worker.TrafficClassifierClient
	predictor *mlclient.Client
	timeout   time.Duration
	workspace *workspace.Service
	input     *coreinput.Service
	flows     *flow.Service
	mu        sync.RWMutex
	jobs      map[string]*job
}
type job struct {
	id, analysisID, state, failure string
	predictions                    map[string]*mlv1.TrafficPrediction
	created                        time.Time
}

func New(client worker.TrafficClassifierClient, timeout time.Duration, state *workspace.Service, input *coreinput.Service, flows *flow.Service) *Service {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	s := &Service{client: client, timeout: timeout, workspace: state, input: input, flows: flows, jobs: map[string]*job{}}
	if client != nil {
		s.predictor, _ = mlclient.New(client, timeout)
	}
	return s
}

// SetTimeout applies a safe runtime timeout change to subsequent worker calls.
func (s *Service) SetTimeout(timeout time.Duration) {
	if s == nil || timeout <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.timeout = timeout
	if s.client != nil {
		s.predictor, _ = mlclient.New(s.client, timeout)
	}
}
func (s *Service) WorkerStatus(ctx context.Context) (*mlv1.MLWorkerStatus, error) {
	if s == nil || s.client == nil {
		return &mlv1.MLWorkerStatus{StatusMessage: "ML worker is not configured"}, nil
	}
	s.mu.RLock()
	timeout := s.timeout
	s.mu.RUnlock()
	start := time.Now()
	probe, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	status, err := s.client.HealthCheck(probe, &emptypb.Empty{})
	if err != nil {
		return &mlv1.MLWorkerStatus{LatencyMs: float64(time.Since(start).Microseconds()) / 1000, StatusMessage: err.Error()}, nil
	}
	available := status.GetStatus() == worker.ServingStatus_SERVING_STATUS_SERVING
	return &mlv1.MLWorkerStatus{Available: available, LatencyMs: float64(time.Since(start).Microseconds()) / 1000, ModelLoaded: status.GetModelLoaded(), ModelVersion: status.GetModelVersion(), FeatureSchemaVersion: "flow.v2", StatusMessage: status.GetStatus().String()}, nil
}
func (s *Service) ModelInfo(ctx context.Context) (*mlv1.ModelInfo, error) {
	status, err := s.WorkerStatus(ctx)
	if err != nil {
		return nil, err
	}
	if !status.GetModelLoaded() {
		return nil, shared.NewError(shared.FailedPrecondition, "", "ML worker has no loaded model")
	}
	return &mlv1.ModelInfo{ModelName: "TrafficClassifier", ModelVersion: status.GetModelVersion(), ModelFamily: "PYTHON_TRAFFIC_CLASSIFIER", Classes: []string{"WEB", "VIDEO", "VOIP", "EMAIL", "FILE_TRANSFER", "MESSAGING", "ICMP", "UNKNOWN"}, FeatureSchemaVersion: status.GetFeatureSchemaVersion(), SupportsShap: true}, nil
}
func (s *Service) Start(ctx context.Context, analysisID string, sequence, shap bool) (*mlv1.RunInferenceResponse, error) {
	if strings.TrimSpace(analysisID) == "" {
		return nil, shared.NewError(shared.InvalidArgument, "", "analysis_id is required")
	}
	if sequence {
		return nil, shared.NewError(shared.FailedPrecondition, "", "the canonical v1 ML worker has no sequence inference RPC")
	}
	s.mu.RLock()
	predictor := s.predictor
	s.mu.RUnlock()
	if predictor == nil || s.workspace == nil || s.input == nil || s.flows == nil {
		return nil, shared.NewError(shared.FailedPrecondition, "", "ML inference dependencies are not configured")
	}
	workspaceRecord, err := s.workspace.Get(ctx, "")
	if err != nil {
		return nil, err
	}
	if workspaceRecord.AnalysisID != analysisID {
		return nil, shared.NewError(shared.NotFound, "", "analysis was not found in current workspace")
	}
	source, err := s.input.Get(ctx, workspaceRecord.SourceID)
	if err != nil {
		return nil, err
	}
	id := uuid.NewString()
	item := &job{id: id, analysisID: analysisID, state: "RUNNING", predictions: map[string]*mlv1.TrafficPrediction{}}
	s.mu.Lock()
	s.jobs[id] = item
	s.mu.Unlock()
	flows, _, err := s.flows.List(ctx, &flowv1.ListFlowsRequest{SensorSessionId: source.SessionID, PageSize: 1000})
	if err != nil {
		return s.fail(id, err)
	}
	for _, f := range flows {
		windows, _, e := s.flows.Windows(ctx, flow.ToProto(f).GetFlowId(), 1000, "")
		if e != nil {
			return s.fail(id, e)
		}
		for _, w := range windows {
			if !w.IsMLReady() {
				continue
			}
			result, e := predictor.Predict(ctx, flow.ToFeature(w))
			if e != nil {
				return s.fail(id, e)
			}
			p := &mlv1.TrafficPrediction{PredictionId: id + ":" + result.GetFlowId(), FlowId: result.GetFlowId(), TrafficClass: result.GetPredictedClass().String(), Confidence: result.GetConfidence(), IsUnknown: result.GetIsUnknown(), ModelVersion: result.GetModelVersion(), FeatureSchemaVersion: "flow.v2", InferenceTimeMs: result.GetInferenceTimeMs(), ClassProbabilities: map[string]float64{}}
			for _, top := range result.GetTopPredictions() {
				p.ClassProbabilities[top.GetTrafficClass().String()] = top.GetConfidence()
			}
			item.predictions[p.PredictionId] = p
		}
	}
	s.mu.Lock()
	item.state = "COMPLETED"
	s.mu.Unlock()
	return &mlv1.RunInferenceResponse{InferenceId: id, State: "COMPLETED"}, nil
}
func (s *Service) fail(id string, e error) (*mlv1.RunInferenceResponse, error) {
	s.mu.Lock()
	if j := s.jobs[id]; j != nil {
		j.state = "FAILED"
		j.failure = e.Error()
	}
	s.mu.Unlock()
	return &mlv1.RunInferenceResponse{InferenceId: id, State: "FAILED"}, e
}
func (s *Service) Status(_ context.Context, id string) (*mlv1.InferenceStatus, error) {
	item, err := s.get(id)
	if err != nil {
		return nil, err
	}
	return &mlv1.InferenceStatus{InferenceId: item.id, AnalysisId: item.analysisID, State: item.state, FailureReason: item.failure}, nil
}
func (s *Service) Predictions(_ context.Context, id string, size uint32, token string) ([]*mlv1.TrafficPrediction, string, error) {
	item, err := s.get(id)
	if err != nil {
		return nil, "", err
	}
	out := make([]*mlv1.TrafficPrediction, 0, len(item.predictions))
	for _, p := range item.predictions {
		out = append(out, p)
	}
	return out, "", nil
}
func (s *Service) Prediction(_ context.Context, inferenceID, predictionID string) (*mlv1.TrafficPrediction, error) {
	item, err := s.get(inferenceID)
	if err != nil {
		return nil, err
	}
	if value := item.predictions[predictionID]; value != nil {
		return value, nil
	}
	return nil, shared.NewError(shared.NotFound, "", "prediction was not found")
}
func (s *Service) Explanation(_ context.Context, inferenceID, predictionID string) (*mlv1.PredictionExplanation, error) {
	if _, err := s.get(inferenceID); err != nil {
		return nil, err
	}
	return &mlv1.PredictionExplanation{PredictionId: predictionID, UnavailableReason: "no cached prediction explanation is available"}, nil
}
func (s *Service) Cancel(_ context.Context, id string) (*mlv1.CancelInferenceResponse, error) {
	item, err := s.get(id)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if item.state == "RUNNING" {
		item.state = "CANCELLED"
	}
	state := item.state
	s.mu.Unlock()
	return &mlv1.CancelInferenceResponse{InferenceId: id, State: state}, nil
}
func (s *Service) get(id string) (*job, error) {
	if s == nil || strings.TrimSpace(id) == "" {
		return nil, shared.NewError(shared.InvalidArgument, "", "inference_id is required")
	}
	s.mu.RLock()
	item := s.jobs[id]
	s.mu.RUnlock()
	if item == nil {
		return nil, shared.NewError(shared.NotFound, "", "inference was not found")
	}
	return item, nil
}
