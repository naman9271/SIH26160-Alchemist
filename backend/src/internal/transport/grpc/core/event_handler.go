package core

import (
	eventv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/event"
	coreevents "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/events"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/workspace"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	fusionevent "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/event"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// EventHandler projects the existing Fusion event history into the public Core
// stream, so Core does not duplicate or lose Fusion events.
type EventHandler struct {
	eventv1.UnimplementedEventServiceServer
	workspace  *workspace.Service
	events     *fusionevent.Service
	coreEvents *coreevents.Service
}

func NewEventHandler(workspaceService *workspace.Service, events *fusionevent.Service, coreEvents *coreevents.Service) *EventHandler {
	return &EventHandler{workspace: workspaceService, events: events, coreEvents: coreEvents}
}
func (h *EventHandler) Subscribe(request *eventv1.SubscribeRequest, stream eventv1.EventService_SubscribeServer) error {
	if h == nil || h.workspace == nil || h.events == nil || h.coreEvents == nil {
		return shared.ToGRPC(shared.NewError(shared.Internal, "", "event service is not configured"))
	}
	ctx := stream.Context()
	current, err := h.workspace.Get(ctx, request.GetWorkspaceId())
	if err != nil {
		return shared.ToGRPC(err)
	}
	analysisID := request.GetAnalysisId()
	if analysisID == "" {
		analysisID = current.AnalysisID
	}
	if analysisID == "" {
		return shared.ToGRPC(shared.NewError(shared.FailedPrecondition, "", "workspace has no analysis to subscribe to"))
	}
	if current.AnalysisID != analysisID {
		return shared.ToGRPC(shared.NewError(shared.NotFound, "", "analysis is not in the selected workspace"))
	}
	if current.FusionRunID == "" {
		return shared.ToGRPC(shared.NewError(shared.FailedPrecondition, "", "analysis has no Fusion event stream"))
	}
	subscription, err := h.events.Subscribe(ctx, fusionevent.SubscribeRequest{FusionRunID: current.FusionRunID, Types: typesFor(request.GetCategories()), AfterSequence: request.GetAfterSequence()})
	if err != nil {
		return shared.ToGRPC(err)
	}
	coreEvents, cancel := h.coreEvents.Subscribe(ctx)
	defer cancel()
	for {
		select {
		case err, ok := <-subscription.Errors:
			if ok && err != nil {
				return shared.ToGRPC(err)
			}
			return nil
		case item, ok := <-subscription.Events:
			if !ok {
				return nil
			}
			category := categoryFor(item.Type)
			if category == eventv1.CoreEventCategory_CORE_EVENT_CATEGORY_UNSPECIFIED {
				continue
			}
			payload, _ := structpb.NewStruct(map[string]any{"fusion_run_id": item.FusionRunID, "property_key": item.PropertyKey, "evidence_id": item.EvidenceID, "conflict_id": item.ConflictID, "conclusion_id": item.ConclusionID, "reason_code": item.ReasonCode, "source": string(item.Source)})
			if err := stream.Send(&eventv1.CoreEvent{EventId: item.ID, Sequence: item.Sequence, Category: category, WorkspaceId: current.ID, AnalysisId: analysisID, OccurredAt: timestamppb.New(item.OccurredAt), Payload: payload}); err != nil {
				return err
			}
		case item, ok := <-coreEvents:
			if !ok {
				return nil
			}
			if item.AnalysisID != analysisID || !matchesCategory(request.GetCategories(), item.Category) {
				continue
			}
			payload, _ := structpb.NewStruct(item.Payload)
			if err := stream.Send(&eventv1.CoreEvent{EventId: item.ID, Sequence: item.Sequence, Category: item.Category, WorkspaceId: current.ID, AnalysisId: analysisID, OccurredAt: timestamppb.New(item.OccurredAt), Payload: payload}); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
func matchesCategory(categories []eventv1.CoreEventCategory, value eventv1.CoreEventCategory) bool {
	if len(categories) == 0 {
		return true
	}
	for _, category := range categories {
		if category == value {
			return true
		}
	}
	return false
}
func typesFor(categories []eventv1.CoreEventCategory) []model.EventType {
	set := map[model.EventType]struct{}{}
	for _, c := range categories {
		for t, mapped := range eventCategories {
			if mapped == c {
				set[t] = struct{}{}
			}
		}
	}
	out := make([]model.EventType, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	return out
}

var eventCategories = map[model.EventType]eventv1.CoreEventCategory{model.EventFusionRunCreated: eventv1.CoreEventCategory_FUSION_STARTED, model.EventConclusionCreated: eventv1.CoreEventCategory_FUSION_CONCLUSION_UPDATED, model.EventConclusionUpdated: eventv1.CoreEventCategory_FUSION_CONCLUSION_UPDATED, model.EventConflictDetected: eventv1.CoreEventCategory_FUSION_CONFLICT, model.EventConflictResolved: eventv1.CoreEventCategory_FUSION_CONFLICT, model.EventFusionFinalized: eventv1.CoreEventCategory_FUSION_COMPLETED, model.EventFusionFailed: eventv1.CoreEventCategory_ANALYSIS_FAILED, model.EventSourceCompleted: eventv1.CoreEventCategory_SOURCE_READY}

func categoryFor(t model.EventType) eventv1.CoreEventCategory { return eventCategories[t] }
