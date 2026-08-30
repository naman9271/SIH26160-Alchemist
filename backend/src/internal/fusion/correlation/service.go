// Package correlation implements deterministic logical-resource correlation.
package correlation

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/store"
)

var supportedResourceTypes = map[string]struct{}{
	"IKE_SA": {}, "CHILD_SA": {}, "ESP_STREAM": {}, "VPN_SESSION": {}, "FLOW": {},
}

type Store interface {
	Get(context.Context, string) (model.Run, error)
	ReplaceCorrelations(context.Context, string, []model.CorrelationGroup) (model.Run, error)
}
type EventPublisher interface {
	Publish(context.Context, model.FusionEvent) error
}

type CorrelateRequest struct{ FusionRunID string }

type CorrelateResponse struct {
	CorrelationGroupsCreated uint64
	EvidenceItemsLinked      uint64
	AmbiguousItems           uint64
	TotalGroups              uint64
}

type CorrelationDetail struct {
	Group    model.CorrelationGroup
	Evidence []model.EvidenceItem
}

type GetRequest struct {
	FusionRunID   string
	CorrelationID string
}

type ListRequest struct {
	FusionRunID  string
	ResourceType string
	PageSize     uint32
	PageToken    string
}

type ListResponse struct {
	Groups        []model.CorrelationGroup
	NextPageToken string
}

type RebuildResponse struct {
	Result  CorrelateResponse
	Rebuilt bool
}

type Service struct {
	store  Store
	mu     sync.Mutex
	now    func() time.Time
	newID  func() (string, error)
	events EventPublisher
}

func New(store Store, publishers ...EventPublisher) *Service {
	service := &Service{store: store, now: func() time.Time { return time.Now().UTC() }, newID: model.NewCorrelationID}
	if len(publishers) > 0 {
		service.events = publishers[0]
	}
	return service
}

func (s *Service) Ready(ctx context.Context) (bool, string) {
	if err := model.ContextError(ctx); err != nil {
		return false, err.Error()
	}
	if s == nil || s.store == nil {
		return false, "correlation store is not configured"
	}
	return true, ""
}

func (s *Service) Correlate(ctx context.Context, request CorrelateRequest) (CorrelateResponse, error) {
	return s.correlate(ctx, request.FusionRunID)
}

func (s *Service) Rebuild(ctx context.Context, fusionRunID string) (RebuildResponse, error) {
	result, err := s.correlate(ctx, fusionRunID)
	return RebuildResponse{Result: result, Rebuilt: err == nil}, err
}

func (s *Service) GetCorrelation(ctx context.Context, request GetRequest) (CorrelationDetail, error) {
	if err := s.ready(ctx, request.FusionRunID); err != nil {
		return CorrelationDetail{}, err
	}
	if err := model.ValidateCorrelationID(request.CorrelationID); err != nil {
		return CorrelationDetail{}, err
	}
	run, err := s.store.Get(ctx, strings.TrimSpace(request.FusionRunID))
	if err != nil {
		return CorrelationDetail{}, err
	}
	group, exists := run.Correlations[strings.TrimSpace(request.CorrelationID)]
	if !exists {
		return CorrelationDetail{}, model.NewError(model.ErrorNotFound, "correlation group was not found")
	}
	evidence := make([]model.EvidenceItem, 0, len(group.EvidenceIDs))
	for _, id := range group.EvidenceIDs {
		if item, ok := run.EvidenceByID[id]; ok {
			evidence = append(evidence, item.Clone())
		}
	}
	return CorrelationDetail{Group: group.Clone(), Evidence: evidence}, nil
}

func (s *Service) ListCorrelations(ctx context.Context, request ListRequest) (ListResponse, error) {
	if err := s.ready(ctx, request.FusionRunID); err != nil {
		return ListResponse{}, err
	}
	resourceType := strings.ToUpper(strings.TrimSpace(request.ResourceType))
	if resourceType != "" {
		if _, valid := supportedResourceTypes[resourceType]; !valid {
			return ListResponse{}, model.NewError(model.ErrorInvalidArgument, "correlation resource_type is invalid")
		}
	}
	pageSize := int(request.PageSize)
	if pageSize == 0 {
		pageSize = 100
	}
	if pageSize > 1000 {
		return ListResponse{}, model.NewError(model.ErrorInvalidArgument, "page_size must not exceed 1000")
	}
	if request.PageToken != "" {
		if err := model.ValidateCorrelationID(request.PageToken); err != nil {
			return ListResponse{}, model.NewError(model.ErrorInvalidArgument, "page_token is invalid")
		}
	}
	run, err := s.store.Get(ctx, strings.TrimSpace(request.FusionRunID))
	if err != nil {
		return ListResponse{}, err
	}
	groups := make([]model.CorrelationGroup, 0, len(run.Correlations))
	for _, group := range run.Correlations {
		if resourceType == "" || group.ResourceType == resourceType {
			groups = append(groups, group.Clone())
		}
	}
	sortGroups(groups)
	start := 0
	if request.PageToken != "" {
		found := false
		for index, group := range groups {
			if group.ID == request.PageToken {
				start, found = index+1, true
				break
			}
		}
		if !found {
			return ListResponse{}, model.NewError(model.ErrorInvalidArgument, "page_token does not belong to this result set")
		}
	}
	end := start + pageSize
	if end > len(groups) {
		end = len(groups)
	}
	next := ""
	if end < len(groups) {
		next = groups[end-1].ID
	}
	return ListResponse{Groups: groups[start:end], NextPageToken: next}, nil
}

func (s *Service) correlate(ctx context.Context, runID string) (CorrelateResponse, error) {
	if err := s.ready(ctx, runID); err != nil {
		return CorrelateResponse{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := model.ContextError(ctx); err != nil {
		return CorrelateResponse{}, err
	}
	run, err := s.store.Get(ctx, strings.TrimSpace(runID))
	if err != nil {
		return CorrelateResponse{}, err
	}
	if run.State != model.RunStateActive {
		return CorrelateResponse{}, model.NewError(model.ErrorFailedPrecondition, "correlation requires an active Fusion run")
	}
	items := store.SortedEvidence(run)
	candidates := make([]candidate, 0, len(items))
	var ambiguous uint64
	for _, item := range items {
		resourceType := normalizedResourceType(item)
		keys := correlationKeys(item, resourceType)
		if resourceType == "" || len(keys) == 0 {
			ambiguous++
			continue
		}
		candidates = append(candidates, candidate{item: item, resourceType: resourceType, keys: keys})
	}
	groups, created, err := s.buildGroups(run, candidates)
	if err != nil {
		return CorrelateResponse{}, err
	}
	if _, err = s.store.ReplaceCorrelations(ctx, run.ID, groups); err != nil {
		return CorrelateResponse{}, err
	}
	if s.events != nil {
		current := make(map[string]struct{}, len(groups))
		for _, group := range groups {
			current[group.ID] = struct{}{}
			eventType := model.EventCorrelationCreated
			if previous, exists := run.Correlations[group.ID]; exists {
				if slices.Equal(previous.EvidenceIDs, group.EvidenceIDs) && maps.Equal(previous.Keys, group.Keys) {
					continue
				}
				eventType = model.EventCorrelationChanged
			}
			if err = s.events.Publish(ctx, model.FusionEvent{FusionRunID: run.ID, AnalysisID: run.AnalysisID, Type: eventType, OccurredAt: s.now().UTC(), CorrelationID: group.ID}); err != nil {
				return CorrelateResponse{}, &model.Error{Kind: model.ErrorUnavailable, Message: "correlations changed but their events could not be emitted", Cause: err}
			}
		}
		for id := range run.Correlations {
			if _, exists := current[id]; exists {
				continue
			}
			if err = s.events.Publish(ctx, model.FusionEvent{FusionRunID: run.ID, AnalysisID: run.AnalysisID, Type: model.EventCorrelationChanged,
				OccurredAt: s.now().UTC(), CorrelationID: id}); err != nil {
				return CorrelateResponse{}, &model.Error{Kind: model.ErrorUnavailable, Message: "correlations changed but their events could not be emitted", Cause: err}
			}
		}
	}
	return CorrelateResponse{
		CorrelationGroupsCreated: created, EvidenceItemsLinked: uint64(len(candidates)),
		AmbiguousItems: ambiguous, TotalGroups: uint64(len(groups)),
	}, nil
}

type candidate struct {
	item         model.EvidenceItem
	resourceType string
	keys         map[string]string
}

func (s *Service) buildGroups(run model.Run, candidates []candidate) ([]model.CorrelationGroup, uint64, error) {
	parents := make([]int, len(candidates))
	for index := range parents {
		parents[index] = index
	}
	firstByToken := make(map[string]int)
	for index, item := range candidates {
		for key, value := range item.keys {
			token := item.resourceType + "\x00" + key + "\x00" + value
			if first, exists := firstByToken[token]; exists {
				union(parents, index, first)
			} else {
				firstByToken[token] = index
			}
		}
	}
	components := make(map[int][]candidate)
	for index, item := range candidates {
		root := find(parents, index)
		components[root] = append(components[root], item)
	}
	existingByEvidence := make(map[string]model.CorrelationGroup)
	for _, group := range run.Correlations {
		for _, evidenceID := range group.EvidenceIDs {
			existingByEvidence[evidenceID] = group
		}
	}
	now := s.now().UTC()
	usedIDs := make(map[string]struct{})
	groups := make([]model.CorrelationGroup, 0, len(components))
	var created uint64
	for _, component := range components {
		sort.Slice(component, func(i, j int) bool { return component[i].item.ID < component[j].item.ID })
		group, reused := reusableGroup(component, existingByEvidence, usedIDs)
		if !reused {
			id, err := s.newID()
			if err != nil {
				return nil, 0, &model.Error{Kind: model.ErrorInternal, Message: "could not generate correlation ID", Cause: err}
			}
			group = model.CorrelationGroup{ID: id, CreatedAt: now}
			created++
		}
		usedIDs[group.ID] = struct{}{}
		group.ResourceType = component[0].resourceType
		group.EvidenceIDs = group.EvidenceIDs[:0]
		for _, item := range component {
			group.EvidenceIDs = append(group.EvidenceIDs, item.item.ID)
		}
		group.Keys = commonKeys(component)
		group.ResourceID = logicalResourceID(component, group.ID)
		group.UpdatedAt = now
		groups = append(groups, group)
	}
	sortGroups(groups)
	return groups, created, nil
}

func normalizedResourceType(item model.EvidenceItem) string {
	metadata := make(map[string]string, len(item.Metadata))
	for key, value := range item.Metadata {
		metadata[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	if value := strings.ToUpper(metadata["correlation_resource_type"]); value != "" {
		if _, valid := supportedResourceTypes[value]; valid {
			return value
		}
	}
	value := strings.ToUpper(strings.TrimSpace(item.ResourceType))
	switch value {
	case "IKE_SA", "VICI_IKE_SA":
		return "IKE_SA"
	case "CHILD_SA", "VICI_CHILD_SA":
		return "CHILD_SA"
	case "ESP_STREAM":
		return "ESP_STREAM"
	case "VPN_SESSION":
		return "VPN_SESSION"
	case "FLOW":
		return "FLOW"
	case "XFRM_STATE":
		if metadata["reqid"] != "" {
			return "CHILD_SA"
		}
		return "ESP_STREAM"
	default:
		return ""
	}
}

func correlationKeys(item model.EvidenceItem, resourceType string) map[string]string {
	keys := map[string]string{"resource_id": strings.TrimSpace(item.ResourceID)}
	metadata := make(map[string]string, len(item.Metadata))
	for key, value := range item.Metadata {
		metadata[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	for _, key := range []string{
		"ike_initiator_spi", "ike_responder_spi", "esp_spi", "ah_spi", "reqid",
		"endpoint_tuple", "traffic_selectors", "strongswan_unique_id", "xfrm_state_identity",
	} {
		if value := metadata[key]; value != "" {
			keys[key] = normalizeKeyValue(value)
		}
	}
	propertyKeys := map[string]string{
		"ike.initiator_spi": "ike_initiator_spi", "ike.responder_spi": "ike_responder_spi",
		"esp.spi": "esp_spi", "ah.spi": "ah_spi", "sa.reqid": "reqid",
	}
	if key := propertyKeys[item.PropertyKey]; key != "" {
		if value := scalarValue(item); value != "" {
			keys[key] = normalizeKeyValue(value)
		}
	}
	for key, value := range keys {
		if value == "" {
			delete(keys, key)
		}
	}
	if resourceType == "" {
		return nil
	}
	return keys
}

func scalarValue(item model.EvidenceItem) string {
	if item.Value == nil {
		return ""
	}
	switch value := item.Value.AsInterface().(type) {
	case string:
		return value
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(value)
	default:
		return ""
	}
}

func normalizeKeyValue(value string) string { return strings.ToLower(strings.TrimSpace(value)) }

func reusableGroup(component []candidate, existing map[string]model.CorrelationGroup, used map[string]struct{}) (model.CorrelationGroup, bool) {
	counts := make(map[string]int)
	groups := make(map[string]model.CorrelationGroup)
	for _, item := range component {
		if group, exists := existing[item.item.ID]; exists {
			if _, alreadyUsed := used[group.ID]; !alreadyUsed {
				counts[group.ID]++
				groups[group.ID] = group
			}
		}
	}
	bestID, bestCount := "", 0
	for id, count := range counts {
		if count > bestCount || count == bestCount && (bestID == "" || id < bestID) {
			bestID, bestCount = id, count
		}
	}
	if bestID == "" {
		return model.CorrelationGroup{}, false
	}
	return groups[bestID].Clone(), true
}

func commonKeys(component []candidate) map[string]string {
	values := make(map[string]map[string]struct{})
	for _, item := range component {
		for key, value := range item.keys {
			if values[key] == nil {
				values[key] = make(map[string]struct{})
			}
			values[key][value] = struct{}{}
		}
	}
	result := make(map[string]string)
	for key, candidates := range values {
		if len(candidates) == 1 {
			for value := range candidates {
				result[key] = value
			}
		}
	}
	return result
}

func logicalResourceID(component []candidate, fallback string) string {
	ids := make(map[string]struct{})
	for _, item := range component {
		ids[item.item.ResourceID] = struct{}{}
	}
	if len(ids) == 1 {
		for id := range ids {
			return id
		}
	}
	return fallback
}

func find(parents []int, value int) int {
	for parents[value] != value {
		parents[value] = parents[parents[value]]
		value = parents[value]
	}
	return value
}

func union(parents []int, left, right int) {
	left, right = find(parents, left), find(parents, right)
	if left != right {
		if left < right {
			parents[right] = left
		} else {
			parents[left] = right
		}
	}
}

func sortGroups(groups []model.CorrelationGroup) {
	sort.Slice(groups, func(i, j int) bool {
		left := fmt.Sprintf("%s\x00%s\x00%s", groups[i].ResourceType, groups[i].ResourceID, groups[i].ID)
		right := fmt.Sprintf("%s\x00%s\x00%s", groups[j].ResourceType, groups[j].ResourceID, groups[j].ID)
		return left < right
	})
}

func (s *Service) ready(ctx context.Context, runID string) error {
	if err := model.ContextError(ctx); err != nil {
		return err
	}
	if s == nil || s.store == nil {
		return model.NewError(model.ErrorInternal, "correlation store is not configured")
	}
	return model.ValidateRunID(runID)
}
