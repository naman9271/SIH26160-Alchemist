// Package query implements the internal EvidenceQueryService contract.
package query

import (
	"context"
	"encoding/base64"
	"strconv"
	"strings"
	"time"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/store"
)

const maxPageSize = 1000

type Store interface {
	Get(context.Context, string) (model.Run, error)
}

type Filter struct {
	Source       model.Source
	Status       commonv1.EvidenceStatus
	PropertyKey  string
	ResourceType string
	ResourceID   string
	ObservedFrom time.Time
	ObservedTo   time.Time
}

type ListRequest struct {
	FusionRunID string
	Filter      Filter
	PageSize    uint32
	PageToken   string
}

type ListResponse struct {
	Evidence      []model.EvidenceItem
	NextPageToken string
}

type GetRequest struct {
	FusionRunID string
	EvidenceID  string
}

type ListByPropertyRequest struct {
	FusionRunID string
	PropertyKey string
	PageSize    uint32
	PageToken   string
}

type ListByResourceRequest struct {
	FusionRunID  string
	ResourceType string
	ResourceID   string
	PageSize     uint32
	PageToken    string
}

type SourceCoverageResponse struct {
	Coverage map[model.Source]model.SourceCoverage
}

type Service struct{ store Store }

func New(store Store) *Service { return &Service{store: store} }

func (s *Service) List(ctx context.Context, request ListRequest) (ListResponse, error) {
	if err := s.ready(ctx, request.FusionRunID); err != nil {
		return ListResponse{}, err
	}
	request.Filter.PropertyKey = strings.TrimSpace(request.Filter.PropertyKey)
	request.Filter.ResourceType = strings.ToUpper(strings.TrimSpace(request.Filter.ResourceType))
	request.Filter.ResourceID = strings.TrimSpace(request.Filter.ResourceID)
	if err := validateFilter(request.Filter); err != nil {
		return ListResponse{}, err
	}
	pageSize, err := normalizePageSize(request.PageSize)
	if err != nil {
		return ListResponse{}, err
	}
	after, err := decodeCursor(request.PageToken)
	if err != nil {
		return ListResponse{}, err
	}
	run, err := s.store.Get(ctx, strings.TrimSpace(request.FusionRunID))
	if err != nil {
		return ListResponse{}, err
	}
	items := store.SortedEvidence(run)
	result := make([]model.EvidenceItem, 0, pageSize)
	var hasMore bool
	for _, item := range items {
		if !matches(item, request.Filter) || !after.before(item) {
			continue
		}
		if len(result) == pageSize {
			hasMore = true
			break
		}
		result = append(result, item.Clone())
	}
	next := ""
	if hasMore {
		next = encodeCursor(result[len(result)-1])
	}
	return ListResponse{Evidence: result, NextPageToken: next}, nil
}

func (s *Service) Get(ctx context.Context, request GetRequest) (model.EvidenceItem, error) {
	if err := s.ready(ctx, request.FusionRunID); err != nil {
		return model.EvidenceItem{}, err
	}
	if err := model.ValidateEvidenceID(request.EvidenceID); err != nil {
		return model.EvidenceItem{}, err
	}
	run, err := s.store.Get(ctx, strings.TrimSpace(request.FusionRunID))
	if err != nil {
		return model.EvidenceItem{}, err
	}
	item, exists := run.EvidenceByID[strings.TrimSpace(request.EvidenceID)]
	if !exists {
		return model.EvidenceItem{}, model.NewError(model.ErrorNotFound, "evidence item was not found")
	}
	return item.Clone(), nil
}

func (s *Service) ListByProperty(ctx context.Context, request ListByPropertyRequest) (ListResponse, error) {
	property := strings.TrimSpace(request.PropertyKey)
	if property == "" {
		return ListResponse{}, model.NewError(model.ErrorInvalidArgument, "property_key is required")
	}
	return s.List(ctx, ListRequest{
		FusionRunID: request.FusionRunID, Filter: Filter{PropertyKey: property},
		PageSize: request.PageSize, PageToken: request.PageToken,
	})
}

func (s *Service) ListByResource(ctx context.Context, request ListByResourceRequest) (ListResponse, error) {
	resourceType, resourceID := strings.ToUpper(strings.TrimSpace(request.ResourceType)), strings.TrimSpace(request.ResourceID)
	if resourceType == "" || resourceID == "" {
		return ListResponse{}, model.NewError(model.ErrorInvalidArgument, "resource_type and resource_id are required")
	}
	return s.List(ctx, ListRequest{
		FusionRunID: request.FusionRunID, Filter: Filter{ResourceType: resourceType, ResourceID: resourceID},
		PageSize: request.PageSize, PageToken: request.PageToken,
	})
}

func (s *Service) GetSourceCoverage(ctx context.Context, fusionRunID string) (SourceCoverageResponse, error) {
	if err := s.ready(ctx, fusionRunID); err != nil {
		return SourceCoverageResponse{}, err
	}
	run, err := s.store.Get(ctx, strings.TrimSpace(fusionRunID))
	if err != nil {
		return SourceCoverageResponse{}, err
	}
	coverage := make(map[model.Source]model.SourceCoverage, len(run.SourceCoverage))
	for source, value := range run.SourceCoverage {
		coverage[source] = value
	}
	return SourceCoverageResponse{Coverage: coverage}, nil
}

func (s *Service) ready(ctx context.Context, runID string) error {
	if err := model.ContextError(ctx); err != nil {
		return err
	}
	if s == nil || s.store == nil {
		return model.NewError(model.ErrorInternal, "evidence store is not configured")
	}
	return model.ValidateRunID(runID)
}

func validateFilter(filter Filter) error {
	if filter.Source != "" && !filter.Source.Valid() {
		return model.NewError(model.ErrorInvalidArgument, "evidence source filter is invalid")
	}
	if filter.Status < commonv1.EvidenceStatus_EVIDENCE_STATUS_UNSPECIFIED || filter.Status > commonv1.EvidenceStatus_UNKNOWN {
		return model.NewError(model.ErrorInvalidArgument, "evidence status filter is invalid")
	}
	if !filter.ObservedFrom.IsZero() && !filter.ObservedTo.IsZero() && filter.ObservedFrom.After(filter.ObservedTo) {
		return model.NewError(model.ErrorInvalidArgument, "observed_from must not be after observed_to")
	}
	if (filter.ResourceType == "") != (filter.ResourceID == "") {
		return model.NewError(model.ErrorInvalidArgument, "resource_type and resource_id filters must be provided together")
	}
	return nil
}

func matches(item model.EvidenceItem, filter Filter) bool {
	return (filter.Source == "" || item.Source == filter.Source) &&
		(filter.Status == commonv1.EvidenceStatus_EVIDENCE_STATUS_UNSPECIFIED || item.Status == filter.Status) &&
		(filter.PropertyKey == "" || item.PropertyKey == filter.PropertyKey) &&
		(filter.ResourceType == "" || strings.EqualFold(item.ResourceType, filter.ResourceType)) &&
		(filter.ResourceID == "" || item.ResourceID == filter.ResourceID) &&
		(filter.ObservedFrom.IsZero() || !item.ObservedAt.Before(filter.ObservedFrom)) &&
		(filter.ObservedTo.IsZero() || !item.ObservedAt.After(filter.ObservedTo))
}

func normalizePageSize(size uint32) (int, error) {
	if size == 0 {
		return 100, nil
	}
	if size > maxPageSize {
		return 0, model.NewError(model.ErrorInvalidArgument, "page_size must not exceed 1000")
	}
	return int(size), nil
}

type cursor struct {
	nanos int64
	id    string
}

func (c cursor) before(item model.EvidenceItem) bool {
	if c.id == "" {
		return true
	}
	nanos := item.ObservedAt.UnixNano()
	return nanos > c.nanos || nanos == c.nanos && item.ID > c.id
}

func encodeCursor(item model.EvidenceItem) string {
	value := strconv.FormatInt(item.ObservedAt.UnixNano(), 10) + ":" + item.ID
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}

func decodeCursor(token string) (cursor, error) {
	if strings.TrimSpace(token) == "" {
		return cursor{}, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return cursor{}, model.NewError(model.ErrorInvalidArgument, "page_token is invalid")
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 || model.ValidateEvidenceID(parts[1]) != nil {
		return cursor{}, model.NewError(model.ErrorInvalidArgument, "page_token is invalid")
	}
	nanos, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return cursor{}, model.NewError(model.ErrorInvalidArgument, "page_token is invalid")
	}
	return cursor{nanos: nanos, id: parts[1]}, nil
}
