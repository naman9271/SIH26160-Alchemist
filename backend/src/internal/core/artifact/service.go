// Package artifact tracks temporary files created by Core services.
package artifact

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	artifactv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/artifact"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
)

type Record struct {
	ID, AnalysisID, Name, MIMEType, Path string
	Type                                 artifactv1.ArtifactType
	Size                                 uint64
	CreatedAt, ExpiresAt                 time.Time
	Referenced                           bool
}
type Service struct {
	mu        sync.RWMutex
	records   map[string]*Record
	directory func() string
}

func New(directory func() string) *Service {
	return &Service{records: map[string]*Record{}, directory: directory}
}
func (s *Service) Create(ctx context.Context, analysisID, name, mime string, typ artifactv1.ArtifactType, content []byte, ttl time.Duration) (Record, error) {
	if err := contextError(ctx); err != nil {
		return Record{}, err
	}
	if s == nil || s.directory == nil {
		return Record{}, shared.NewError(shared.Internal, "", "artifact service is not configured")
	}
	if strings.TrimSpace(analysisID) == "" || typ == artifactv1.ArtifactType_ARTIFACT_TYPE_UNSPECIFIED {
		return Record{}, shared.NewError(shared.InvalidArgument, "", "analysis_id and artifact type are required")
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Record{}, err
	}
	root := s.directory()
	if root == "" {
		return Record{}, shared.NewError(shared.FailedPrecondition, "", "report temporary directory is not configured")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return Record{}, err
	}
	path := filepath.Join(root, id.String())
	if err := os.WriteFile(path, content, 0600); err != nil {
		return Record{}, err
	}
	now := time.Now().UTC()
	record := &Record{ID: id.String(), AnalysisID: analysisID, Name: name, MIMEType: mime, Path: path, Type: typ, Size: uint64(len(content)), CreatedAt: now, ExpiresAt: now.Add(ttl)}
	s.mu.Lock()
	s.records[record.ID] = record
	s.mu.Unlock()
	return *record, nil
}
func (s *Service) Get(ctx context.Context, id string) (Record, error) {
	if err := contextError(ctx); err != nil {
		return Record{}, err
	}
	s.mu.RLock()
	item := clone(s.records[id])
	s.mu.RUnlock()
	if item == nil {
		return Record{}, shared.NewError(shared.NotFound, "", "artifact was not found")
	}
	return *item, nil
}
func (s *Service) List(ctx context.Context, typ artifactv1.ArtifactType, analysisID string) ([]Record, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	s.mu.RLock()
	out := []Record{}
	for _, item := range s.records {
		if (typ == artifactv1.ArtifactType_ARTIFACT_TYPE_UNSPECIFIED || item.Type == typ) && (analysisID == "" || item.AnalysisID == analysisID) {
			out = append(out, *clone(item))
		}
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}
func (s *Service) Open(ctx context.Context, id string) (io.ReadCloser, Record, error) {
	item, err := s.Get(ctx, id)
	if err != nil {
		return nil, Record{}, err
	}
	f, err := os.Open(item.Path)
	if os.IsNotExist(err) {
		return nil, Record{}, shared.NewError(shared.NotFound, "", "artifact file was not found")
	}
	return f, item, err
}
func (s *Service) Delete(ctx context.Context, id string) (bool, error) {
	if err := contextError(ctx); err != nil {
		return false, err
	}
	s.mu.Lock()
	item := s.records[id]
	if item != nil {
		delete(s.records, id)
	}
	s.mu.Unlock()
	if item == nil {
		return false, shared.NewError(shared.NotFound, "", "artifact was not found")
	}
	if err := os.Remove(item.Path); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	return true, nil
}
func (s *Service) SetReferenced(ctx context.Context, id string, referenced bool) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item := s.records[id]
	if item == nil {
		return shared.NewError(shared.NotFound, "", "artifact was not found")
	}
	item.Referenced = referenced
	return nil
}
func (s *Service) Cleanup(ctx context.Context, before time.Time, includeReferenced bool) (uint64, error) {
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	if before.IsZero() {
		before = time.Now().UTC()
	}
	ids := []string{}
	s.mu.RLock()
	for id, item := range s.records {
		if item.ExpiresAt.Before(before) && (includeReferenced || !item.Referenced) {
			ids = append(ids, id)
		}
	}
	s.mu.RUnlock()
	var n uint64
	for _, id := range ids {
		if ok, err := s.Delete(ctx, id); err != nil {
			return n, err
		} else if ok {
			n++
		}
	}
	return n, nil
}
func clone(v *Record) *Record {
	if v == nil {
		return nil
	}
	c := *v
	return &c
}
func contextError(ctx context.Context) error {
	if ctx == nil {
		return shared.NewError(shared.InvalidArgument, "", "context is required")
	}
	return ctx.Err()
}
