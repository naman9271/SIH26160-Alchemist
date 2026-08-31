package core

import (
	"context"
	artifactv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/artifact"
	coreartifact "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/artifact"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"google.golang.org/protobuf/types/known/timestamppb"
	"time"
)

type ArtifactHandler struct {
	artifactv1.UnimplementedArtifactServiceServer
	service *coreartifact.Service
}

func NewArtifactHandler(s *coreartifact.Service) *ArtifactHandler {
	return &ArtifactHandler{service: s}
}
func (h *ArtifactHandler) valid() error {
	if h == nil || h.service == nil {
		return shared.NewError(shared.Internal, "", "artifact service is not configured")
	}
	return nil
}
func (h *ArtifactHandler) List(ctx context.Context, r *artifactv1.ListArtifactsRequest) (*artifactv1.ListArtifactsResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	values, e := h.service.List(ctx, r.GetType(), r.GetAnalysisId())
	out := &artifactv1.ListArtifactsResponse{}
	for _, v := range values {
		out.Artifacts = append(out.Artifacts, artifactView(v))
	}
	return out, shared.ToGRPC(e)
}
func (h *ArtifactHandler) Get(ctx context.Context, r *artifactv1.GetArtifactRequest) (*artifactv1.Artifact, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Get(ctx, r.GetArtifactId())
	return artifactView(v), shared.ToGRPC(e)
}
func (h *ArtifactHandler) Delete(ctx context.Context, r *artifactv1.DeleteArtifactRequest) (*artifactv1.DeleteArtifactResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	ok, e := h.service.Delete(ctx, r.GetArtifactId())
	return &artifactv1.DeleteArtifactResponse{ArtifactId: r.GetArtifactId(), Deleted: ok}, shared.ToGRPC(e)
}
func (h *ArtifactHandler) Cleanup(ctx context.Context, r *artifactv1.CleanupArtifactsRequest) (*artifactv1.CleanupArtifactsResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	var before time.Time
	if r.GetExpiredBefore() != nil {
		before = r.GetExpiredBefore().AsTime()
	}
	n, e := h.service.Cleanup(ctx, before, r.GetIncludeReferenced())
	return &artifactv1.CleanupArtifactsResponse{DeletedCount: n}, shared.ToGRPC(e)
}
func artifactView(v coreartifact.Record) *artifactv1.Artifact {
	return &artifactv1.Artifact{ArtifactId: v.ID, Type: v.Type, Name: v.Name, MimeType: v.MIMEType, SizeBytes: v.Size, AnalysisId: v.AnalysisID, CreatedAt: timestamppb.New(v.CreatedAt), ExpiresAt: timestamppb.New(v.ExpiresAt)}
}
