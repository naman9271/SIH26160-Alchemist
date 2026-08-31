package core

import (
	"context"
	"io"

	reportv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/report"
	coreartifact "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/artifact"
	corereport "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/report"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type ReportHandler struct {
	reportv1.UnimplementedReportServiceServer
	service *corereport.Service
}

func NewReportHandler(s *corereport.Service) *ReportHandler { return &ReportHandler{service: s} }
func (h *ReportHandler) valid() error {
	if h == nil || h.service == nil {
		return shared.NewError(shared.Internal, "", "report service is not configured")
	}
	return nil
}
func (h *ReportHandler) Generate(ctx context.Context, r *reportv1.GenerateReportRequest) (*reportv1.GenerateReportResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Generate(ctx, r)
	return &reportv1.GenerateReportResponse{ReportId: v.ID, State: v.State}, shared.ToGRPC(e)
}
func (h *ReportHandler) Get(ctx context.Context, r *reportv1.GetReportRequest) (*reportv1.Report, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Get(ctx, r.GetReportId())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	a, e := h.service.Artifact(ctx, r.GetReportId())
	return reportView(v, a), shared.ToGRPC(e)
}
func (h *ReportHandler) Download(r *reportv1.DownloadReportRequest, stream reportv1.ReportService_DownloadServer) error {
	if e := h.valid(); e != nil {
		return shared.ToGRPC(e)
	}
	a, e := h.service.Open(stream.Context(), r.GetReportId())
	if e != nil {
		return shared.ToGRPC(e)
	}
	f, _, e := h.service.ArtifactOpen(stream.Context(), a.ID)
	if e != nil {
		return shared.ToGRPC(e)
	}
	defer f.Close()
	buf := make([]byte, 32*1024)
	var offset uint64
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			if e := stream.Send(&reportv1.ReportChunk{Data: append([]byte(nil), buf[:n]...), Offset: offset}); e != nil {
				return e
			}
			offset += uint64(n)
		}
		if readErr == io.EOF {
			return stream.Send(&reportv1.ReportChunk{Offset: offset, Eof: true})
		}
		if readErr != nil {
			return shared.ToGRPC(readErr)
		}
	}
}
func (h *ReportHandler) Delete(ctx context.Context, r *reportv1.DeleteReportRequest) (*reportv1.DeleteReportResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	ok, e := h.service.Delete(ctx, r.GetReportId())
	return &reportv1.DeleteReportResponse{ReportId: r.GetReportId(), Deleted: ok}, shared.ToGRPC(e)
}
func (h *ReportHandler) ListTypes(context.Context, *reportv1.ListReportTypesRequest) (*reportv1.ListReportTypesResponse, error) {
	return &reportv1.ListReportTypesResponse{Types: []*reportv1.ReportTypeDescriptor{{Id: "EXECUTIVE_PDF", Type: reportv1.ReportType_EXECUTIVE, Format: reportv1.ReportFormat_PDF, DisplayName: "Executive PDF"}, {Id: "TECHNICAL_PDF", Type: reportv1.ReportType_TECHNICAL, Format: reportv1.ReportFormat_PDF, DisplayName: "Technical PDF"}, {Id: "JSON", Type: reportv1.ReportType_JSON, Format: reportv1.ReportFormat_JSON_FORMAT, DisplayName: "JSON"}}}, nil
}
func reportView(v corereport.Record, a coreartifact.Record) *reportv1.Report {
	return &reportv1.Report{ReportId: v.ID, AnalysisId: v.AnalysisID, Type: v.Type, Format: v.Format, State: v.State, MimeType: a.MIMEType, SizeBytes: a.Size, FailureReason: v.Failure, CreatedAt: timestamppb.New(v.CreatedAt), UpdatedAt: timestamppb.New(v.UpdatedAt), ExpiresAt: timestamppb.New(v.ExpiresAt)}
}
