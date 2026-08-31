package core

import (
	"context"

	policyv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/policy"
	corepolicy "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/policy"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
)

type PolicyHandler struct {
	policyv1.UnimplementedPolicyServiceServer
	service *corepolicy.Service
}

func NewPolicyHandler(service *corepolicy.Service) *PolicyHandler {
	return &PolicyHandler{service: service}
}
func (h *PolicyHandler) valid() error {
	if h == nil || h.service == nil {
		return shared.NewError(shared.Internal, "", "policy service is not configured")
	}
	return nil
}
func (h *PolicyHandler) List(ctx context.Context, _ *policyv1.ListPoliciesRequest) (*policyv1.ListPoliciesResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.List(ctx)
	return &policyv1.ListPoliciesResponse{Policies: v}, shared.ToGRPC(e)
}
func (h *PolicyHandler) Get(ctx context.Context, r *policyv1.GetPolicyRequest) (*policyv1.SecurityPolicy, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Get(ctx, r.GetPolicyId())
	return v, shared.ToGRPC(e)
}
func (h *PolicyHandler) GetActive(ctx context.Context, _ *policyv1.GetActivePolicyRequest) (*policyv1.SecurityPolicy, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Active(ctx)
	return v, shared.ToGRPC(e)
}
func (h *PolicyHandler) SetActive(ctx context.Context, r *policyv1.SetActivePolicyRequest) (*policyv1.SetActivePolicyResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.SetActive(ctx, r.GetPolicyId())
	return &policyv1.SetActivePolicyResponse{Policy: v}, shared.ToGRPC(e)
}
func (h *PolicyHandler) Validate(ctx context.Context, r *policyv1.ValidatePolicyRequest) (*policyv1.ValidatePolicyResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Validate(ctx, r.GetPolicy())
	return v, shared.ToGRPC(e)
}
func (h *PolicyHandler) Reload(ctx context.Context, _ *policyv1.ReloadPoliciesRequest) (*policyv1.ReloadPoliciesResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Reload(ctx)
	return v, shared.ToGRPC(e)
}
