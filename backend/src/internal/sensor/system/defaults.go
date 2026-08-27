package system

import "context"

type unavailableDependencies struct{}

func (unavailableDependencies) Readiness(context.Context) (Readiness, error) {
	return Readiness{
		CaptureEngine:  ComponentUnavailable,
		TempStorage:    ComponentUnavailable,
		ProtocolEngine: ComponentUnavailable,
		VICI:           ComponentUnavailable,
		XFRM:           ComponentUnavailable,
	}, nil
}

func (unavailableDependencies) Capabilities(context.Context) (Capabilities, error) {
	return Capabilities{}, nil
}

type zeroMetrics struct{}

func (zeroMetrics) PipelineStats(context.Context) (PipelineStats, error) {
	return PipelineStats{}, nil
}
