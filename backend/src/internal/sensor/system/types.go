package system

import (
	"context"
	"time"
)

// ComponentState describes availability of a Sensor dependency.
type ComponentState string

const (
	ComponentReady       ComponentState = "READY"
	ComponentDegraded    ComponentState = "DEGRADED"
	ComponentUnavailable ComponentState = "UNAVAILABLE"
)

type Readiness struct {
	CaptureEngine  ComponentState
	TempStorage    ComponentState
	ProtocolEngine ComponentState
	VICI           ComponentState
	XFRM           ComponentState
}

// PassiveReady deliberately excludes VICI and XFRM: they enrich Deep
// Assessment but are not prerequisites for passive acquisition.
func (r Readiness) PassiveReady() bool {
	return r.CaptureEngine == ComponentReady &&
		r.TempStorage == ComponentReady &&
		r.ProtocolEngine == ComponentReady
}

type Capabilities struct {
	PassiveLive      bool
	PassivePCAP      bool
	DeepAssessment   bool
	IPv4             bool
	IPv6             bool
	IKEv1            bool
	IKEv2            bool
	ESP              bool
	AH               bool
	NATT             bool
	VICI             bool
	XFRM             bool
	FeatureWindows   bool
	SequenceSketches bool
}

type RuntimeStats struct {
	UptimeSeconds      uint64
	CPUPercent         float64
	RSSBytes           uint64
	Goroutines         uint32
	ActiveFlows        uint64
	PacketQueueDepth   uint64
	FeatureQueueDepth  uint64
	TemporaryDiskBytes uint64
}

// DependencyProvider gives the system service a seam for capture, protocol,
// VICI and XFRM implementations without making it own those subsystems.
type DependencyProvider interface {
	Readiness(context.Context) (Readiness, error)
	Capabilities(context.Context) (Capabilities, error)
}

// MetricsProvider is implemented by the future capture/flow/feature pipeline.
// Its zero-value implementation accurately communicates that no pipeline is
// connected yet.
type MetricsProvider interface {
	PipelineStats(context.Context) (PipelineStats, error)
}

type PipelineStats struct {
	ActiveFlows        uint64
	PacketQueueDepth   uint64
	FeatureQueueDepth  uint64
	TemporaryDiskBytes uint64
}

type Version struct {
	SensorVersion string
	BuildCommit   string
}

type Options struct {
	StartedAt    time.Time
	Version      Version
	Dependencies DependencyProvider
	Metrics      MetricsProvider
}
