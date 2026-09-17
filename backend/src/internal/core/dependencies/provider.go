// Package dependencies reports local in-process Sensor capabilities and the
// availability of the optional Python ML process without exposing Sensor RPCs.
package dependencies

import (
	"context"
	"os"
	"time"

	coresystemv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/system"
	mlv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/ml/v1"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/localsensor"
	coresystem "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/system"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/acquisition"
	sensorsystem "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/system"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/vici"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/xfrm"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Provider struct {
	Sensor          acquisition.Services
	MLAddress       string
	FusionAvailable bool
	VICI            *vici.Service
	XFRM            *xfrm.Service
}

// SensorSystemProvider adapts the in-process Core dependency provider to the
// SensorSystem contract. Keeping this adapter separate prevents the two API
// versions from being accidentally conflated while allowing both surfaces to
// report the same real local dependencies.
type SensorSystemProvider struct{ Provider *Provider }

func (p SensorSystemProvider) Readiness(ctx context.Context) (sensorsystem.Readiness, error) {
	if p.Provider == nil {
		return sensorsystem.Readiness{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return sensorsystem.Readiness{}, err
	}
	ready := sensorsystem.ComponentUnavailable
	if p.Provider.sensorAvailable(ctx) {
		ready = sensorsystem.ComponentReady
	}
	temporary := sensorsystem.ComponentUnavailable
	if file, err := os.CreateTemp("", "ipsec-sensor-readiness-*"); err == nil {
		name := file.Name()
		_ = file.Close()
		_ = os.Remove(name)
		temporary = sensorsystem.ComponentReady
	}
	viciState, xfrmState := sensorsystem.ComponentUnavailable, sensorsystem.ComponentUnavailable
	if p.Provider.VICI != nil {
		if probe, err := p.Provider.VICI.Probe(ctx, vici.DefaultSocketURI); err == nil && probe.GetAvailable() {
			viciState = sensorsystem.ComponentReady
		}
	}
	if p.Provider.XFRM != nil {
		if caps, err := p.Provider.XFRM.Capabilities(ctx); err == nil && caps.GetAvailable() {
			xfrmState = sensorsystem.ComponentReady
		}
	}
	return sensorsystem.Readiness{CaptureEngine: ready, TempStorage: temporary, ProtocolEngine: sensorsystem.ComponentReady, VICI: viciState, XFRM: xfrmState}, nil
}

func (p SensorSystemProvider) Capabilities(ctx context.Context) (sensorsystem.Capabilities, error) {
	if p.Provider == nil {
		return sensorsystem.Capabilities{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return sensorsystem.Capabilities{}, err
	}
	live := p.Provider.sensorAvailable(ctx)
	probe := localsensor.Probe{}
	if value, err := p.Provider.SensorProbe(ctx); err == nil {
		probe = value
	}
	return sensorsystem.Capabilities{PassiveLive: live, PassivePCAP: true, DeepAssessment: probe.VICI.Available || probe.XFRM.Available, IPv4: true, IPv6: true, IKEv1: true, IKEv2: true, ESP: true, AH: true, NATT: true, VICI: probe.VICI.Available, XFRM: probe.XFRM.Available, FeatureWindows: true, SequenceSketches: true}, nil
}

func (p SensorSystemProvider) PipelineStats(ctx context.Context) (sensorsystem.PipelineStats, error) {
	if p.Provider == nil || p.Provider.Sensor.Flows == nil {
		return sensorsystem.PipelineStats{}, nil
	}
	if err := ctx.Err(); err != nil {
		return sensorsystem.PipelineStats{}, err
	}
	active, pending, _ := p.Provider.Sensor.Flows.RuntimeCounts()
	return sensorsystem.PipelineStats{ActiveFlows: active, FeatureQueueDepth: pending}, nil
}

func (p *Provider) Dependencies(ctx context.Context) (coresystem.Dependencies, error) {
	if err := ctx.Err(); err != nil {
		return coresystem.Dependencies{}, err
	}
	tempState := coresystemv1.DependencyState_UNAVAILABLE
	if file, err := os.CreateTemp("", "ipsec-core-readiness-*"); err == nil {
		name := file.Name()
		_ = file.Close()
		_ = os.Remove(name)
		tempState = coresystemv1.DependencyState_READY
	}
	sensorState := coresystemv1.DependencyState_UNAVAILABLE
	if p.sensorAvailable(ctx) {
		sensorState = coresystemv1.DependencyState_READY
	}
	mlState := coresystemv1.DependencyState_UNAVAILABLE
	if p.mlAvailable(ctx) {
		mlState = coresystemv1.DependencyState_READY
	}
	return coresystem.Dependencies{
		InMemoryStore: coresystemv1.DependencyState_READY,
		TempStorage:   tempState,
		Sensor:        sensorState,
		MLWorker:      mlState,
		FusionEngine:  dependencyState(p.FusionAvailable),
	}, nil
}

func dependencyState(available bool) coresystemv1.DependencyState {
	if available {
		return coresystemv1.DependencyState_READY
	}
	return coresystemv1.DependencyState_UNAVAILABLE
}

func (p *Provider) Capabilities(ctx context.Context) (coresystem.Capabilities, error) {
	if err := ctx.Err(); err != nil {
		return coresystem.Capabilities{}, err
	}
	passiveLive := p.sensorAvailable(ctx)
	mlAvailable := p.mlAvailable(ctx)
	probe, _ := p.SensorProbe(ctx)
	return coresystem.Capabilities{
		DeepAssessment:  probe.VICI.Available || probe.XFRM.Available,
		ExecutiveReport: true, TechnicalReport: true,
		PassiveLive: passiveLive,
		// The capture package can decode uploaded PCAP and the supported PCAPNG
		// packet blocks without relying on tcpdump or local capture privileges.
		PassivePCAP:        true,
		SecurityAssessment: true,
		RiskScoring:        true,
		ThreatMatrix:       true,
		MLClassification:   mlAvailable,
		SHAP:               mlAvailable,
		MetadataExposure:   true,
	}, nil
}

func (p *Provider) RuntimeInstrumentation(ctx context.Context) (coresystem.RuntimeInstrumentation, error) {
	if err := ctx.Err(); err != nil {
		return coresystem.RuntimeInstrumentation{}, err
	}
	if p.Sensor.Flows == nil {
		return coresystem.RuntimeInstrumentation{}, nil
	}
	_, pending, subscribers := p.Sensor.Flows.RuntimeCounts()
	return coresystem.RuntimeInstrumentation{EventSubscribers: subscribers, SensorQueueDepth: pending}, nil
}

func (p *Provider) SensorStatus(ctx context.Context) (localsensor.Status, error) {
	if err := ctx.Err(); err != nil {
		return localsensor.Status{}, err
	}
	capabilities, err := p.Capabilities(ctx)
	if err != nil {
		return localsensor.Status{}, err
	}
	var activeFlows, pending uint64
	if p.Sensor.Flows != nil {
		activeFlows, pending, _ = p.Sensor.Flows.RuntimeCounts()
	}
	return localsensor.Status{
		Ready:             capabilities.PassiveLive,
		SensorVersion:     "sensor.v1",
		SessionActive:     p.Sensor.Sessions != nil && p.Sensor.Sessions.ActiveCount() > 0,
		CaptureActive:     p.Sensor.Captures != nil && p.Sensor.Captures.Active(),
		PacketQueueDepth:  pending,
		FeatureQueueDepth: activeFlows,
	}, nil
}

func (p *Provider) SensorCapabilities(ctx context.Context) (localsensor.Capabilities, error) {
	if err := ctx.Err(); err != nil {
		return localsensor.Capabilities{}, err
	}
	live := p.sensorAvailable(ctx)
	probe, _ := p.SensorProbe(ctx)
	return localsensor.Capabilities{
		PassivePCAP: true, IKEv1: true, IKEv2: true, VICI: probe.VICI.Available, XFRM: probe.XFRM.Available, SequenceSketches: true,
		PassiveLive: live,
		IPv4:        true, IPv6: true,
		ESP: true, AH: true, NATT: true,
		FeatureWindows: true,
	}, nil
}

func (p *Provider) SensorProbe(ctx context.Context) (localsensor.Probe, error) {
	if err := ctx.Err(); err != nil {
		return localsensor.Probe{}, err
	}
	live := p.sensorAvailable(ctx)
	reason := "tcpdump is unavailable or capture permission has not been granted"
	if live {
		reason = ""
	}
	viciDependency := localsensor.Dependency{Reason: "StrongSwan VICI is unavailable"}
	if p.VICI != nil {
		if probe, err := p.VICI.Probe(ctx, vici.DefaultSocketURI); err == nil && probe.GetAvailable() {
			viciDependency = localsensor.Dependency{Available: true}
		} else if err != nil {
			viciDependency.Reason = err.Error()
		}
	}
	xfrmDependency := localsensor.Dependency{Reason: "Linux XFRM provider is unavailable"}
	if p.XFRM != nil {
		if capabilities, err := p.XFRM.Capabilities(ctx); err == nil && capabilities.GetAvailable() {
			xfrmDependency = localsensor.Dependency{Available: true}
		} else if err != nil {
			xfrmDependency.Reason = err.Error()
		}
	}
	return localsensor.Probe{
		PassiveLive: localsensor.Dependency{Available: live, Reason: reason},
		PassivePCAP: localsensor.Dependency{Available: true, Reason: "PCAP and supported PCAPNG packet blocks are available"},
		VICI:        viciDependency,
		XFRM:        xfrmDependency,
	}, nil
}

func (p *Provider) mlAvailable(ctx context.Context) bool {
	if p.MLAddress == "" {
		return false
	}
	probeCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	connection, err := grpc.NewClient(p.MLAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return false
	}
	defer connection.Close()
	status, err := mlv1.NewTrafficClassifierClient(connection).HealthCheck(probeCtx, &emptypb.Empty{})
	return err == nil && status.GetStatus() == mlv1.ServingStatus_SERVING_STATUS_SERVING && status.GetModelLoaded()
}

func (p *Provider) sensorAvailable(ctx context.Context) bool {
	return p.Sensor.Captures != nil && p.Sensor.Captures.Probe(ctx) == nil
}
