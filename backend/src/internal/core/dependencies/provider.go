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
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Provider struct {
	Sensor          acquisition.Services
	MLAddress       string
	FusionAvailable bool
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
	return coresystem.Capabilities{
		PassiveLive: passiveLive,
		// The capture package can decode an uploaded classic-PCAP stream without
		// relying on tcpdump or local capture privileges. PCAPNG is intentionally
		// not advertised until its parser is implemented.
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
	return localsensor.Capabilities{
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
	return localsensor.Probe{
		PassiveLive: localsensor.Dependency{Available: live, Reason: reason},
		PassivePCAP: localsensor.Dependency{Available: true, Reason: "classic PCAP decoding is available; PCAPNG is not supported by the Go decoder yet"},
		VICI:        localsensor.Dependency{Reason: "StrongSwan VICI decoder is not configured"},
		XFRM:        localsensor.Dependency{Reason: "Linux XFRM provider is not configured"},
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
