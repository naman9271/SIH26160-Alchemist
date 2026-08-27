// Package acquisition wires the services that share session/capture lifecycle state.
package acquisition

import (
	"context"

	flowv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/flow"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/capture"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/flow"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/network"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/session"
)

type Services struct {
	Sessions   *session.Service
	Interfaces *network.Service
	Captures   *capture.Service
	Flows      *flow.Service
}

type lifecycleHooks struct {
	capture *capture.Service
	flow    *flow.Service
}

func (h lifecycleHooks) StopForSession(ctx context.Context, id string) error {
	if err := h.capture.StopForSession(ctx, id); err != nil {
		return err
	}
	return h.flow.StopForSession(ctx, id)
}
func (h lifecycleHooks) ResetForSession(ctx context.Context, id string, remove bool) error {
	if err := h.capture.ResetForSession(ctx, id, remove); err != nil {
		return err
	}
	return h.flow.ResetForSession(ctx, id, remove)
}

func New(engine capture.Engine, counters network.CounterReader, metrics capture.FlowMetrics) Services {
	sessions := session.New()
	captures := capture.New(sessions, engine, metrics)
	flows := flow.New(64)
	captures.SetPacketObserver(func(ctx context.Context, packet capture.PacketMetadata) error {
		return observePacket(ctx, flows, packet)
	})
	sessions.SetLifecycleHooks(lifecycleHooks{capture: captures, flow: flows})
	return Services{Sessions: sessions, Interfaces: network.New(counters, captures), Captures: captures, Flows: flows}
}

func observePacket(ctx context.Context, flows *flow.Service, p capture.PacketMetadata) error {
	protocol := flowv1.FlowProtocol_OTHER
	switch p.Protocol {
	case 50:
		protocol = flowv1.FlowProtocol_ESP
	case 51:
		protocol = flowv1.FlowProtocol_AH
	case 17:
		if p.SourcePort == 4500 || p.DestinationPort == 4500 {
			protocol = flowv1.FlowProtocol_NAT_T
		} else if p.SourcePort == 500 || p.DestinationPort == 500 {
			protocol = flowv1.FlowProtocol_IKE
		}
	}
	_, err := flows.ObservePacket(ctx, flow.Packet{SessionID: p.SessionID, Protocol: protocol, SourceAddress: p.SourceAddress, DestinationAddress: p.DestinationAddress, SourcePort: uint32(p.SourcePort), DestinationPort: uint32(p.DestinationPort), SPI: p.SPI, Size: p.Length, SeenAt: p.SeenAt})
	return err
}
