// Package acquisition wires the services that share session/capture lifecycle state.
package acquisition

import (
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/capture"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/network"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/session"
)

type Services struct {
	Sessions   *session.Service
	Interfaces *network.Service
	Captures   *capture.Service
}

func New(engine capture.Engine, counters network.CounterReader, metrics capture.FlowMetrics) Services {
	sessions := session.New()
	captures := capture.New(sessions, engine, metrics)
	sessions.SetLifecycleHooks(captures)
	return Services{Sessions: sessions, Interfaces: network.New(counters, captures), Captures: captures}
}
