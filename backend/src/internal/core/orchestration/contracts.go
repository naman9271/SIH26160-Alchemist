// Package orchestration defines workspace-scoped seams shared by external Core
// services. Concrete Sensor, ML, Fusion, Security and Risk implementations
// bind here; Core handlers never maintain shadow subsystem state.
package orchestration

import "context"

// Availability records a current, probe-derived dependency state.
type Availability struct {
	Available bool
	Reason    string
}

// LocalSensor exposes the existing local Sensor module to Core orchestration.
// Implementations must use current Sensor state rather than cached Core data.
type LocalSensor interface {
	Availability(context.Context) (Availability, error)
}

// WorkspaceCleaner is implemented by a subsystem that owns ephemeral state.
type WorkspaceCleaner interface {
	Cleanup(context.Context, string, bool, bool) error
}
