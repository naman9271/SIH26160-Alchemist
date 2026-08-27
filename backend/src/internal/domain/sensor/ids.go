// Package sensor contains transport-neutral domain conventions shared by all
// Sensor services.
package sensor

import (
	"fmt"

	"github.com/google/uuid"
)

// The distinct types prevent accidental mixing of opaque logical resource IDs
// in future Sensor services while keeping their wire representation a string.
type (
	SensorSessionID string
	WorkspaceID     string
	CaptureID       string
	PCAPID          string
	FlowID          string
	ProtocolEventID string
	IKESAID         string
	ChildSAID       string
)

func NewSensorSessionID() (SensorSessionID, error) { return newID[SensorSessionID]() }
func NewWorkspaceID() (WorkspaceID, error)         { return newID[WorkspaceID]() }
func NewCaptureID() (CaptureID, error)             { return newID[CaptureID]() }
func NewPCAPID() (PCAPID, error)                   { return newID[PCAPID]() }
func NewFlowID() (FlowID, error)                   { return newID[FlowID]() }
func NewProtocolEventID() (ProtocolEventID, error) { return newID[ProtocolEventID]() }
func NewIKESAID() (IKESAID, error)                 { return newID[IKESAID]() }
func NewChildSAID() (ChildSAID, error)             { return newID[ChildSAID]() }

func newID[T ~string]() (T, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("generate UUIDv7: %w", err)
	}
	return T(id.String()), nil
}
