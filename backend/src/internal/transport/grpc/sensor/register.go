package sensor

import (
	capturev1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/capture"
	flowv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/flow"
	networkv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/network"
	sessionv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/session"
	viciv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/vici"
	"google.golang.org/grpc"
)

// RegisterAcquisitionServices registers the connected Session, Network and
// Capture APIs on a caller-owned gRPC server.
func RegisterAcquisitionServices(server grpc.ServiceRegistrar, sessions *SessionHandler, interfaces *NetworkInterfaceHandler, captures *CaptureHandler) {
	sessionv1.RegisterSensorSessionServiceServer(server, sessions)
	networkv1.RegisterNetworkInterfaceServiceServer(server, interfaces)
	capturev1.RegisterPassiveCaptureServiceServer(server, captures)
}

// RegisterTelemetryServices registers payload-free flow telemetry and the
// read-only normalized StrongSwan VICI boundary.
func RegisterTelemetryServices(server grpc.ServiceRegistrar, flows *FlowHandler, vici *ViciHandler) {
	if flows != nil {
		flowv1.RegisterFlowTelemetryServiceServer(server, flows)
	}
	if vici != nil {
		viciv1.RegisterStrongSwanViciServiceServer(server, vici)
	}
}
