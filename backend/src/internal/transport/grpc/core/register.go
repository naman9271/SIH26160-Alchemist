package core

import (
	localsensorv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/localsensor"
	coresystemv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/system"
	workspacev1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/workspace"
	"google.golang.org/grpc"
)

func RegisterCoreServices(server grpc.ServiceRegistrar, system *SystemHandler, workspace *WorkspaceHandler, sensors ...*LocalSensorHandler) {
	coresystemv1.RegisterCoreSystemServiceServer(server, system)
	workspacev1.RegisterWorkspaceServiceServer(server, workspace)
	if len(sensors) > 0 && sensors[0] != nil {
		localsensorv1.RegisterLocalSensorStatusServiceServer(server, sensors[0])
	}
}
