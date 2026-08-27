package core

import (
	coresystemv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/system"
	workspacev1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/workspace"
	"google.golang.org/grpc"
)

func RegisterCoreServices(server grpc.ServiceRegistrar, system *SystemHandler, workspace *WorkspaceHandler) {
	coresystemv1.RegisterCoreSystemServiceServer(server, system)
	workspacev1.RegisterWorkspaceServiceServer(server, workspace)
}
