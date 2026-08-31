package core

import (
	analysisv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/analysis"
	fusionv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/fusion"
	inputv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/input"
	localsensorv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/localsensor"
	mlv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/ml"
	policyv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/policy"
	protocolreadv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/protocolread"
	riskv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/risk"
	securityv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/security"
	coresystemv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/system"
	workspacev1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/workspace"
	"google.golang.org/grpc"
)

func RegisterCoreServices(server grpc.ServiceRegistrar, system *SystemHandler, workspace *WorkspaceHandler, handlers ...any) {
	coresystemv1.RegisterCoreSystemServiceServer(server, system)
	workspacev1.RegisterWorkspaceServiceServer(server, workspace)
	for _, handler := range handlers {
		switch value := handler.(type) {
		case *LocalSensorHandler:
			if value != nil {
				localsensorv1.RegisterLocalSensorStatusServiceServer(server, value)
			}
		case *ProtocolReadHandler:
			if value != nil {
				protocolreadv1.RegisterProtocolReadServiceServer(server, value)
			}
		case *SecurityHandler:
			if value != nil {
				securityv1.RegisterSecurityAssessmentServiceServer(server, value)
			}
		case *RiskHandler:
			if value != nil {
				riskv1.RegisterRiskServiceServer(server, value)
			}
		case *InputHandler:
			if value != nil {
				inputv1.RegisterInputServiceServer(server, value)
			}
		case *AnalysisHandler:
			if value != nil {
				analysisv1.RegisterAnalysisServiceServer(server, value)
			}
		case *PolicyHandler:
			if value != nil {
				policyv1.RegisterPolicyServiceServer(server, value)
			}
		case *MLHandler:
			if value != nil {
				mlv1.RegisterMLOrchestrationServiceServer(server, value)
			}
		case *FusionHandler:
			if value != nil {
				fusionv1.RegisterFusionOrchestrationServiceServer(server, value)
			}
		}
	}
}
