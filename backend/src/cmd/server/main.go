package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	coresystemv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/system"
	mlworkerv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/ml/v1"
	coreanalysis "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/analysis"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/dependencies"
	corefusion "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/fusion"
	coreinput "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/input"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/localsensor"
	coreml "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/ml"
	corepolicy "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/policy"
	coreprotocol "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/protocolread"
	corerisk "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/risk"
	coresecurity "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/security"
	coresystem "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/system"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/workspace"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/acquisition"
	coretransport "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/transport/grpc/core"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	sensorServices := acquisition.New(nil, nil, nil)
	fusionRuntime := fusion.NewRuntime(fusion.RuntimeOptions{})
	fusionReadiness, fusionReadinessErr := fusionRuntime.System.Readiness(context.Background())
	workspaceService := workspace.New(workspace.Options{})
	provider := &dependencies.Provider{
		Sensor:          sensorServices,
		MLAddress:       envOrDefault("ML_GRPC_ADDRESS", "127.0.0.1:50051"),
		FusionAvailable: fusionReadinessErr == nil && fusionReadiness.Ready,
	}
	systemService := coresystem.New(coresystem.Options{
		Dependencies: provider,
		Metrics:      provider,
		Workspace:    workspaceService,
	})
	protocolService := coreprotocol.New(coreprotocol.WorkspaceRunResolver{Workspace: workspaceService}, fusionRuntime.Query, sensorServices)
	inputService := coreinput.New(sensorServices)
	analysisService := coreanalysis.New(inputService, fusionRuntime.Sessions, workspaceService)
	securityService := coresecurity.New(protocolService)
	riskService := corerisk.New(securityService)
	policyService := corepolicy.New(fusionRuntime.Policy)
	fusionService := corefusion.New(coreprotocol.WorkspaceRunResolver{Workspace: workspaceService}, fusionRuntime.Fusion, fusionRuntime.Provenance, fusionRuntime.Ingest)
	mlConnection, mlConnectionErr := grpc.NewClient(provider.MLAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if mlConnectionErr != nil {
		logger.Warn("ML client initialization failed", "error", mlConnectionErr)
	}
	var mlWorker mlworkerv1.TrafficClassifierClient
	if mlConnectionErr == nil {
		defer mlConnection.Close()
		mlWorker = mlworkerv1.NewTrafficClassifierClient(mlConnection)
	}
	mlService := coreml.New(mlWorker, 2*time.Second, workspaceService, inputService, sensorServices.Flows)

	grpcServer := grpc.NewServer()
	coretransport.RegisterCoreServices(
		grpcServer,
		coretransport.NewSystemHandler(systemService),
		coretransport.NewWorkspaceHandler(workspaceService),
		coretransport.NewLocalSensorHandler(localsensor.New(provider)),
		coretransport.NewInputHandler(inputService, workspaceService),
		coretransport.NewAnalysisHandler(analysisService),
		coretransport.NewProtocolReadHandler(protocolService),
		coretransport.NewSecurityHandler(securityService),
		coretransport.NewRiskHandler(riskService),
		coretransport.NewPolicyHandler(policyService),
		coretransport.NewMLHandler(mlService),
		coretransport.NewFusionHandler(fusionService),
	)
	grpcAddress := envOrDefault("CORE_GRPC_ADDRESS", "127.0.0.1:50052")
	grpcListener, err := net.Listen("tcp", grpcAddress)
	if err != nil {
		logger.Error("gRPC listener failed", "address", grpcAddress, "error", err)
		os.Exit(1)
	}
	go func() {
		logger.Info("Core gRPC server started", "address", grpcAddress)
		if serveErr := grpcServer.Serve(grpcListener); serveErr != nil {
			logger.Error("Core gRPC server stopped unexpectedly", "error", serveErr)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /live", func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(response, http.StatusOK, map[string]any{"status": "alive", "service": "ipsec-core"})
	})
	mux.HandleFunc("GET /health", func(response http.ResponseWriter, request *http.Request) {
		states, readinessErr := systemService.Readiness(request.Context())
		ready := readinessErr == nil &&
			states.InMemoryStore == coresystemv1.DependencyState_READY &&
			states.TempStorage == coresystemv1.DependencyState_READY &&
			states.Sensor == coresystemv1.DependencyState_READY &&
			states.MLWorker == coresystemv1.DependencyState_READY &&
			states.FusionEngine == coresystemv1.DependencyState_READY
		statusCode, status := http.StatusOK, "ready"
		if !ready {
			statusCode, status = http.StatusServiceUnavailable, "degraded"
		}
		writeJSON(response, statusCode, map[string]any{
			"status": status,
			"ready":  ready,
			"dependencies": map[string]string{
				"memory": states.InMemoryStore.String(), "temp_storage": states.TempStorage.String(),
				"sensor": states.Sensor.String(), "ml": states.MLWorker.String(), "fusion": states.FusionEngine.String(),
			},
		})
	})
	httpAddress := envOrDefault("CORE_HTTP_ADDRESS", "127.0.0.1:8080")
	httpServer := &http.Server{
		Addr: httpAddress, Handler: mux,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second,
	}
	go func() {
		logger.Info("Core HTTP status server started", "address", httpAddress)
		if serveErr := httpServer.ListenAndServe(); serveErr != nil && serveErr != http.ErrServerClosed {
			logger.Error("HTTP server stopped unexpectedly", "error", serveErr)
		}
	}()

	shutdownSignal, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-shutdownSignal.Done()
	logger.Info("shutdown requested")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTP graceful shutdown failed", "error", err)
	}
	grpcDone := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(grpcDone)
	}()
	select {
	case <-grpcDone:
	case <-shutdownCtx.Done():
		grpcServer.Stop()
	}
	logger.Info("server stopped")
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
