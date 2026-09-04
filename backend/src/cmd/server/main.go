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

	runtimeconfigv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/runtimeconfig"
	coresystemv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/system"
	sensorv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1"
	mlworkerv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/ml/v1"
	coreanalysis "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/analysis"
	coreartifact "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/artifact"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/dependencies"
	coreevents "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/events"
	corefusion "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/fusion"
	coreinput "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/input"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/localsensor"
	coreml "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/ml"
	corepolicy "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/policy"
	coreprotocol "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/protocolread"
	corereport "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/report"
	corerisk "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/risk"
	coreruntimeconfig "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/runtimeconfig"
	coresecurity "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/security"
	coresystem "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/system"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/workspace"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/acquisition"
	sensorsystem "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/system"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/vici"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/xfrm"
	coretransport "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/transport/grpc/core"
	sensortransport "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/transport/grpc/sensor"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	sensorServices := acquisition.New(nil, nil, nil)
	var viciBackend vici.Backend = vici.NewRealBackend(3 * time.Second)
	if path := os.Getenv("VICI_FIXTURE_PATH"); path != "" {
		fixture, err := vici.LoadFixture(path)
		if err != nil {
			logger.Error("invalid VICI fixture", "path", path, "error", err)
			os.Exit(1)
		}
		viciBackend = fixture
	}
	viciService := vici.New(viciBackend)
	xfrmProvider := xfrm.NewRealProvider()
	if path := os.Getenv("XFRM_FIXTURE_PATH"); path != "" {
		fixture, err := xfrm.LoadFixture(path)
		if err != nil {
			logger.Error("invalid XFRM fixture", "path", path, "error", err)
			os.Exit(1)
		}
		xfrmProvider = fixture
	}
	xfrmService := xfrm.New(xfrmProvider)
	fusionRuntime := fusion.NewRuntime(fusion.RuntimeOptions{})
	fusionReadiness, fusionReadinessErr := fusionRuntime.System.Readiness(context.Background())
	workspaceService := workspace.New(workspace.Options{})
	provider := &dependencies.Provider{
		Sensor:          sensorServices,
		MLAddress:       envOrDefault("ML_GRPC_ADDRESS", "127.0.0.1:50051"),
		FusionAvailable: fusionReadinessErr == nil && fusionReadiness.Ready,
		VICI:            viciService, XFRM: xfrmService,
	}
	systemService := coresystem.New(coresystem.Options{
		Dependencies: provider,
		Metrics:      provider,
		Workspace:    workspaceService,
	})
	protocolService := coreprotocol.New(coreprotocol.WorkspaceRunResolver{Workspace: workspaceService}, fusionRuntime.Query, sensorServices)
	inputService := coreinput.New(sensorServices)
	analysisService := coreanalysis.New(inputService, fusionRuntime.Sessions, workspaceService)
	runtimeConfigService := coreruntimeconfig.New(coreruntimeconfig.Defaults(envOrDefault("REPORT_TEMP_DIRECTORY", "")))
	artifactService := coreartifact.New(runtimeConfigService.ReportDirectory)
	coreEventService := coreevents.New()
	analysisService.SetEvents(coreEventService)
	policyService := corepolicy.New(fusionRuntime.Policy)
	localSensorService := localsensor.New(provider)
	sensorSystemService := sensorsystem.New(sensorsystem.Options{Dependencies: dependencies.SensorSystemProvider{Provider: provider}, Metrics: dependencies.SensorSystemProvider{Provider: provider}})
	fusionService := corefusion.New(coreprotocol.WorkspaceRunResolver{Workspace: workspaceService}, fusionRuntime.Fusion, fusionRuntime.Provenance, fusionRuntime.Ingest)
	securityService := coresecurity.New(fusionService)
	riskService := corerisk.New(securityService)
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
	analysisService.SetReadModels(coreanalysis.ReadModels{Fusion: fusionService, Security: securityService, Risk: riskService, ML: mlService})
	reportService := corereport.New(analysisService, fusionService, artifactService, workspaceService, securityService, riskService, mlService, coreEventService)
	analysisService.SetPipeline(&coreanalysis.Pipeline{Sensor: sensorServices, Input: inputService, Ingest: fusionRuntime.Ingest, Fusion: fusionRuntime.Fusion, ML: mlService, Security: securityService, Risk: riskService, Events: coreEventService, VICI: viciService, XFRM: xfrmService, VICIURI: envOrDefault("VICI_SOCKET_URI", vici.DefaultSocketURI)})
	// Apply safe runtime changes to the services that own these settings.
	runtimeConfigService.Subscribe(func(config *runtimeconfigv1.RuntimeConfig) {
		mlService.SetTimeout(time.Duration(config.GetMlTimeoutMs()) * time.Millisecond)
		fusionService.SetRecomputationTimeout(time.Duration(config.GetFusionRecomputationTimeoutMs()) * time.Millisecond)
		coreEventService.SetBufferSize(config.GetEventBufferSize())
	})

	grpcServer := grpc.NewServer()
	coretransport.RegisterCoreServices(
		grpcServer,
		coretransport.NewSystemHandler(systemService),
		coretransport.NewWorkspaceHandler(workspaceService),
		coretransport.NewLocalSensorHandler(localSensorService),
		coretransport.NewInputHandler(inputService, workspaceService),
		coretransport.NewAnalysisHandler(analysisService),
		coretransport.NewProtocolReadHandler(protocolService),
		coretransport.NewSecurityHandler(securityService),
		coretransport.NewRiskHandler(riskService),
		coretransport.NewPolicyHandler(policyService),
		coretransport.NewMLHandler(mlService),
		coretransport.NewFusionHandler(fusionService),
		coretransport.NewReportHandler(reportService),
		coretransport.NewArtifactHandler(artifactService),
		coretransport.NewRuntimeConfigHandler(runtimeConfigService),
		coretransport.NewEventHandler(workspaceService, fusionRuntime.Events, coreEventService),
	)
	// Sensor services share the Core gRPC listener but were previously only
	// constructed in-process. Register them so every implemented Sensor API is
	// reachable by trusted gRPC clients; the browser still uses the HTTP BFF.
	sensortransport.RegisterAcquisitionServices(
		grpcServer,
		sensortransport.NewSessionHandler(sensorServices.Sessions),
		sensortransport.NewNetworkInterfaceHandler(sensorServices.Interfaces),
		sensortransport.NewCaptureHandler(sensorServices.Captures),
	)
	sensorv1.RegisterSensorSystemServiceServer(grpcServer, sensortransport.NewSystemHandler(sensorSystemService))
	sensortransport.RegisterDeepAndTelemetryServices(
		grpcServer,
		sensortransport.NewXfrmHandler(xfrmService),
		sensortransport.NewTelemetryHandler(sensorServices.Sessions, sensorServices.Flows),
	)
	sensortransport.RegisterTelemetryServices(
		grpcServer,
		sensortransport.NewFlowHandler(sensorServices.Flows),
		sensortransport.NewViciHandler(viciService),
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
		// Offline PCAP analysis is the baseline supported workflow. Live capture
		// and ML inference are selected per analysis, so their optional runtime
		// dependencies must be reported without making the whole Core unavailable.
		ready := readinessErr == nil &&
			states.InMemoryStore == coresystemv1.DependencyState_READY &&
			states.TempStorage == coresystemv1.DependencyState_READY &&
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
	registerWorkflowAPI(mux, inputService, analysisService, reportService, workspaceService, protocolService, fusionService, securityService, riskService, mlService, sensorServices.Flows, systemService, localSensorService)
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
