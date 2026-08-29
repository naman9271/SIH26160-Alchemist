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
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/dependencies"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/localsensor"
	coresystem "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/system"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/workspace"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/acquisition"
<<<<<<< HEAD
	coretransport "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/transport/grpc/core"
=======
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/system"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/vici"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/xfrm"
	transport "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/transport/grpc/sensor"
>>>>>>> decaacd (fixed the non working api's)
	"google.golang.org/grpc"
)

func main() {
<<<<<<< HEAD
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	sensorServices := acquisition.New(nil, nil, nil)
	fusionEngine := fusion.New()
	workspaceService := workspace.New(workspace.Options{})
	provider := &dependencies.Provider{
		Sensor:          sensorServices,
		MLAddress:       envOrDefault("ML_GRPC_ADDRESS", "127.0.0.1:50051"),
		FusionAvailable: fusionEngine != nil,
=======
	services := acquisition.New(nil, nil, nil)
	grpcServer := grpc.NewServer()
	sensorv1.RegisterSensorSystemServiceServer(grpcServer, transport.NewSystemHandler(system.New(system.Options{})))
	transport.RegisterAcquisitionServices(grpcServer, transport.NewSessionHandler(services.Sessions), transport.NewNetworkInterfaceHandler(services.Interfaces), transport.NewCaptureHandler(services.Captures))
	transport.RegisterTelemetryServices(grpcServer, transport.NewFlowHandler(services.Flows), transport.NewViciHandler(vici.New(nil)))
	transport.RegisterDeepAndTelemetryServices(grpcServer, transport.NewXfrmHandler(xfrm.New(nil)), transport.NewTelemetryHandler(services.Sessions, services.Flows))
	reflection.Register(grpcServer)
	grpcListener, err := net.Listen("tcp", ":50052")
	if err != nil {
		log.Fatalf("gRPC listener: %v", err)
>>>>>>> decaacd (fixed the non working api's)
	}
	systemService := coresystem.New(coresystem.Options{
		Dependencies: provider,
		Metrics:      provider,
		Workspace:    workspaceService,
	})

	grpcServer := grpc.NewServer()
	coretransport.RegisterCoreServices(
		grpcServer,
		coretransport.NewSystemHandler(systemService),
		coretransport.NewWorkspaceHandler(workspaceService),
		coretransport.NewLocalSensorHandler(localsensor.New(provider)),
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
