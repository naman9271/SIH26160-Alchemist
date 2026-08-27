package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	sensorv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/acquisition"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/system"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/vici"
	transport "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/transport/grpc/sensor"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	services := acquisition.New(nil, nil, nil)
	grpcServer := grpc.NewServer()
	sensorv1.RegisterSensorSystemServiceServer(grpcServer, transport.NewSystemHandler(system.New(system.Options{})))
	transport.RegisterAcquisitionServices(grpcServer, transport.NewSessionHandler(services.Sessions), transport.NewNetworkInterfaceHandler(services.Interfaces), transport.NewCaptureHandler(services.Captures))
	transport.RegisterTelemetryServices(grpcServer, transport.NewFlowHandler(services.Flows), transport.NewViciHandler(vici.New(nil)))
	reflection.Register(grpcServer)
	grpcListener, err := net.Listen("tcp", ":50052")
	if err != nil {
		log.Fatalf("gRPC listener: %v", err)
	}
	go func() {
		if err := grpcServer.Serve(grpcListener); err != nil {
			log.Printf("gRPC server error: %v", err)
		}
	}()

	server := &http.Server{
		Addr:         ":8080",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"status":"ok","service":"ipsec-backend"}`)
	})

	go func() {
		log.Println("Server running on http://localhost:8080")

		if err := server.ListenAndServe(); err != nil &&
			err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop

	log.Println("Shutdown signal received")

	ctx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Graceful shutdown failed: %v", err)
		return
	}
	grpcServer.GracefulStop()

	log.Println("Server stopped")
}
