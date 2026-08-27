package sensor_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	sensorv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1"
	capturev1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/capture"
	networkv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/network"
	sessionv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/session"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/acquisition"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/system"
	transport "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/transport/grpc/sensor"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const bufferSize = 1024 * 1024

type grpcFixture struct {
	connection *grpc.ClientConn
	cleanup    func()
	system     sensorv1.SensorSystemServiceClient
	sessions   sessionv1.SensorSessionServiceClient
	interfaces networkv1.NetworkInterfaceServiceClient
	captures   capturev1.PassiveCaptureServiceClient
}

func newGRPCFixture(t *testing.T) grpcFixture {
	t.Helper()
	engine, counters := &fakeEngine{}, &fakeCounters{}
	services := acquisition.New(engine, counters, nil)
	grpcServer := grpc.NewServer()
	sensorv1.RegisterSensorSystemServiceServer(grpcServer, transport.NewSystemHandler(system.New(system.Options{
		Version:      system.Version{SensorVersion: "test-sensor", BuildCommit: "test-commit"},
		Dependencies: dependencyStub{readiness: system.Readiness{CaptureEngine: system.ComponentReady, TempStorage: system.ComponentReady, ProtocolEngine: system.ComponentReady, VICI: system.ComponentUnavailable, XFRM: system.ComponentUnavailable}, capabilities: system.Capabilities{PassiveLive: true, PassivePCAP: true, IPv4: true, IPv6: true, IKEv1: true, IKEv2: true, ESP: true, AH: true, NATT: true}},
		Metrics:      metricsStub{stats: system.PipelineStats{ActiveFlows: 4, PacketQueueDepth: 2, FeatureQueueDepth: 1, TemporaryDiskBytes: 64}},
	})))
	transport.RegisterAcquisitionServices(grpcServer, transport.NewSessionHandler(services.Sessions), transport.NewNetworkInterfaceHandler(services.Interfaces), transport.NewCaptureHandler(services.Captures))
	listener := bufconn.Listen(bufferSize)
	go func() { _ = grpcServer.Serve(listener) }()
	contextWithTimeout, cancel := context.WithTimeout(context.Background(), time.Second)
	connection, err := grpc.DialContext(contextWithTimeout, "bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	cancel()
	if err != nil {
		t.Fatalf("dial registered gRPC server: %v", err)
	}
	return grpcFixture{connection: connection, cleanup: func() { _ = connection.Close(); grpcServer.Stop(); _ = listener.Close() }, system: sensorv1.NewSensorSystemServiceClient(connection), sessions: sessionv1.NewSensorSessionServiceClient(connection), interfaces: networkv1.NewNetworkInterfaceServiceClient(connection), captures: capturev1.NewPassiveCaptureServiceClient(connection)}
}

func TestRegisteredGRPCServicesEndToEnd(t *testing.T) {
	fixture := newGRPCFixture(t)
	defer fixture.cleanup()
	ctx := context.Background()

	health, err := fixture.system.Health(ctx, &sensorv1.HealthRequest{})
	if err != nil || health.GetStatus() != sensorv1.HealthStatus_HEALTHY || health.GetTime() == nil || health.GetTime().CheckValid() != nil {
		t.Fatalf("Health = %+v, %v", health, err)
	}
	if health.GetTime().AsTime().UTC().Location() != time.UTC {
		t.Fatal("Health timestamp is not UTC")
	}
	readiness, err := fixture.system.Readiness(ctx, &sensorv1.ReadinessRequest{})
	if err != nil || !readiness.GetReady() || readiness.GetVici() != sensorv1.ReadinessComponentState_UNAVAILABLE {
		t.Fatalf("Readiness = %+v, %v", readiness, err)
	}
	version, err := fixture.system.GetVersion(ctx, &sensorv1.GetVersionRequest{})
	if err != nil || version.GetSensorVersion() != "test-sensor" || version.GetApiVersion() != "sensor.v1" || version.GetGoVersion() == "" || version.GetOs() == "" || version.GetArchitecture() == "" {
		t.Fatalf("GetVersion = %+v, %v", version, err)
	}
	capabilities, err := fixture.system.GetCapabilities(ctx, &sensorv1.GetCapabilitiesRequest{})
	if err != nil || !capabilities.GetPassiveLive() || capabilities.GetVici() {
		t.Fatalf("GetCapabilities = %+v, %v", capabilities, err)
	}
	runtimeStats, err := fixture.system.GetRuntimeStats(ctx, &sensorv1.GetRuntimeStatsRequest{})
	if err != nil || runtimeStats.GetGoroutines() == 0 || runtimeStats.GetRssBytes() == 0 || runtimeStats.GetActiveFlows() != 4 || runtimeStats.GetPacketQueueDepth() != 2 {
		t.Fatalf("GetRuntimeStats = %+v, %v", runtimeStats, err)
	}

	pcapSession, err := fixture.sessions.CreateSession(ctx, &sessionv1.CreateSensorSessionRequest{Mode: sensorv1.SensorMode_PASSIVE_PCAP, Name: "pcap"})
	if err != nil || pcapSession.GetState() != "READY" {
		t.Fatalf("PASSIVE_PCAP CreateSession = %+v, %v", pcapSession, err)
	}
	deepSession, err := fixture.sessions.CreateSession(ctx, &sessionv1.CreateSensorSessionRequest{Mode: sensorv1.SensorMode_DEEP_ASSESSMENT, Name: "deep", DeepOptions: &sessionv1.DeepAssessmentOptions{EnableVici: true, EnableXfrm: true}})
	if err != nil || deepSession.GetMode() != sensorv1.SensorMode_DEEP_ASSESSMENT {
		t.Fatalf("DEEP_ASSESSMENT CreateSession = %+v, %v", deepSession, err)
	}
	liveSession, err := fixture.sessions.CreateSession(ctx, &sessionv1.CreateSensorSessionRequest{Mode: sensorv1.SensorMode_PASSIVE_LIVE, Name: "live"})
	if err != nil {
		t.Fatal(err)
	}
	parsedSession, parseErr := uuid.Parse(liveSession.GetSensorSessionId())
	if parseErr != nil || parsedSession.Version() != uuid.Version(7) || liveSession.GetCreatedAt() == nil {
		t.Fatalf("session UUID/timestamp invalid: %+v %v", liveSession, parseErr)
	}

	listed, err := fixture.interfaces.ListInterfaces(ctx, &networkv1.ListInterfacesRequest{})
	if err != nil || len(listed.GetInterfaces()) == 0 {
		t.Fatalf("ListInterfaces = %+v, %v", listed, err)
	}
	interfaceName := listed.GetInterfaces()[0].GetName()
	metadata, err := fixture.interfaces.GetInterface(ctx, &networkv1.GetInterfaceRequest{InterfaceName: interfaceName})
	if err != nil || metadata.GetName() != interfaceName || metadata.GetIndex() == 0 {
		t.Fatalf("GetInterface = %+v, %v", metadata, err)
	}
	firstStats, err := fixture.interfaces.GetInterfaceStats(ctx, &networkv1.GetInterfaceStatsRequest{InterfaceName: interfaceName})
	if err != nil || firstStats.GetRxBytes() == 0 || firstStats.GetRxBytesPerSecond() != 0 {
		t.Fatalf("first GetInterfaceStats = %+v, %v", firstStats, err)
	}
	time.Sleep(15 * time.Millisecond)
	secondStats, err := fixture.interfaces.GetInterfaceStats(ctx, &networkv1.GetInterfaceStatsRequest{InterfaceName: interfaceName})
	if err != nil || secondStats.GetRxBytesPerSecond() <= 0 {
		t.Fatalf("second GetInterfaceStats = %+v, %v", secondStats, err)
	}

	started, err := fixture.captures.StartCapture(ctx, &capturev1.StartCaptureRequest{SensorSessionId: liveSession.GetSensorSessionId(), InterfaceName: interfaceName, FilterMode: capturev1.CaptureFilterMode_IPSEC_ONLY, MaxDurationSeconds: 30})
	if err != nil || started.GetState() != "STARTING" || started.GetStartedAt() == nil {
		t.Fatalf("StartCapture = %+v, %v", started, err)
	}
	if _, err = fixture.captures.StartCapture(ctx, &capturev1.StartCaptureRequest{SensorSessionId: liveSession.GetSensorSessionId(), InterfaceName: interfaceName, FilterMode: capturev1.CaptureFilterMode_ALL_TRAFFIC}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("duplicate StartCapture code = %s", status.Code(err))
	}
	parsedCapture, parseErr := uuid.Parse(started.GetCaptureId())
	if parseErr != nil || parsedCapture.Version() != uuid.Version(7) {
		t.Fatalf("capture ID is not UUIDv7: %v", parseErr)
	}
	currentSession, err := fixture.sessions.GetSession(ctx, &sessionv1.GetSensorSessionRequest{SensorSessionId: liveSession.GetSensorSessionId()})
	if err != nil || currentSession.GetState() != "RUNNING" || currentSession.GetCaptureId() != started.GetCaptureId() {
		t.Fatalf("GetSession = %+v, %v", currentSession, err)
	}
	captureStatus, err := fixture.captures.GetCaptureStatus(ctx, &capturev1.GetCaptureStatusRequest{CaptureId: started.GetCaptureId()})
	if err != nil || captureStatus.GetState() != "CAPTURING" || captureStatus.GetInterfaceName() != interfaceName {
		t.Fatalf("GetCaptureStatus = %+v, %v", captureStatus, err)
	}
	captureStats, err := fixture.captures.GetCaptureStats(ctx, &capturev1.GetCaptureStatsRequest{CaptureId: started.GetCaptureId()})
	if err != nil || captureStats.GetPacketsTotal() != 12 || captureStats.GetEspPackets() != 8 {
		t.Fatalf("GetCaptureStats = %+v, %v", captureStats, err)
	}
	if _, err = fixture.captures.UpdateCaptureFilter(ctx, &capturev1.UpdateCaptureFilterRequest{CaptureId: started.GetCaptureId(), FilterMode: capturev1.CaptureFilterMode_ALL_TRAFFIC}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("active UpdateCaptureFilter code = %s", status.Code(err))
	}

	streamContext, cancelStream := context.WithCancel(ctx)
	stream, err := fixture.captures.StreamCaptureStats(streamContext, &capturev1.StreamCaptureStatsRequest{CaptureId: started.GetCaptureId(), IntervalMs: 10})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = stream.Recv(); err != nil {
		t.Fatalf("first streamed stats: %v", err)
	}
	if _, err = stream.Recv(); err != nil {
		t.Fatalf("second streamed stats: %v", err)
	}
	cancelStream()
	if _, err = stream.Recv(); status.Code(err) != codes.Canceled {
		t.Fatalf("cancelled stream code = %s, error = %v", status.Code(err), err)
	}

	stopStream, err := fixture.captures.StreamCaptureStats(ctx, &capturev1.StreamCaptureStatsRequest{CaptureId: started.GetCaptureId(), IntervalMs: 10})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = stopStream.Recv(); err != nil {
		t.Fatalf("stop stream first stats: %v", err)
	}
	stopped, err := fixture.captures.StopCapture(ctx, &capturev1.StopCaptureRequest{CaptureId: started.GetCaptureId()})
	if err != nil || stopped.GetState() != "STOPPED" {
		t.Fatalf("StopCapture = %+v, %v", stopped, err)
	}
	if _, err = stopStream.Recv(); err != io.EOF {
		t.Fatalf("stream after capture stop = %v, want EOF", err)
	}
	if _, err = fixture.captures.StopCapture(ctx, &capturev1.StopCaptureRequest{CaptureId: started.GetCaptureId()}); err != nil {
		t.Fatalf("idempotent StopCapture: %v", err)
	}
	updated, err := fixture.captures.UpdateCaptureFilter(ctx, &capturev1.UpdateCaptureFilterRequest{CaptureId: started.GetCaptureId(), FilterMode: capturev1.CaptureFilterMode_CUSTOM_BPF, CustomBpf: "udp port 500"})
	if err != nil || !updated.GetUpdated() || updated.GetActiveFilter() != "udp port 500" {
		t.Fatalf("stopped UpdateCaptureFilter = %+v, %v", updated, err)
	}
	stoppedSession, err := fixture.sessions.StopSession(ctx, &sessionv1.StopSensorSessionRequest{SensorSessionId: liveSession.GetSensorSessionId()})
	if err != nil || stoppedSession.GetState() != "STOPPED" {
		t.Fatalf("StopSession = %+v, %v", stoppedSession, err)
	}
	reset, err := fixture.sessions.ResetSession(ctx, &sessionv1.ResetSensorSessionRequest{SensorSessionId: liveSession.GetSensorSessionId(), DeleteTemporaryFiles: true})
	if err != nil || !reset.GetReset_() || reset.GetState() != "EMPTY" {
		t.Fatalf("ResetSession = %+v, %v", reset, err)
	}
	if _, err = fixture.captures.StartCapture(ctx, &capturev1.StartCaptureRequest{SensorSessionId: liveSession.GetSensorSessionId(), InterfaceName: interfaceName, FilterMode: capturev1.CaptureFilterMode_ALL_TRAFFIC}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("StartCapture after reset code = %s", status.Code(err))
	}
	resetSession, err := fixture.sessions.CreateSession(ctx, &sessionv1.CreateSensorSessionRequest{Mode: sensorv1.SensorMode_PASSIVE_LIVE, Name: "reset-stream"})
	if err != nil {
		t.Fatal(err)
	}
	resetCapture, err := fixture.captures.StartCapture(ctx, &capturev1.StartCaptureRequest{SensorSessionId: resetSession.GetSensorSessionId(), InterfaceName: interfaceName, FilterMode: capturev1.CaptureFilterMode_ALL_TRAFFIC})
	if err != nil {
		t.Fatal(err)
	}
	resetStream, err := fixture.captures.StreamCaptureStats(ctx, &capturev1.StreamCaptureStatsRequest{CaptureId: resetCapture.GetCaptureId(), IntervalMs: 10})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = resetStream.Recv(); err != nil {
		t.Fatalf("reset stream first stats: %v", err)
	}
	if _, err = fixture.sessions.StopSession(ctx, &sessionv1.StopSensorSessionRequest{SensorSessionId: resetSession.GetSensorSessionId()}); err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.sessions.ResetSession(ctx, &sessionv1.ResetSensorSessionRequest{SensorSessionId: resetSession.GetSensorSessionId(), DeleteTemporaryFiles: true}); err != nil {
		t.Fatal(err)
	}
	if _, err = resetStream.Recv(); err != io.EOF {
		t.Fatalf("stream after session reset = %v, want EOF", err)
	}
}

func TestRegisteredGRPCServicesValidationAndErrorDetails(t *testing.T) {
	fixture := newGRPCFixture(t)
	defer fixture.cleanup()
	ctx := context.Background()
	interfaceName := hostInterface(t)
	if _, err := fixture.sessions.GetSession(ctx, &sessionv1.GetSensorSessionRequest{SensorSessionId: "missing"}); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown session code = %s", status.Code(err))
	}
	if _, err := fixture.sessions.ResetSession(ctx, &sessionv1.ResetSensorSessionRequest{SensorSessionId: "missing"}); status.Code(err) != codes.NotFound {
		t.Fatalf("reset missing code = %s", status.Code(err))
	}
	if _, err := fixture.sessions.CreateSession(ctx, &sessionv1.CreateSensorSessionRequest{Mode: sensorv1.SensorMode_DEEP_ASSESSMENT, Name: "invalid"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid deep options code = %s", status.Code(err))
	}
	if _, err := fixture.interfaces.GetInterface(ctx, &networkv1.GetInterfaceRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty interface code = %s", status.Code(err))
	}
	_, err := fixture.interfaces.GetInterface(ctx, &networkv1.GetInterfaceRequest{InterfaceName: "does-not-exist"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("missing interface code = %s", status.Code(err))
	}
	details := status.Convert(err).Details()
	if len(details) != 1 {
		t.Fatalf("missing interface detail count = %d", len(details))
	}
	detail, ok := details[0].(*commonv1.SensorErrorDetail)
	if !ok || detail.GetCode() != commonv1.SensorErrorCode_INTERFACE_NOT_FOUND {
		t.Fatalf("missing interface detail = %#v", details)
	}
	if _, err = fixture.captures.StartCapture(ctx, &capturev1.StartCaptureRequest{SensorSessionId: "missing", InterfaceName: interfaceName, FilterMode: capturev1.CaptureFilterMode_ALL_TRAFFIC}); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown capture session code = %s", status.Code(err))
	}
	if _, err = fixture.captures.GetCaptureStatus(ctx, &capturev1.GetCaptureStatusRequest{CaptureId: "missing"}); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown capture code = %s", status.Code(err))
	}
	stream, streamErr := fixture.captures.StreamCaptureStats(ctx, &capturev1.StreamCaptureStatsRequest{CaptureId: "missing", IntervalMs: 1})
	if streamErr != nil {
		t.Fatalf("stream construction unexpectedly failed: %v", streamErr)
	}
	if _, streamErr = stream.Recv(); status.Code(streamErr) != codes.InvalidArgument {
		t.Fatalf("invalid stream interval code = %s", status.Code(streamErr))
	}
	if _, err = fixture.captures.StartCapture(ctx, &capturev1.StartCaptureRequest{SensorSessionId: "missing", InterfaceName: interfaceName, FilterMode: capturev1.CaptureFilterMode_CUSTOM_BPF, CustomBpf: ""}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid custom BPF code = %s", status.Code(err))
	}
	if _, err = fixture.captures.StartCapture(ctx, &capturev1.StartCaptureRequest{SensorSessionId: "missing", InterfaceName: interfaceName, FilterMode: capturev1.CaptureFilterMode_CUSTOM_BPF, CustomBpf: "bad"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid BPF code = %s", status.Code(err))
	}
}
