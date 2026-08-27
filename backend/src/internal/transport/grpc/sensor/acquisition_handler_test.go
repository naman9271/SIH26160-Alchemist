package sensor_test

import (
	"context"
	"net"
	"sync"
	"testing"

	sensorv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1"
	capturev1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/capture"
	networkv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/network"
	sessionv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/session"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/acquisition"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/capture"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/network"
	transport "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/transport/grpc/sensor"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeHandle struct {
	done     chan error
	once     sync.Once
	counters capture.Counters
}

func newFakeHandle() *fakeHandle {
	return &fakeHandle{done: make(chan error), counters: capture.Counters{PacketsTotal: 12, BytesTotal: 600, IKEPackets: 2, ESPPackets: 8, NATTPackets: 2}}
}
func (h *fakeHandle) Stop(context.Context) error { h.once.Do(func() { close(h.done) }); return nil }
func (h *fakeHandle) Done() <-chan error         { return h.done }
func (h *fakeHandle) Counters() capture.Counters { return h.counters }
func (h *fakeHandle) TemporaryFiles() []string   { return nil }

type fakeEngine struct {
	mu      sync.Mutex
	handles []*fakeHandle
}

func (e *fakeEngine) Available() bool { return true }
func (e *fakeEngine) ValidateFilter(_ context.Context, filter string) error {
	if filter == "bad" {
		return shared.NewError(shared.InvalidArgument, "", "invalid BPF filter")
	}
	return nil
}
func (e *fakeEngine) Start(context.Context, capture.Config) (capture.Handle, error) {
	h := newFakeHandle()
	e.mu.Lock()
	e.handles = append(e.handles, h)
	e.mu.Unlock()
	return h, nil
}

type fakeCounters struct {
	mu sync.Mutex
	n  uint64
}

func (c *fakeCounters) ReadCounters(context.Context, string) (network.Counters, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n += 100
	return network.Counters{RXPackets: c.n, TXPackets: c.n / 2, RXBytes: c.n * 10, TXBytes: c.n * 5}, nil
}

type captureStream struct {
	grpc.ServerStream
	ctx    context.Context
	cancel context.CancelFunc
	sent   int
}

func (s *captureStream) Context() context.Context           { return s.ctx }
func (s *captureStream) Send(*capturev1.CaptureStats) error { s.sent++; s.cancel(); return nil }

func hostInterface(t *testing.T) string {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) == 0 {
		t.Fatalf("no host interface available: %v", err)
	}
	return interfaces[0].Name
}

func TestAcquisitionRPCsAndSharedLifecycle(t *testing.T) {
	engine, counters := &fakeEngine{}, &fakeCounters{}
	services := acquisition.New(engine, counters, nil)
	sessions := transport.NewSessionHandler(services.Sessions)
	interfaces := transport.NewNetworkInterfaceHandler(services.Interfaces)
	captures := transport.NewCaptureHandler(services.Captures)
	ctx, interfaceName := context.Background(), hostInterface(t)

	created, err := sessions.CreateSession(ctx, &sessionv1.CreateSensorSessionRequest{Mode: sensorv1.SensorMode_PASSIVE_LIVE, Name: "live"})
	if err != nil {
		t.Fatal(err)
	}
	if created.GetState() != "READY" || created.GetSensorSessionId() == "" {
		t.Fatalf("unexpected session: %+v", created)
	}
	if _, err = sessions.GetSession(ctx, &sessionv1.GetSensorSessionRequest{SensorSessionId: created.GetSensorSessionId()}); err != nil {
		t.Fatal(err)
	}
	if _, err = interfaces.ListInterfaces(ctx, &networkv1.ListInterfacesRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err = interfaces.GetInterface(ctx, &networkv1.GetInterfaceRequest{InterfaceName: interfaceName}); err != nil {
		t.Fatal(err)
	}
	if stats, err := interfaces.GetInterfaceStats(ctx, &networkv1.GetInterfaceStatsRequest{InterfaceName: interfaceName}); err != nil || stats.GetRxBytes() == 0 {
		t.Fatalf("stats=%+v err=%v", stats, err)
	}

	started, err := captures.StartCapture(ctx, &capturev1.StartCaptureRequest{SensorSessionId: created.GetSensorSessionId(), InterfaceName: interfaceName, FilterMode: capturev1.CaptureFilterMode_IPSEC_ONLY})
	if err != nil {
		t.Fatal(err)
	}
	if started.GetState() != capture.StateStarting {
		t.Fatalf("start state=%s", started.GetState())
	}
	if state, err := captures.GetCaptureStatus(ctx, &capturev1.GetCaptureStatusRequest{CaptureId: started.GetCaptureId()}); err != nil || state.GetState() != capture.StateCapturing {
		t.Fatalf("status=%+v err=%v", state, err)
	}
	if stats, err := captures.GetCaptureStats(ctx, &capturev1.GetCaptureStatsRequest{CaptureId: started.GetCaptureId()}); err != nil || stats.GetEspPackets() != 8 {
		t.Fatalf("stats=%+v err=%v", stats, err)
	}
	streamContext, cancel := context.WithCancel(ctx)
	stream := &captureStream{ctx: streamContext, cancel: cancel}
	if err := captures.StreamCaptureStats(&capturev1.StreamCaptureStatsRequest{CaptureId: started.GetCaptureId(), IntervalMs: 10}, stream); err == nil || stream.sent != 1 {
		t.Fatalf("stream err=%v sent=%d", err, stream.sent)
	}
	if _, err := captures.UpdateCaptureFilter(ctx, &capturev1.UpdateCaptureFilterRequest{CaptureId: started.GetCaptureId(), FilterMode: capturev1.CaptureFilterMode_ALL_TRAFFIC}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("active update code=%s", status.Code(err))
	}
	stopped, err := captures.StopCapture(ctx, &capturev1.StopCaptureRequest{CaptureId: started.GetCaptureId()})
	if err != nil || stopped.GetState() != capture.StateStopped {
		t.Fatalf("stop=%+v err=%v", stopped, err)
	}
	if _, err := captures.StopCapture(ctx, &capturev1.StopCaptureRequest{CaptureId: started.GetCaptureId()}); err != nil {
		t.Fatalf("idempotent stop: %v", err)
	}
	if update, err := captures.UpdateCaptureFilter(ctx, &capturev1.UpdateCaptureFilterRequest{CaptureId: started.GetCaptureId(), FilterMode: capturev1.CaptureFilterMode_ALL_TRAFFIC}); err != nil || !update.GetUpdated() {
		t.Fatalf("update=%+v err=%v", update, err)
	}
	if stoppedSession, err := sessions.StopSession(ctx, &sessionv1.StopSensorSessionRequest{SensorSessionId: created.GetSensorSessionId()}); err != nil || stoppedSession.GetState() != "STOPPED" {
		t.Fatalf("stop session=%+v err=%v", stoppedSession, err)
	}
	reset, err := sessions.ResetSession(ctx, &sessionv1.ResetSensorSessionRequest{SensorSessionId: created.GetSensorSessionId(), DeleteTemporaryFiles: true})
	if err != nil || !reset.GetReset_() || reset.GetState() != "EMPTY" {
		t.Fatalf("reset=%+v err=%v", reset, err)
	}
}

func TestAcquisitionValidationAndRegistration(t *testing.T) {
	services := acquisition.New(&fakeEngine{}, &fakeCounters{}, nil)
	sessions := transport.NewSessionHandler(services.Sessions)
	captures := transport.NewCaptureHandler(services.Captures)
	if _, err := sessions.CreateSession(context.Background(), &sessionv1.CreateSensorSessionRequest{Mode: sensorv1.SensorMode_DEEP_ASSESSMENT, Name: "deep"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("deep validation code=%s", status.Code(err))
	}
	if _, err := captures.StartCapture(context.Background(), &capturev1.StartCaptureRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("capture validation code=%s", status.Code(err))
	}
	if _, err := transport.NewNetworkInterfaceHandler(services.Interfaces).GetInterface(context.Background(), &networkv1.GetInterfaceRequest{InterfaceName: "does-not-exist"}); status.Code(err) != codes.NotFound {
		t.Fatalf("missing interface code=%s", status.Code(err))
	}
	server := grpc.NewServer()
	transport.RegisterAcquisitionServices(server, sessions, transport.NewNetworkInterfaceHandler(services.Interfaces), captures)
	if len(server.GetServiceInfo()) != 3 {
		t.Fatalf("registered services=%d", len(server.GetServiceInfo()))
	}
}

func TestConcurrentCaptureStartsAllowOnlyOneActiveCapture(t *testing.T) {
	engine := &fakeEngine{}
	services := acquisition.New(engine, &fakeCounters{}, nil)
	handler := transport.NewSessionHandler(services.Sessions)
	captures := transport.NewCaptureHandler(services.Captures)
	ctx, interfaceName := context.Background(), hostInterface(t)
	first, err := handler.CreateSession(ctx, &sessionv1.CreateSensorSessionRequest{Mode: sensorv1.SensorMode_PASSIVE_LIVE, Name: "first"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := handler.CreateSession(ctx, &sessionv1.CreateSensorSessionRequest{Mode: sensorv1.SensorMode_PASSIVE_LIVE, Name: "second"})
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{first.GetSensorSessionId(), second.GetSensorSessionId()}
	responses := make(chan *capturev1.StartCaptureResponse, 2)
	errors := make(chan error, 2)
	var group sync.WaitGroup
	for _, id := range ids {
		group.Add(1)
		go func(sessionID string) {
			defer group.Done()
			response, startErr := captures.StartCapture(ctx, &capturev1.StartCaptureRequest{SensorSessionId: sessionID, InterfaceName: interfaceName, FilterMode: capturev1.CaptureFilterMode_ALL_TRAFFIC})
			responses <- response
			errors <- startErr
		}(id)
	}
	group.Wait()
	close(responses)
	close(errors)
	successes := 0
	for response := range responses {
		if response != nil {
			successes++
			_, _ = captures.StopCapture(ctx, &capturev1.StopCaptureRequest{CaptureId: response.GetCaptureId()})
		}
	}
	if successes != 1 {
		t.Fatalf("successful concurrent starts = %d, want 1", successes)
	}
	for startErr := range errors {
		if startErr != nil && status.Code(startErr) != codes.FailedPrecondition {
			t.Fatalf("unexpected concurrent start error: %v", startErr)
		}
	}
}
