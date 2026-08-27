package core_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	coresystemv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/system"
	workspacev1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/workspace"
	sensorv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1"
	coresystem "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/system"
	coreworkspace "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/workspace"
	transport "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/transport/grpc/core"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type dependencies struct {
	value        coresystem.Dependencies
	capabilities coresystem.Capabilities
	err          error
}

func (d dependencies) Dependencies(context.Context) (coresystem.Dependencies, error) {
	return d.value, d.err
}
func (d dependencies) Capabilities(context.Context) (coresystem.Capabilities, error) {
	return d.capabilities, d.err
}

type metrics struct{}

func (metrics) RuntimeInstrumentation(context.Context) (coresystem.RuntimeInstrumentation, error) {
	return coresystem.RuntimeInstrumentation{EventSubscribers: 2, SensorQueueDepth: 3, MLRoundTripMS: 4.5, FusionRecomputeMS: 1.2}, nil
}

type coordinator struct {
	mu         sync.Mutex
	calls      int
	fail       bool
	lastDelete bool
}

func (c *coordinator) Name() string { return "test-coordinator" }
func (c *coordinator) Cleanup(_ context.Context, _ string, force, deleteTemporaryFiles bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	c.lastDelete = deleteTemporaryFiles
	if c.fail && !force {
		return context.DeadlineExceeded
	}
	return nil
}
func (c *coordinator) Calls() int { c.mu.Lock(); defer c.mu.Unlock(); return c.calls }
func (c *coordinator) LastDeleteTemporaryFiles() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastDelete
}

type fixture struct {
	system    coresystemv1.CoreSystemServiceClient
	workspace workspacev1.WorkspaceServiceClient
	state     *coreworkspace.Service
	cleanup   func()
}

func newFixture(t *testing.T, dependency coresystem.Dependencies, coordinator *coordinator) fixture {
	t.Helper()
	state := coreworkspace.New(coreworkspace.Options{Coordinators: []coreworkspace.Coordinator{coordinator}, CleanupTimeout: time.Second})
	server := grpc.NewServer()
	system := coresystem.New(coresystem.Options{Version: coresystem.Version{CoreVersion: "1.0.0", BuildCommit: "commit"}, Dependencies: dependencies{value: dependency, capabilities: coresystem.Capabilities{PassiveLive: true, PassivePCAP: true, SecurityAssessment: true, RiskScoring: true, ThreatMatrix: true, MLClassification: dependency.MLWorker == coresystemv1.DependencyState_READY, SHAP: false, ExecutiveReport: true, TechnicalReport: true}}, Metrics: metrics{}, Workspace: state})
	transport.RegisterCoreServices(server, transport.NewSystemHandler(system), transport.NewWorkspaceHandler(state))
	listener := bufconn.Listen(1024 * 1024)
	go func() { _ = server.Serve(listener) }()
	dialContext, cancel := context.WithTimeout(context.Background(), time.Second)
	connection, err := grpc.DialContext(dialContext, "bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	return fixture{system: coresystemv1.NewCoreSystemServiceClient(connection), workspace: workspacev1.NewWorkspaceServiceClient(connection), state: state, cleanup: func() { _ = connection.Close(); server.Stop(); _ = listener.Close() }}
}
func readyDependencies() coresystem.Dependencies {
	return coresystem.Dependencies{InMemoryStore: coresystemv1.DependencyState_READY, TempStorage: coresystemv1.DependencyState_READY, Sensor: coresystemv1.DependencyState_READY, MLWorker: coresystemv1.DependencyState_UNAVAILABLE, FusionEngine: coresystemv1.DependencyState_READY}
}
func withKey(ctx context.Context, key string) context.Context {
	return metadata.NewOutgoingContext(ctx, metadata.Pairs(coreworkspace.IdempotencyMetadataKey, key))
}

func TestCoreSystemServiceOverGRPC(t *testing.T) {
	f := newFixture(t, readyDependencies(), &coordinator{})
	defer f.cleanup()
	ctx := context.Background()
	health, err := f.system.Health(ctx, &coresystemv1.HealthRequest{})
	if err != nil || health.GetStatus() != coresystemv1.HealthStatus_HEALTHY || health.GetTime() == nil || health.GetTime().CheckValid() != nil {
		t.Fatalf("Health=%+v err=%v", health, err)
	}
	readiness, err := f.system.Readiness(ctx, &coresystemv1.ReadinessRequest{})
	if err != nil || !readiness.GetReady() || readiness.GetMlWorker() != coresystemv1.DependencyState_UNAVAILABLE {
		t.Fatalf("Readiness=%+v err=%v", readiness, err)
	}
	version, err := f.system.GetVersion(ctx, &coresystemv1.GetVersionRequest{})
	if err != nil || version.GetCoreVersion() != "1.0.0" || version.GetApiVersion() != "core.v1" || version.GetSensorContract() != "sensor.v1" {
		t.Fatalf("Version=%+v err=%v", version, err)
	}
	capabilities, err := f.system.GetCapabilities(ctx, &coresystemv1.GetCapabilitiesRequest{})
	if err != nil || !capabilities.GetPassiveLive() || capabilities.GetShap() || capabilities.GetMlClassification() {
		t.Fatalf("Capabilities=%+v err=%v", capabilities, err)
	}
	stats, err := f.system.GetRuntimeStats(ctx, &coresystemv1.GetRuntimeStatsRequest{})
	if err != nil || stats.GetGoroutines() == 0 || stats.GetRssBytes() == 0 || stats.GetEventSubscribers() != 2 || stats.GetSensorQueueDepth() != 3 {
		t.Fatalf("RuntimeStats=%+v err=%v", stats, err)
	}
}

func TestCoreSystemReadinessRequiresMandatoryDependencies(t *testing.T) {
	dependency := readyDependencies()
	dependency.Sensor = coresystemv1.DependencyState_UNAVAILABLE
	f := newFixture(t, dependency, &coordinator{})
	defer f.cleanup()
	response, err := f.system.Readiness(context.Background(), &coresystemv1.ReadinessRequest{})
	if err != nil || response.GetReady() {
		t.Fatalf("Readiness=%+v err=%v", response, err)
	}
}

func TestWorkspaceServiceOverGRPC(t *testing.T) {
	cleaner := &coordinator{}
	f := newFixture(t, readyDependencies(), cleaner)
	defer f.cleanup()
	ctx := context.Background()
	created, err := f.workspace.Create(withKey(ctx, "create-1"), &workspacev1.CreateWorkspaceRequest{DisplayName: "NTRO Assessment"})
	if err != nil || created.GetState() != workspacev1.WorkspaceState_WORKSPACE_STATE_EMPTY || created.GetCreatedAt() == nil {
		t.Fatalf("Create=%+v err=%v", created, err)
	}
	id, err := uuid.Parse(created.GetWorkspaceId())
	if err != nil || id.Version() != uuid.Version(7) {
		t.Fatalf("workspace ID=%s err=%v", created.GetWorkspaceId(), err)
	}
	replayed, err := f.workspace.Create(withKey(ctx, "create-1"), &workspacev1.CreateWorkspaceRequest{DisplayName: "ignored"})
	if err != nil || replayed.GetWorkspaceId() != created.GetWorkspaceId() {
		t.Fatalf("idempotent Create=%+v err=%v", replayed, err)
	}
	if cleaner.Calls() != 0 {
		t.Fatalf("replay cleanup calls=%d", cleaner.Calls())
	}
	got, err := f.workspace.Get(ctx, &workspacev1.GetWorkspaceRequest{})
	if err != nil || got.GetWorkspaceId() != created.GetWorkspaceId() {
		t.Fatalf("Get=%+v err=%v", got, err)
	}
	ownedID, generation, err := f.state.CurrentOwnership(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !f.state.UpdateIfCurrent(ownedID, generation, func(record *coreworkspace.Record) {
		record.State = workspacev1.WorkspaceState_WORKSPACE_STATE_COMPLETED
		record.Mode = sensorv1.SensorMode_PASSIVE_PCAP
		record.SourceID = "source"
		record.AnalysisID = "analysis"
		record.MLJobID = "ml"
		record.FusionRunID = "fusion"
		record.ReportID = "report"
	}) {
		t.Fatal("current workspace update rejected")
	}
	state, err := f.workspace.GetState(ctx, &workspacev1.GetWorkspaceStateRequest{})
	if err != nil || state.GetState() != workspacev1.WorkspaceState_WORKSPACE_STATE_COMPLETED || !state.GetHasSource() || !state.GetHasAnalysis() || !state.GetHasMlResult() || !state.GetHasFusedResult() || !state.GetHasReport() {
		t.Fatalf("GetState=%+v err=%v", state, err)
	}
	replacement, err := f.workspace.Create(withKey(ctx, "create-2"), &workspacev1.CreateWorkspaceRequest{DisplayName: "replacement"})
	if err != nil || replacement.GetWorkspaceId() == created.GetWorkspaceId() || cleaner.Calls() != 1 {
		t.Fatalf("replacement=%+v cleanup=%d err=%v", replacement, cleaner.Calls(), err)
	}
	if f.state.UpdateIfCurrent(ownedID, generation, func(*coreworkspace.Record) {}) {
		t.Fatal("stale callback mutated replacement workspace")
	}
	reset, err := f.workspace.Reset(withKey(ctx, "reset-1"), &workspacev1.ResetWorkspaceRequest{DeleteTemporaryFiles: true})
	if err != nil || reset.GetState() != workspacev1.WorkspaceState_WORKSPACE_STATE_EMPTY || reset.GetWorkspaceId() == replacement.GetWorkspaceId() {
		t.Fatalf("Reset=%+v err=%v", reset, err)
	}
	if !cleaner.LastDeleteTemporaryFiles() {
		t.Fatal("reset did not propagate temporary-file deletion to coordinators")
	}
	replayedReset, err := f.workspace.Reset(withKey(ctx, "reset-1"), &workspacev1.ResetWorkspaceRequest{})
	if err != nil || replayedReset.GetWorkspaceId() != reset.GetWorkspaceId() {
		t.Fatalf("idempotent Reset=%+v err=%v", replayedReset, err)
	}
}

func TestWorkspaceValidationAndResetFailure(t *testing.T) {
	cleaner := &coordinator{}
	f := newFixture(t, readyDependencies(), cleaner)
	defer f.cleanup()
	ctx := context.Background()
	if _, err := f.workspace.Create(ctx, &workspacev1.CreateWorkspaceRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty name code=%s", status.Code(err))
	}
	created, err := f.workspace.Create(ctx, &workspacev1.CreateWorkspaceRequest{DisplayName: "workspace"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.workspace.Get(ctx, &workspacev1.GetWorkspaceRequest{WorkspaceId: "missing"}); status.Code(err) != codes.NotFound {
		t.Fatalf("missing workspace code=%s", status.Code(err))
	}
	cleaner.fail = true
	if _, err = f.workspace.Reset(ctx, &workspacev1.ResetWorkspaceRequest{Force: false}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("safe reset code=%s", status.Code(err))
	}
	current, err := f.workspace.Get(ctx, &workspacev1.GetWorkspaceRequest{})
	if err != nil || current.GetWorkspaceId() != created.GetWorkspaceId() {
		t.Fatalf("failed reset destroyed current workspace: %+v %v", current, err)
	}
	forced, err := f.workspace.Reset(ctx, &workspacev1.ResetWorkspaceRequest{Force: true})
	if err != nil || forced.GetState() != workspacev1.WorkspaceState_WORKSPACE_STATE_EMPTY {
		t.Fatalf("forced reset=%+v err=%v", forced, err)
	}
}

func TestWorkspaceConcurrentMutationsRemainConsistent(t *testing.T) {
	f := newFixture(t, readyDependencies(), &coordinator{})
	defer f.cleanup()
	ctx := context.Background()
	if _, err := f.workspace.Create(ctx, &workspacev1.CreateWorkspaceRequest{DisplayName: "initial"}); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	errors := make(chan error, 16)
	for index := 0; index < 8; index++ {
		group.Add(2)
		go func(index int) {
			defer group.Done()
			_, err := f.workspace.Create(withKey(ctx, "concurrent-create-"+string(rune('a'+index))), &workspacev1.CreateWorkspaceRequest{DisplayName: "workspace"})
			errors <- err
		}(index)
		go func(index int) {
			defer group.Done()
			_, err := f.workspace.Reset(withKey(ctx, "concurrent-reset-"+string(rune('a'+index))), &workspacev1.ResetWorkspaceRequest{Force: true})
			errors <- err
		}(index)
	}
	group.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent mutation: %v", err)
		}
	}
	current, err := f.workspace.Get(ctx, &workspacev1.GetWorkspaceRequest{})
	if err != nil || current.GetWorkspaceId() == "" || current.GetState() != workspacev1.WorkspaceState_WORKSPACE_STATE_EMPTY {
		t.Fatalf("current workspace after concurrent mutations = %+v, %v", current, err)
	}
}
