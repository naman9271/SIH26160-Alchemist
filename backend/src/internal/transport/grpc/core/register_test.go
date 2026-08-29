package core

import (
	"strings"
	"testing"

	coresystem "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/system"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/workspace"
	"google.golang.org/grpc"
)

func TestCoreRegistrationDoesNotExposeSensorServices(t *testing.T) {
	server := grpc.NewServer()
	RegisterCoreServices(
		server,
		NewSystemHandler(coresystem.New(coresystem.Options{})),
		NewWorkspaceHandler(workspace.New(workspace.Options{})),
	)
	services := server.GetServiceInfo()
	if len(services) != 2 {
		t.Fatalf("registered services=%v", services)
	}
	for name := range services {
		if strings.HasPrefix(name, "sensor.") {
			t.Fatalf("internal Sensor service was exposed: %s", name)
		}
	}
}
