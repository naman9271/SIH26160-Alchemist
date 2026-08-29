package sensor_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	sensorv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNewLogicalResourceIDsUseUUIDv7(t *testing.T) {
	newIDs := []func() (string, error){
		func() (string, error) { value, err := sensor.NewSensorSessionID(); return string(value), err },
		func() (string, error) { value, err := sensor.NewCaptureID(); return string(value), err },
		func() (string, error) { value, err := sensor.NewPCAPID(); return string(value), err },
		func() (string, error) { value, err := sensor.NewFlowID(); return string(value), err },
		func() (string, error) { value, err := sensor.NewProtocolEventID(); return string(value), err },
		func() (string, error) { value, err := sensor.NewIKESAID(); return string(value), err },
		func() (string, error) { value, err := sensor.NewChildSAID(); return string(value), err },
	}

	seen := make(map[string]struct{}, len(newIDs))
	for _, newID := range newIDs {
		value, err := newID()
		if err != nil {
			t.Fatalf("generate ID: %v", err)
		}
		parsed, err := uuid.Parse(value)
		if err != nil {
			t.Fatalf("ID is not a UUID: %q: %v", value, err)
		}
		if parsed.Version() != uuid.Version(7) {
			t.Fatalf("ID has version %d, want UUIDv7", parsed.Version())
		}
		if _, exists := seen[value]; exists {
			t.Fatalf("duplicate logical resource ID %q", value)
		}
		seen[value] = struct{}{}
	}
}

func TestTimestampUsesUTC(t *testing.T) {
	value := time.Date(2026, time.August, 27, 20, 2, 8, 511_000_000, time.FixedZone("IST", 5*60*60+30*60))
	timestamp := sensor.Timestamp(value)
	if err := timestamp.CheckValid(); err != nil {
		t.Fatalf("timestamp is invalid: %v", err)
	}
	if got, want := timestamp.AsTime().UTC(), value.UTC(); !got.Equal(want) {
		t.Fatalf("timestamp = %s, want %s", got, want)
	}
}

func TestErrorCategoryMapsToGRPCWithMachineReadableDetail(t *testing.T) {
	err := sensor.ToGRPC(sensor.NewError(sensor.Unavailable, sensor.VICIUnavailable, "VICI socket is unavailable"))
	if got := status.Code(err); got != codes.Unavailable {
		t.Fatalf("gRPC code = %s, want %s", got, codes.Unavailable)
	}
	details := status.Convert(err).Details()
	if len(details) != 1 {
		t.Fatalf("detail count = %d, want 1", len(details))
	}
	detail, ok := details[0].(*commonv1.SensorErrorDetail)
	if !ok {
		t.Fatalf("detail type = %T, want SensorErrorDetail", details[0])
	}
	if detail.GetCategory() != commonv1.ErrorCategory_UNAVAILABLE || detail.GetCode() != commonv1.SensorErrorCode_VICI_UNAVAILABLE {
		t.Fatalf("unexpected error detail: %+v", detail)
	}
}

func TestAllCanonicalErrorCategoriesMapToGRPC(t *testing.T) {
	testCases := []struct {
		category sensor.ErrorCategory
		grpcCode codes.Code
	}{
		{sensor.InvalidArgument, codes.InvalidArgument},
		{sensor.NotFound, codes.NotFound},
		{sensor.AlreadyExists, codes.AlreadyExists},
		{sensor.FailedPrecondition, codes.FailedPrecondition},
		{sensor.ResourceExhausted, codes.ResourceExhausted},
		{sensor.Unavailable, codes.Unavailable},
		{sensor.DeadlineExceeded, codes.DeadlineExceeded},
		{sensor.Internal, codes.Internal},
	}
	for _, testCase := range testCases {
		t.Run(string(testCase.category), func(t *testing.T) {
			err := sensor.ToGRPC(sensor.NewError(testCase.category, "", "test error"))
			if got := status.Code(err); got != testCase.grpcCode {
				t.Fatalf("gRPC code = %s, want %s", got, testCase.grpcCode)
			}
		})
	}
}

func TestSharedEnumNumbersAreStable(t *testing.T) {
	if sensorv1.SensorMode_DEEP_ASSESSMENT != 3 {
		t.Fatalf("DEEP_ASSESSMENT number = %d, want 3", sensorv1.SensorMode_DEEP_ASSESSMENT)
	}
	if commonv1.EvidenceStatus_INFERRED != 3 || commonv1.EvidenceStatus_VERIFIED_GATEWAY != 4 || commonv1.EvidenceStatus_UNKNOWN != 5 {
		t.Fatalf("EvidenceStatus numeric contract changed")
	}
}
