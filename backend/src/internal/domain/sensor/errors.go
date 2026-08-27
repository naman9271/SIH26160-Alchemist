package sensor

import (
	"context"
	"errors"
	"fmt"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrorCategory is transport neutral so the Sensor remains usable by internal
// Go callers as well as a future gRPC boundary.
type ErrorCategory string

const (
	InvalidArgument    ErrorCategory = "INVALID_ARGUMENT"
	NotFound           ErrorCategory = "NOT_FOUND"
	AlreadyExists      ErrorCategory = "ALREADY_EXISTS"
	FailedPrecondition ErrorCategory = "FAILED_PRECONDITION"
	ResourceExhausted  ErrorCategory = "RESOURCE_EXHAUSTED"
	Unavailable        ErrorCategory = "UNAVAILABLE"
	DeadlineExceeded   ErrorCategory = "DEADLINE_EXCEEDED"
	Internal           ErrorCategory = "INTERNAL"
)

// ErrorCode is a stable machine-readable Sensor failure reason.
type ErrorCode string

const (
	CaptureAlreadyRunning ErrorCode = "CAPTURE_ALREADY_RUNNING"
	InterfaceNotFound     ErrorCode = "INTERFACE_NOT_FOUND"
	InvalidPCAP           ErrorCode = "INVALID_PCAP"
	VICIUnavailable       ErrorCode = "VICI_UNAVAILABLE"
	VICIPluginDisabled    ErrorCode = "VICI_PLUGIN_DISABLED"
	XFRMUnavailable       ErrorCode = "XFRM_UNAVAILABLE"
	SessionNotActive      ErrorCode = "SESSION_NOT_ACTIVE"
)

// Error retains semantic details without exposing implementation causes to a
// transport client.
type Error struct {
	Category ErrorCategory
	Code     ErrorCode
	Message  string
	Cause    error
}

func (err *Error) Error() string {
	if err.Cause == nil {
		return fmt.Sprintf("%s (%s): %s", err.Category, err.Code, err.Message)
	}
	return fmt.Sprintf("%s (%s): %s: %v", err.Category, err.Code, err.Message, err.Cause)
}

func (err *Error) Unwrap() error { return err.Cause }

func NewError(category ErrorCategory, code ErrorCode, message string) *Error {
	return &Error{Category: category, Code: code, Message: message}
}

// ToGRPC maps canonical Sensor errors at a transport boundary. It is kept out
// of business logic so an internal caller can handle Error directly.
func ToGRPC(err error) error {
	if err == nil {
		return nil
	}
	if status.Code(err) != codes.Unknown {
		return err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return status.Error(codes.DeadlineExceeded, context.DeadlineExceeded.Error())
	}
	if errors.Is(err, context.Canceled) {
		return status.Error(codes.Canceled, context.Canceled.Error())
	}

	var sensorErr *Error
	if errors.As(err, &sensorErr) {
		grpcStatus := status.New(categoryToGRPC(sensorErr.Category), sensorErr.Message)
		withDetail, detailErr := grpcStatus.WithDetails(&commonv1.SensorErrorDetail{
			Category: categoryToProto(sensorErr.Category),
			Code:     codeToProto(sensorErr.Code),
			Message:  sensorErr.Message,
		})
		if detailErr == nil {
			return withDetail.Err()
		}
		return grpcStatus.Err()
	}
	return status.Error(codes.Internal, "internal sensor error")
}

func categoryToProto(category ErrorCategory) commonv1.ErrorCategory {
	switch category {
	case InvalidArgument:
		return commonv1.ErrorCategory_INVALID_ARGUMENT
	case NotFound:
		return commonv1.ErrorCategory_NOT_FOUND
	case AlreadyExists:
		return commonv1.ErrorCategory_ALREADY_EXISTS
	case FailedPrecondition:
		return commonv1.ErrorCategory_FAILED_PRECONDITION
	case ResourceExhausted:
		return commonv1.ErrorCategory_RESOURCE_EXHAUSTED
	case Unavailable:
		return commonv1.ErrorCategory_UNAVAILABLE
	case DeadlineExceeded:
		return commonv1.ErrorCategory_DEADLINE_EXCEEDED
	default:
		return commonv1.ErrorCategory_INTERNAL
	}
}

func codeToProto(code ErrorCode) commonv1.SensorErrorCode {
	switch code {
	case CaptureAlreadyRunning:
		return commonv1.SensorErrorCode_CAPTURE_ALREADY_RUNNING
	case InterfaceNotFound:
		return commonv1.SensorErrorCode_INTERFACE_NOT_FOUND
	case InvalidPCAP:
		return commonv1.SensorErrorCode_INVALID_PCAP
	case VICIUnavailable:
		return commonv1.SensorErrorCode_VICI_UNAVAILABLE
	case VICIPluginDisabled:
		return commonv1.SensorErrorCode_VICI_PLUGIN_DISABLED
	case XFRMUnavailable:
		return commonv1.SensorErrorCode_XFRM_UNAVAILABLE
	case SessionNotActive:
		return commonv1.SensorErrorCode_SESSION_NOT_ACTIVE
	default:
		return commonv1.SensorErrorCode_SENSOR_ERROR_CODE_UNSPECIFIED
	}
}

func categoryToGRPC(category ErrorCategory) codes.Code {
	switch category {
	case InvalidArgument:
		return codes.InvalidArgument
	case NotFound:
		return codes.NotFound
	case AlreadyExists:
		return codes.AlreadyExists
	case FailedPrecondition:
		return codes.FailedPrecondition
	case ResourceExhausted:
		return codes.ResourceExhausted
	case Unavailable:
		return codes.Unavailable
	case DeadlineExceeded:
		return codes.DeadlineExceeded
	default:
		return codes.Internal
	}
}
