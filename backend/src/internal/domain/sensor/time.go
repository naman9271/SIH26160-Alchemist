package sensor

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// Timestamp converts a time to a valid protobuf timestamp in UTC.
func Timestamp(value time.Time) *timestamppb.Timestamp {
	return timestamppb.New(value.UTC())
}
