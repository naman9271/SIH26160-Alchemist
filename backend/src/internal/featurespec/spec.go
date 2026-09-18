package featurespec

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed flow_v2.json
var raw []byte

type Spec struct {
	SchemaVersion       string   `json:"schema_version"`
	WindowSeconds       float64  `json:"window_seconds"`
	BurstGapSeconds     float64  `json:"burst_gap_seconds"`
	IdleGapSeconds      float64  `json:"idle_gap_seconds"`
	TimeUnit            string   `json:"time_unit"`
	SizeUnit            string   `json:"size_unit"`
	PercentileMethod    string   `json:"percentile_method"`
	DirectionConvention string   `json:"direction_convention"`
	Features            []string `json:"features"`
	ExcludedInputs      []string `json:"excluded_inputs"`
}

func Load() (Spec, error) {
	var spec Spec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return Spec{}, fmt.Errorf("decode flow feature specification: %w", err)
	}
	if spec.SchemaVersion == "" || len(spec.Features) == 0 || spec.WindowSeconds <= 0 || spec.BurstGapSeconds <= 0 || spec.IdleGapSeconds <= spec.BurstGapSeconds {
		return Spec{}, fmt.Errorf("flow feature specification is incomplete")
	}
	return spec, nil
}

func MustLoad() Spec {
	spec, err := Load()
	if err != nil {
		panic(err)
	}
	return spec
}
