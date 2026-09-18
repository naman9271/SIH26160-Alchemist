package flow

import (
	"encoding/json"
	"math"
	"os"
	"testing"
	"time"
)

func TestGoFeaturesMatchSharedGoldenCapture(t *testing.T) {
	var golden struct {
		Packets []struct {
			Time    float64 `json:"time_seconds"`
			Size    int64   `json:"size_bytes"`
			Forward bool    `json:"forward"`
		} `json:"packets"`
		Expected map[string]float64 `json:"expected"`
	}
	raw, err := os.ReadFile("../../featurespec/golden_capture.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	base := time.Unix(0, 0).UTC()
	w := &window{burstGap: defaultBurstGap, idleGap: defaultIdleGap}
	for _, item := range golden.Packets {
		size := item.Size
		if !item.Forward {
			size = -size
		}
		w.packets = append(w.packets, packet{size: size, at: base.Add(time.Duration(item.Time * float64(time.Second))), forward: item.Forward})
	}
	values := featureValues(w)
	for index, name := range FeatureNames {
		if math.Abs(values[index]-golden.Expected[name]) > 1e-9 {
			t.Fatalf("%s = %.15f, want %.15f", name, values[index], golden.Expected[name])
		}
	}
}

func TestWindowBoundariesStayAnchoredToFirstObservedPacket(t *testing.T) {
	anchor := time.Unix(100, 0).UTC()
	if got := windowBucket(anchor.Add(19*time.Second), anchor, 10*time.Second); got != 1 {
		t.Fatalf("bucket = %d, want 1", got)
	}
	if got := windowBucket(anchor.Add(20*time.Second), anchor, 10*time.Second); got != 2 {
		t.Fatalf("boundary bucket = %d, want 2", got)
	}
}
