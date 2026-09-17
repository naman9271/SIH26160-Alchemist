package analysis_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	analysisv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/analysis"
	inputv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/input"
	reportv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/report"
	workspacev1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/workspace"
	viciv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/vici"
	xfrmv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/xfrm"
	coreanalysis "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/analysis"
	coreartifact "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/artifact"
	coreevents "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/events"
	corefusion "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/fusion"
	coreinput "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/input"
	coreprotocol "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/protocolread"
	corereport "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/report"
	coresecurity "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/security"
	coreworkspace "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/workspace"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/acquisition"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/vici"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/xfrm"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestDeterministicOfflinePipelineWithFixtureTelemetryAndPDF(t *testing.T) {
	ctx := context.Background()
	sensor := acquisition.New(nil, nil, nil)
	input := coreinput.New(sensor)
	workspace := coreworkspace.New(coreworkspace.Options{})
	if _, err := workspace.Create(ctx, "deterministic e2e", "e2e"); err != nil {
		t.Fatal(err)
	}
	runtime := fusion.NewRuntime(fusion.RuntimeOptions{})
	analysis := coreanalysis.New(input, runtime.Sessions, workspace)
	fusionService := corefusion.New(coreprotocol.WorkspaceRunResolver{Workspace: workspace}, runtime.Fusion, runtime.Provenance, runtime.Ingest)
	security := coresecurity.New(fusionService)
	now := timestamppb.New(time.Now().UTC())
	viciFixture, err := vici.NewFixture(&viciv1.GatewaySnapshot{SchemaVersion: vici.FixtureSchemaVersion, SnapshotTimestamp: now, IkeSas: []*viciv1.IkeSa{{Name: "ike", UniqueId: 1, IkeVersion: "IKEv2", State: "ESTABLISHED", EncryptionAlgorithm: "AES_GCM_16", IntegrityAlgorithm: "NONE", DhGroup: "CURVE_25519"}}, ChildSas: []*viciv1.ChildSa{{Name: "child", UniqueId: 2, Protocol: "ESP", Mode: "TUNNEL", SpiIn: 1, SpiOut: 2, EncryptionAlgorithm: "AES_GCM_16", PacketsIn: 1, BytesIn: 64}}})
	if err != nil {
		t.Fatal(err)
	}
	xfrmFixture, err := xfrm.NewFixture(&xfrmv1.KernelSnapshot{SchemaVersion: xfrm.FixtureSchemaVersion, SnapshotTimestamp: now, States: []*xfrmv1.XfrmState{{Source: "192.0.2.1", Destination: "198.51.100.1", Protocol: "ESP", Spi: 1, Mode: "TUNNEL", EncryptionAlgorithm: "aes-gcm", ReplayWindow: 32, Packets: 1, Bytes: 64}}})
	if err != nil {
		t.Fatal(err)
	}
	events := coreevents.New()
	analysis.SetPipeline(&coreanalysis.Pipeline{Sensor: sensor, Input: input, Ingest: runtime.Ingest, Fusion: runtime.Fusion, Security: security, Events: events, VICI: vici.New(viciFixture), XFRM: xfrm.New(xfrmFixture), VICIURI: "fixture"})

	pcap := classicPCAP(iKEFrame())
	uploadID, err := input.BeginUpload(ctx, &inputv1.BeginPcapUploadRequest{Filename: "fixture.pcap", SizeBytes: uint64(len(pcap))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = input.UploadChunk(ctx, &inputv1.UploadPcapChunkRequest{UploadId: uploadID, ChunkIndex: 0, Data: pcap}); err != nil {
		t.Fatal(err)
	}
	source, err := input.CompleteUpload(ctx, uploadID)
	if err != nil {
		t.Fatal(err)
	}
	record, err := analysis.Start(ctx, source.ID, workspacev1.AnalysisMode_OFFLINE_PCAP, "", &analysisv1.AnalysisOptions{EnableFusion: true, EnableSecurity: true, EnableMl: false})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		current, getErr := analysis.Get(ctx, record.ID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if current.State == analysisv1.AnalysisState_ANALYSIS_STATE_COMPLETED {
			break
		}
		if current.State == analysisv1.AnalysisState_ANALYSIS_STATE_FAILED {
			t.Fatalf("analysis failed: %s", current.Failure)
		}
		if time.Now().After(deadline) {
			t.Fatal("analysis did not complete")
		}
		time.Sleep(10 * time.Millisecond)
	}
	conclusions, _, err := fusionService.List(ctx, record.ID, nil)
	if err != nil || len(conclusions) == 0 {
		t.Fatalf("fused conclusions = %d, err=%v", len(conclusions), err)
	}
	reportDirectory := t.TempDir()
	reports := corereport.New(analysis, fusionService, coreartifact.New(func() string { return reportDirectory }), workspace, security, nil, nil, events)
	report, err := reports.Generate(ctx, &reportv1.GenerateReportRequest{AnalysisId: record.ID, Type: reportv1.ReportType_EXECUTIVE, Format: reportv1.ReportFormat_PDF})
	if err != nil {
		t.Fatal(err)
	}
	for {
		current, getErr := reports.Get(ctx, report.ID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if current.State == reportv1.ReportState_READY {
			artifact, artifactErr := reports.Artifact(ctx, current.ID)
			if artifactErr != nil {
				t.Fatal(artifactErr)
			}
			body, _, openErr := reports.ArtifactOpen(ctx, artifact.ID)
			if openErr != nil {
				t.Fatal(openErr)
			}
			defer body.Close()
			content := make([]byte, 8)
			_, _ = body.Read(content)
			if !bytes.HasPrefix(content, []byte("%PDF-")) {
				t.Fatalf("report is not a PDF: %q", content)
			}
			break
		}
		if current.State == reportv1.ReportState_FAILED {
			t.Fatalf("report failed: %s", current.Failure)
		}
		if time.Now().After(deadline) {
			t.Fatal("report did not complete")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func classicPCAP(frame []byte) []byte {
	var out bytes.Buffer
	header := make([]byte, 24)
	copy(header[:4], []byte{0xd4, 0xc3, 0xb2, 0xa1})
	binary.LittleEndian.PutUint32(header[20:24],1)
	out.Write(header)
	record := make([]byte, 16)
	binary.LittleEndian.PutUint32(record[:4], 1)
	binary.LittleEndian.PutUint32(record[8:12], uint32(len(frame)))
	binary.LittleEndian.PutUint32(record[12:16], uint32(len(frame)))
	out.Write(record)
	out.Write(frame)
	return out.Bytes()
}
func iKEFrame() []byte {
	ike := make([]byte, 28)
	binary.BigEndian.PutUint64(ike[:8], 1)
	ike[17], ike[18] = 0x20, 34
	binary.BigEndian.PutUint32(ike[24:28], 28)
	frame := make([]byte, 14+20+8+len(ike))
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	ip := frame[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+8+len(ike)))
	ip[9] = 17
	copy(ip[12:16], []byte{192, 0, 2, 1})
	copy(ip[16:20], []byte{198, 51, 100, 1})
	udp := ip[20:]
	binary.BigEndian.PutUint16(udp[:2], 500)
	binary.BigEndian.PutUint16(udp[2:4], 500)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(ike)))
	copy(udp[8:], ike)
	return frame
}
