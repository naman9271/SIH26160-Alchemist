package input

import (
	"context"
	"errors"
	"os"
	"testing"

	inputv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/input"
)

func TestIncompleteUploadCleansTemporaryFile(t *testing.T) {
	service := &Service{sources: map[string]*Source{}, uploads: map[string]*upload{}}
	id, err := service.BeginUpload(context.Background(), &inputv1.BeginPcapUploadRequest{Filename: "capture.pcap", SizeBytes: 2})
	if err != nil {
		t.Fatal(err)
	}
	service.mu.RLock()
	path := service.uploads[id].path
	service.mu.RUnlock()
	if _, err = service.CompleteUpload(context.Background(), id); err == nil {
		t.Fatal("incomplete upload completed")
	}
	if _, err = os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary upload was not removed: %v", err)
	}
}

func TestCancelledChunkCleansTemporaryFile(t *testing.T) {
	service := &Service{sources: map[string]*Source{}, uploads: map[string]*upload{}}
	id, err := service.BeginUpload(context.Background(), &inputv1.BeginPcapUploadRequest{Filename: "capture.pcap", SizeBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	service.mu.RLock()
	path := service.uploads[id].path
	service.mu.RUnlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = service.UploadChunk(ctx, &inputv1.UploadPcapChunkRequest{UploadId: id, ChunkIndex: 0, Data: []byte{1}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("UploadChunk error = %v", err)
	}
	if _, err = os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled temporary upload was not removed: %v", err)
	}
}
