// Package input owns Core input-source state while delegating all packet work to Sensor.
package input

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	inputv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/input"
	sensorv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1"
	capturev1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/capture"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/acquisition"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/capture"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/session"
)

const ChunkSize uint64 = 1 << 20

type Source struct {
	ID                                                   string
	Mode                                                 inputv1.InputMode
	State                                                inputv1.InputState
	SessionID, CaptureID, PCAPID, Filename, SHA256, Path string
	Size                                                 uint64
	CreatedAt, UpdatedAt                                 time.Time
	Counters                                             capture.Counters
}
type upload struct {
	id, filename, sha, path string
	size, received, next    uint64
	file                    *os.File
}
type Service struct {
	mu      sync.RWMutex
	sensor  acquisition.Services
	sources map[string]*Source
	uploads map[string]*upload
}

func New(sensor acquisition.Services) *Service {
	return &Service{sensor: sensor, sources: map[string]*Source{}, uploads: map[string]*upload{}}
}
func (s *Service) ListInterfaces(ctx context.Context) ([]inputv1.NetworkInterface, error) {
	if s.sensor.Interfaces == nil {
		return nil, shared.NewError(shared.Internal, "", "network service is not configured")
	}
	items, e := s.sensor.Interfaces.List(ctx)
	if e != nil {
		return nil, e
	}
	out := make([]inputv1.NetworkInterface, 0, len(items))
	for _, v := range items {
		out = append(out, inputv1.NetworkInterface{Name: v.Name, Index: v.Index, MacAddress: v.MACAddress, Addresses: v.Addresses, Up: v.Up, Loopback: v.Loopback, CaptureSupported: v.CaptureSupported})
	}
	return out, nil
}
func mode(v inputv1.InputMode) (sensorv1.SensorMode, error) {
	switch v {
	case inputv1.InputMode_PASSIVE_LIVE:
		return sensorv1.SensorMode_PASSIVE_LIVE, nil
	case inputv1.InputMode_DEEP_ASSESSMENT:
		return sensorv1.SensorMode_DEEP_ASSESSMENT, nil
	default:
		return 0, shared.NewError(shared.InvalidArgument, "", "mode must be PASSIVE_LIVE or DEEP_ASSESSMENT")
	}
}
func filter(v inputv1.CaptureFilterMode) capturev1.CaptureFilterMode {
	return capturev1.CaptureFilterMode(v)
}
func (s *Service) StartLive(ctx context.Context, r *inputv1.StartLiveInputRequest) (Source, error) {
	if r == nil {
		return Source{}, shared.NewError(shared.InvalidArgument, "", "request is required")
	}
	m, e := mode(r.GetMode())
	if e != nil {
		return Source{}, e
	}
	if s.sensor.Sessions == nil || s.sensor.Captures == nil {
		return Source{}, shared.NewError(shared.Internal, "", "sensor acquisition is not configured")
	}
	var deep *session.DeepOptions
	if m == sensorv1.SensorMode_DEEP_ASSESSMENT {
		deep = &session.DeepOptions{EnableVICI: r.GetEnableVici(), EnableXFRM: r.GetEnableXfrm()}
	}
	ses, e := s.sensor.Sessions.Create(ctx, m, "core-input", deep)
	if e != nil {
		return Source{}, e
	}
	rec, e := s.sensor.Captures.Start(ctx, ses.ID, r.GetInterfaceName(), filter(r.GetFilterMode()), r.GetCustomBpf(), r.GetPromiscuousMode(), r.GetSavePcap(), r.GetMaxDurationSeconds(), r.GetMaxCaptureBytes())
	if e != nil {
		return Source{}, e
	}
	id, e := shared.NewPCAPID()
	if e != nil {
		return Source{}, e
	}
	now := time.Now().UTC()
	src := Source{ID: string(id), Mode: r.GetMode(), State: inputv1.InputState_CAPTURING, SessionID: ses.ID, CaptureID: rec.CaptureID(), CreatedAt: now, UpdatedAt: now}
	s.mu.Lock()
	s.sources[src.ID] = &src
	s.mu.Unlock()
	return src, nil
}
func (s *Service) StopLive(ctx context.Context, id string) (Source, error) {
	src, e := s.Get(ctx, id)
	if e != nil {
		return Source{}, e
	}
	if src.CaptureID == "" {
		return Source{}, shared.NewError(shared.FailedPrecondition, "", "source is not a live capture")
	}
	if _, e = s.sensor.Sessions.Stop(ctx, src.SessionID); e != nil {
		return Source{}, e
	}
	s.mu.Lock()
	stored := s.sources[id]
	stored.State = inputv1.InputState_STOPPED
	stored.UpdatedAt = time.Now().UTC()
	out := *stored
	s.mu.Unlock()
	return out, nil
}
func (s *Service) LiveStatus(ctx context.Context, id string) (Source, uint64, uint64, uint64, error) {
	src, e := s.Get(ctx, id)
	if e != nil {
		return Source{}, 0, 0, 0, e
	}
	if src.CaptureID == "" {
		return Source{}, 0, 0, 0, shared.NewError(shared.FailedPrecondition, "", "source is not live")
	}
	c, f, v, d, e := s.sensor.Captures.Stats(ctx, src.CaptureID)
	if e != nil {
		return Source{}, 0, 0, 0, e
	}
	src.Counters = c
	return src, f, v, uint64(d.Seconds()), nil
}
func (s *Service) BeginUpload(ctx context.Context, r *inputv1.BeginPcapUploadRequest) (string, error) {
	if r == nil || strings.TrimSpace(r.GetFilename()) == "" || r.GetSizeBytes() == 0 {
		return "", shared.NewError(shared.InvalidArgument, "", "filename and positive size_bytes are required")
	}
	if r.GetSizeBytes() > 4<<30 {
		return "", shared.NewError(shared.ResourceExhausted, "", "PCAP exceeds 4 GiB upload limit")
	}
	id, e := shared.NewPCAPID()
	if e != nil {
		return "", e
	}
	f, e := os.CreateTemp("", "ipsec-upload-*")
	if e != nil {
		return "", e
	}
	u := &upload{id: string(id), filename: filepath.Base(r.GetFilename()), sha: strings.ToLower(r.GetSha256()), path: f.Name(), size: r.GetSizeBytes(), file: f}
	s.mu.Lock()
	s.uploads[u.id] = u
	s.mu.Unlock()
	return u.id, nil
}
func (s *Service) UploadChunk(ctx context.Context, r *inputv1.UploadPcapChunkRequest) (uint64, error) {
	if r == nil || len(r.GetData()) == 0 {
		return 0, shared.NewError(shared.InvalidArgument, "", "upload_id and data are required")
	}
	if err := ctx.Err(); err != nil {
		s.discardUpload(r.GetUploadId())
		return 0, err
	}
	s.mu.Lock()
	u := s.uploads[r.GetUploadId()]
	if u == nil {
		s.mu.Unlock()
		return 0, shared.NewError(shared.NotFound, "", "upload was not found")
	}
	if r.GetChunkIndex() != u.next {
		s.mu.Unlock()
		return 0, shared.NewError(shared.FailedPrecondition, "", "chunk_index is out of order")
	}
	if uint64(len(r.GetData())) > ChunkSize || u.received+uint64(len(r.GetData())) > u.size {
		s.mu.Unlock()
		return 0, shared.NewError(shared.InvalidArgument, "", "chunk exceeds declared upload size")
	}
	_, e := u.file.Write(r.GetData())
	if e == nil {
		u.received += uint64(len(r.GetData()))
		u.next++
	}
	received := u.received
	s.mu.Unlock()
	if e != nil {
		s.discardUpload(r.GetUploadId())
		return 0, e
	}
	return received, nil
}
func (s *Service) CompleteUpload(ctx context.Context, id string) (Source, error) {
	s.mu.Lock()
	u := s.uploads[id]
	if u == nil {
		s.mu.Unlock()
		return Source{}, shared.NewError(shared.NotFound, "", "upload was not found")
	}
	delete(s.uploads, id)
	s.mu.Unlock()
	success := false
	defer func() {
		_ = u.file.Close()
		if !success {
			_ = os.Remove(u.path)
		}
	}()
	if err := ctx.Err(); err != nil {
		return Source{}, err
	}
	if u.received != u.size {
		return Source{}, shared.NewError(shared.FailedPrecondition, "", "upload is incomplete")
	}
	if _, e := u.file.Seek(0, io.SeekStart); e != nil {
		return Source{}, e
	}
	h := sha256.New()
	if _, e := io.Copy(h, u.file); e != nil {
		return Source{}, e
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if u.sha != "" && u.sha != sum {
		return Source{}, shared.NewError(shared.InvalidArgument, "", "sha256 does not match uploaded content")
	}
	if _, e := u.file.Seek(0, io.SeekStart); e != nil {
		return Source{}, e
	}
	ses, e := s.sensor.Sessions.Create(ctx, sensorv1.SensorMode_PASSIVE_PCAP, "core-pcap", nil)
	if e != nil {
		return Source{}, e
	}
	resetSession := true
	defer func() {
		if resetSession {
			_, _ = s.sensor.Sessions.Reset(context.Background(), ses.ID, true)
		}
	}()
	result, e := s.sensor.Captures.ReadOfflinePCAP(ctx, u.file, ses.ID)
	if e != nil {
		return Source{}, e
	}
	if e = s.sensor.Flows.StopForSession(ctx, ses.ID); e != nil {
		return Source{}, e
	}
	pcap, e := shared.NewPCAPID()
	if e != nil {
		return Source{}, e
	}
	now := time.Now().UTC()
	src := Source{ID: id, Mode: inputv1.InputMode_PASSIVE_PCAP, State: inputv1.InputState_SOURCE_READY, SessionID: ses.ID, PCAPID: string(pcap), Filename: u.filename, SHA256: sum, Path: u.path, Size: u.size, CreatedAt: now, UpdatedAt: now, Counters: result.Counters}
	s.mu.Lock()
	s.sources[id] = &src
	s.mu.Unlock()
	success = true
	resetSession = false
	return src, nil
}
func (s *Service) discardUpload(id string) {
	s.mu.Lock()
	u := s.uploads[id]
	delete(s.uploads, id)
	s.mu.Unlock()
	if u != nil {
		_ = u.file.Close()
		_ = os.Remove(u.path)
	}
}
func (s *Service) Get(ctx context.Context, id string) (Source, error) {
	if strings.TrimSpace(id) == "" {
		return Source{}, shared.NewError(shared.InvalidArgument, "", "source_id is required")
	}
	s.mu.RLock()
	v := s.sources[id]
	if v != nil {
		c := *v
		v = &c
	}
	s.mu.RUnlock()
	if v == nil {
		return Source{}, shared.NewError(shared.NotFound, "", "source was not found")
	}
	return *v, nil
}
func (s *Service) Validate(ctx context.Context, id string) (capture.OfflineResult, error) {
	src, e := s.Get(ctx, id)
	if e != nil {
		return capture.OfflineResult{}, e
	}
	if src.Path == "" {
		return capture.OfflineResult{}, shared.NewError(shared.FailedPrecondition, "", "validation is available only for uploaded PCAP")
	}
	f, e := os.Open(src.Path)
	if e != nil {
		return capture.OfflineResult{}, e
	}
	defer f.Close()
	return capture.ReadOfflinePCAP(ctx, f, src.SessionID, nil)
}
func (s *Service) Remove(ctx context.Context, id string, deleteFile bool) (Source, error) {
	src, e := s.Get(ctx, id)
	if e != nil {
		return Source{}, e
	}
	if src.CaptureID != "" && src.State == inputv1.InputState_CAPTURING {
		_, _ = s.StopLive(ctx, id)
	}
	if deleteFile && src.Path != "" {
		_ = os.Remove(src.Path)
	}
	s.mu.Lock()
	delete(s.sources, id)
	src.State = inputv1.InputState_REMOVED
	src.UpdatedAt = time.Now().UTC()
	s.mu.Unlock()
	return src, nil
}
func (s *Service) String() string { return fmt.Sprintf("core input service") }
