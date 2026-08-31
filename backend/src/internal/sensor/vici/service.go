// Package vici is the read-only StrongSwan gateway boundary.  It deliberately
// exposes normalized models only; the UNIX socket protocol never crosses it.
package vici

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	viciv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/vici"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	govici "github.com/strongswan/govici/vici"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const DefaultSocketURI = "unix:///var/run/charon.vici"

// Backend separates normalized VICI decoding from gRPC and makes a real VICI
// decoder replaceable without ever accepting raw VICI from clients.
type Backend interface {
	Capabilities(context.Context, string) (*viciv1.ViciCapabilities, error)
	DaemonStats(context.Context, string) (*viciv1.ViciDaemonStats, error)
	IkeSas(context.Context, string) ([]*viciv1.IkeSa, error)
	ChildSas(context.Context, string) ([]*viciv1.ChildSa, error)
	Connections(context.Context, string) ([]*viciv1.StrongSwanConnection, error)
	Policies(context.Context, string) ([]*viciv1.ViciPolicy, error)
	Algorithms(context.Context, string) ([]*viciv1.ViciAlgorithm, error)
	Counters(context.Context, string, string, bool) (*viciv1.ViciCounters, error)
	Certificates(context.Context, string) ([]*viciv1.Certificate, error)
	Authorities(context.Context, string) ([]*viciv1.Authority, error)
	Events(context.Context, string, uint32) (<-chan *viciv1.ViciEvent, error)
}
type Service struct {
	backend Backend
	dial    func(context.Context, string) (net.Conn, error)
}

func New(backend Backend) *Service { return &Service{backend: backend, dial: dial} }
func URI(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		value = DefaultSocketURI
	}
	u, e := url.Parse(value)
	if e != nil || u.Scheme != "unix" || u.Path == "" || u.Host != "" {
		return "", shared.NewError(shared.InvalidArgument, "", "socket_uri must be an absolute unix:/// path")
	}
	return value, nil
}
func dial(ctx context.Context, uri string) (net.Conn, error) {
	u, _ := url.Parse(uri)
	d := net.Dialer{}
	return d.DialContext(ctx, "unix", u.Path)
}
func (s *Service) Probe(ctx context.Context, uri string) (*viciv1.ProbeViciResponse, error) {
	uri, e := URI(uri)
	if e != nil {
		return nil, e
	}
	if _, fixture := s.backend.(*FixtureBackend); fixture {
		return &viciv1.ProbeViciResponse{Available: true, SocketUri: uri, CharonReachable: true}, nil
	}
	c, e := s.dial(ctx, uri)
	if e == nil {
		_ = c.Close()
		u, _ := url.Parse(uri)
		session, commandErr := govici.NewSession(govici.WithSocketPath(u.Path))
		if commandErr == nil {
			_, commandErr = session.CommandRequest("version", nil)
			_ = session.Close()
		}
		if commandErr == nil {
			return &viciv1.ProbeViciResponse{Available: true, SocketUri: uri, CharonReachable: true}, nil
		}
		return &viciv1.ProbeViciResponse{SocketUri: uri}, shared.NewError(shared.Unavailable, shared.VICIPluginDisabled, "VICI is reachable but did not accept the version command")
	}
	if errors.Is(e, os.ErrNotExist) || errors.Is(e, os.ErrPermission) {
		return &viciv1.ProbeViciResponse{SocketUri: uri}, shared.NewError(shared.Unavailable, shared.VICIUnavailable, "VICI socket is unavailable")
	}
	if errors.Is(e, context.DeadlineExceeded) {
		return &viciv1.ProbeViciResponse{SocketUri: uri}, shared.NewError(shared.DeadlineExceeded, shared.VICIUnavailable, "VICI connection timed out")
	}
	return &viciv1.ProbeViciResponse{SocketUri: uri}, shared.NewError(shared.Unavailable, shared.VICIUnavailable, "cannot connect to VICI socket")
}
func (s *Service) Backend(ctx context.Context, uri string) (Backend, string, error) {
	uri, e := URI(uri)
	if e != nil {
		return nil, "", e
	}
	// Recorded fixtures are an explicit test collector and do not require a
	// host socket. All other backends must pass the read-only probe.
	if _, fixture := s.backend.(*FixtureBackend); !fixture {
		if _, e = s.Probe(ctx, uri); e != nil {
			return nil, "", e
		}
	}
	if s.backend == nil {
		return nil, "", shared.NewError(shared.Unavailable, shared.VICIPluginDisabled, "VICI command decoder is not configured")
	}
	return s.backend, uri, nil
}

// Snapshot collects every sanitized VICI view used by evidence mapping. A
// component failure is recorded without discarding the other available views.
func (s *Service) Snapshot(ctx context.Context, uri string) (*viciv1.GatewaySnapshot, error) {
	backend, resolved, err := s.Backend(ctx, uri)
	if err != nil {
		return nil, err
	}
	out := &viciv1.GatewaySnapshot{SchemaVersion: FixtureSchemaVersion, SnapshotTimestamp: timestamppb.New(time.Now().UTC())}
	type collection struct {
		name string
		run  func() error
	}
	collections := []collection{
		{"daemon_stats", func() error { out.DaemonStats, err = backend.DaemonStats(ctx, resolved); return err }},
		{"ike_sas", func() error { out.IkeSas, err = backend.IkeSas(ctx, resolved); return err }},
		{"child_sas", func() error { out.ChildSas, err = backend.ChildSas(ctx, resolved); return err }},
		{"connections", func() error { out.Connections, err = backend.Connections(ctx, resolved); return err }},
		{"policies", func() error { out.Policies, err = backend.Policies(ctx, resolved); return err }},
		{"algorithms", func() error { out.Algorithms, err = backend.Algorithms(ctx, resolved); return err }},
		{"counters", func() error { out.Counters, err = backend.Counters(ctx, resolved, "", true); return err }},
		{"certificates", func() error { out.Certificates, err = backend.Certificates(ctx, resolved); return err }},
		{"authorities", func() error { out.Authorities, err = backend.Authorities(ctx, resolved); return err }},
	}
	available := 0
	for _, item := range collections {
		itemErr := item.run()
		status := &viciv1.SourceAvailability{Source: item.name, Available: itemErr == nil}
		if itemErr != nil {
			status.Message = itemErr.Error()
		} else {
			available++
		}
		out.PerSourceAvailability = append(out.PerSourceAvailability, status)
	}
	if available == 0 {
		return nil, shared.NewError(shared.Unavailable, shared.VICIUnavailable, "VICI returned no usable telemetry")
	}
	return out, nil
}
func FilterIke(in []*viciv1.IkeSa, r *viciv1.ListIkeSasRequest) ([]*viciv1.IkeSa, string, error) {
	out := make([]*viciv1.IkeSa, 0, len(in))
	for _, x := range in {
		if r.GetIkeName() != "" && x.GetName() != r.GetIkeName() {
			continue
		}
		if r.GetIkeUniqueId() != 0 && x.GetUniqueId() != r.GetIkeUniqueId() {
			continue
		}
		if r.GetState() != "" && x.GetState() != r.GetState() {
			continue
		}
		out = append(out, x)
	}
	return page(out, r.GetPageSize(), r.GetPageToken(), func(x *viciv1.IkeSa) string { return x.GetName() + "/" + sortableID(x.GetUniqueId()) })
}
func FilterChild(in []*viciv1.ChildSa, r *viciv1.ListChildSasRequest) ([]*viciv1.ChildSa, string, error) {
	out := make([]*viciv1.ChildSa, 0, len(in))
	for _, x := range in {
		if r.GetChildUniqueId() != 0 && x.GetUniqueId() != r.GetChildUniqueId() {
			continue
		}
		if r.GetState() != "" && x.GetState() != r.GetState() {
			continue
		}
		out = append(out, x)
	}
	return page(out, r.GetPageSize(), r.GetPageToken(), func(x *viciv1.ChildSa) string { return x.GetName() + "/" + sortableID(x.GetUniqueId()) })
}
func sortableID(v uint64) string { return fmt.Sprintf("%020d", v) }
func page[T any](in []T, size uint32, token string, key func(T) string) ([]T, string, error) {
	if size == 0 {
		size = 100
	}
	if size > 1000 {
		return nil, "", shared.NewError(shared.InvalidArgument, "", "page_size must not exceed 1000")
	}
	start := 0
	for start < len(in) && token != "" && key(in[start]) <= token {
		start++
	}
	end := start + int(size)
	if end > len(in) {
		end = len(in)
	}
	next := ""
	if end < len(in) {
		next = key(in[end-1])
	}
	return in[start:end], next, nil
}
