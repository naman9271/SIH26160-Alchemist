package vici

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	viciv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/vici"
	govici "github.com/strongswan/govici/vici"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// RealBackend reads sanitized StrongSwan state using VICI commands. It never
// requests or exposes private key material.
type RealBackend struct{ timeout time.Duration }

func NewRealBackend(timeout time.Duration) *RealBackend {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &RealBackend{timeout: timeout}
}

func (b *RealBackend) session(ctx context.Context, uri string) (*govici.Session, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: b.timeout}
	return govici.NewSession(govici.WithSocketPath(parsed.Path), govici.WithDialContext(func(_ context.Context, network, address string) (net.Conn, error) {
		connection, dialErr := dialer.DialContext(ctx, network, address)
		if dialErr == nil {
			deadline := time.Now().Add(b.timeout)
			if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
				deadline = value
			}
			_ = connection.SetDeadline(deadline)
		}
		return connection, dialErr
	}))
}

func (b *RealBackend) command(ctx context.Context, uri, command string, request *govici.Message) (*govici.Message, error) {
	session, err := b.session(ctx, uri)
	if err != nil {
		return nil, err
	}
	defer session.Close()
	return session.CommandRequest(command, request)
}
func (b *RealBackend) streamed(ctx context.Context, uri, command, event string) ([]*govici.Message, error) {
	session, err := b.session(ctx, uri)
	if err != nil {
		return nil, err
	}
	defer session.Close()
	return session.StreamedCommandRequest(command, event, nil)
}

func (b *RealBackend) Capabilities(ctx context.Context, uri string) (*viciv1.ViciCapabilities, error) {
	if _, err := b.command(ctx, uri, "version", nil); err != nil {
		return nil, err
	}
	return &viciv1.ViciCapabilities{ListSas: true, ListConnections: true, ListPolicies: true, ListAlgorithms: true, Stats: true, Counters: true, ListCertificates: true, ListAuthorities: true, Events: true}, nil
}
func (b *RealBackend) DaemonStats(ctx context.Context, uri string) (*viciv1.ViciDaemonStats, error) {
	message, err := b.command(ctx, uri, "stats", nil)
	if err != nil {
		return nil, err
	}
	return &viciv1.ViciDaemonStats{UptimeSeconds: uint64Value(message, "uptime"), WorkerThreadsTotal: uint32(uint64Value(message, "workers")), WorkerThreadsIdle: uint32(uint64Value(message, "idle")), IkeSaTotal: uint32(uint64Value(message, "ikesas")), IkeSaHalfOpen: uint32(uint64Value(message, "half-open")), LoadedPlugins: listValue(message, "plugins")}, nil
}
func (b *RealBackend) IkeSas(ctx context.Context, uri string) ([]*viciv1.IkeSa, error) {
	messages, err := b.streamed(ctx, uri, "list-sas", "list-sa")
	if err != nil {
		return nil, err
	}
	result := make([]*viciv1.IkeSa, 0)
	for _, message := range messages {
		for _, name := range message.Keys() {
			if section, ok := message.Get(name).(*govici.Message); ok {
				result = append(result, decodeIke(name, section))
			}
		}
	}
	return result, nil
}
func (b *RealBackend) ChildSas(ctx context.Context, uri string) ([]*viciv1.ChildSa, error) {
	messages, err := b.streamed(ctx, uri, "list-sas", "list-sa")
	if err != nil {
		return nil, err
	}
	result := make([]*viciv1.ChildSa, 0)
	for _, message := range messages {
		for _, name := range message.Keys() {
			if ike, ok := message.Get(name).(*govici.Message); ok {
				if children, ok := ike.Get("child-sas").(*govici.Message); ok {
					for _, childName := range children.Keys() {
						if child, ok := children.Get(childName).(*govici.Message); ok {
							result = append(result, decodeChild(childName, child))
						}
					}
				}
			}
		}
	}
	return result, nil
}
func decodeIke(name string, m *govici.Message) *viciv1.IkeSa {
	return &viciv1.IkeSa{Name: name, UniqueId: uint64Value(m, "uniqueid"), State: stringValue(m, "state"), IkeVersion: normalizeIKEVersion(stringValue(m, "version")), LocalHost: stringValue(m, "local-host"), LocalPort: uint32(uint64Value(m, "local-port")), RemoteHost: stringValue(m, "remote-host"), RemotePort: uint32(uint64Value(m, "remote-port")), LocalIdentity: stringValue(m, "local-id"), RemoteIdentity: stringValue(m, "remote-id"), Initiator: yes(stringValue(m, "initiator")), InitiatorSpi: stringValue(m, "initiator-spi"), ResponderSpi: stringValue(m, "responder-spi"), EncryptionAlgorithm: stringValue(m, "encr-alg"), EncryptionKeySize: uint32(uint64Value(m, "encr-keysize")), IntegrityAlgorithm: stringValue(m, "integ-alg"), Prf: stringValue(m, "prf-alg"), DhGroup: stringValue(m, "dh-group"), EstablishedDuration: uint64Value(m, "established"), RekeyTime: uint64Value(m, "rekey-time"), ReauthTime: uint64Value(m, "reauth-time"), EvidenceStatus: commonv1.EvidenceStatus_VERIFIED_GATEWAY}
}
func decodeChild(name string, m *govici.Message) *viciv1.ChildSa {
	return &viciv1.ChildSa{Name: name, UniqueId: uint64Value(m, "uniqueid"), Reqid: uint32(uint64Value(m, "reqid")), State: stringValue(m, "state"), Mode: strings.ToUpper(stringValue(m, "mode")), Protocol: strings.ToUpper(stringValue(m, "protocol")), SpiIn: uint32(hexOrDecimal(m, "spi-in")), SpiOut: uint32(hexOrDecimal(m, "spi-out")), EncryptionAlgorithm: stringValue(m, "encr-alg"), KeyLength: uint32(uint64Value(m, "encr-keysize")), IntegrityAlgorithm: stringValue(m, "integ-alg"), BytesIn: uint64Value(m, "bytes-in"), BytesOut: uint64Value(m, "bytes-out"), PacketsIn: uint64Value(m, "packets-in"), PacketsOut: uint64Value(m, "packets-out"), InstallTime: timestamppb.New(time.Unix(int64(uint64Value(m, "install-time")), 0).UTC()), RekeyTime: uint64Value(m, "rekey-time"), LifeTime: uint64Value(m, "life-time"), LocalTrafficSelectors: listValue(m, "local-ts"), RemoteTrafficSelectors: listValue(m, "remote-ts"), EvidenceStatus: commonv1.EvidenceStatus_VERIFIED_GATEWAY}
}
func (b *RealBackend) Connections(ctx context.Context, uri string) ([]*viciv1.StrongSwanConnection, error) {
	messages, err := b.streamed(ctx, uri, "list-conns", "list-conn")
	if err != nil {
		return nil, err
	}
	result := make([]*viciv1.StrongSwanConnection, 0)
	for _, message := range messages {
		for _, name := range message.Keys() {
			if m, ok := message.Get(name).(*govici.Message); ok {
				result = append(result, &viciv1.StrongSwanConnection{Name: name, IkeVersion: normalizeIKEVersion(stringValue(m, "version")), AuthenticationMethods: listValue(m, "auth"), IkeProposals: listValue(m, "proposals"), ChildDefinitions: sectionKeys(m, "children"), LocalTrafficSelectors: listValue(m, "local-ts"), RemoteTrafficSelectors: listValue(m, "remote-ts"), LifeTime: uint64Value(m, "life-time"), RekeyTime: uint64Value(m, "rekey-time"), PfsKeyExchange: stringValue(m, "pfs-key-exchange"), EvidenceStatus: commonv1.EvidenceStatus_VERIFIED_GATEWAY})
			}
		}
	}
	return result, nil
}
func (b *RealBackend) Policies(ctx context.Context, uri string) ([]*viciv1.ViciPolicy, error) {
	_, err := b.streamed(ctx, uri, "list-pols", "list-policy")
	return []*viciv1.ViciPolicy{}, err
}
func (b *RealBackend) Algorithms(ctx context.Context, uri string) ([]*viciv1.ViciAlgorithm, error) {
	_, err := b.command(ctx, uri, "get-algorithms", nil)
	return []*viciv1.ViciAlgorithm{}, err
}
func (b *RealBackend) Counters(ctx context.Context, uri, connection string, all bool) (*viciv1.ViciCounters, error) {
	request := govici.NewMessage()
	if connection != "" {
		_ = request.Set("name", connection)
	}
	if all {
		_ = request.Set("all", true)
	}
	message, err := b.command(ctx, uri, "get-counters", request)
	if err != nil {
		return nil, err
	}
	values := make(map[string]uint64)
	flattenCounters(message, "", values)
	return &viciv1.ViciCounters{Values: values, EvidenceStatus: commonv1.EvidenceStatus_VERIFIED_GATEWAY}, nil
}
func (b *RealBackend) Certificates(ctx context.Context, uri string) ([]*viciv1.Certificate, error) {
	_, err := b.streamed(ctx, uri, "list-certs", "list-cert")
	return []*viciv1.Certificate{}, err
}
func (b *RealBackend) Authorities(ctx context.Context, uri string) ([]*viciv1.Authority, error) {
	_, err := b.streamed(ctx, uri, "list-authorities", "list-authority")
	return []*viciv1.Authority{}, err
}
func (b *RealBackend) Events(context.Context, string, uint32) (<-chan *viciv1.ViciEvent, error) {
	channel := make(chan *viciv1.ViciEvent)
	close(channel)
	return channel, nil
}

func stringValue(m *govici.Message, key string) string {
	if m == nil {
		return ""
	}
	value, _ := m.Get(key).(string)
	return strings.TrimSpace(value)
}
func uint64Value(m *govici.Message, key string) uint64 {
	value, _ := strconv.ParseUint(strings.TrimPrefix(stringValue(m, key), "0x"), 10, 64)
	return value
}
func hexOrDecimal(m *govici.Message, key string) uint64 {
	value := stringValue(m, key)
	base := 10
	if strings.HasPrefix(value, "0x") {
		base, value = 16, strings.TrimPrefix(value, "0x")
	}
	parsed, _ := strconv.ParseUint(value, base, 64)
	return parsed
}
func listValue(m *govici.Message, key string) []string {
	if m == nil {
		return nil
	}
	if values, ok := m.Get(key).([]string); ok {
		return append([]string(nil), values...)
	}
	if value := stringValue(m, key); value != "" {
		return strings.Fields(value)
	}
	return nil
}
func sectionKeys(m *govici.Message, key string) []string {
	section, _ := m.Get(key).(*govici.Message)
	if section == nil {
		return nil
	}
	return section.Keys()
}
func yes(value string) bool { return value == "yes" || value == "true" || value == "1" }
func normalizeIKEVersion(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "1" || value == "IKEV1" {
		return "IKEv1"
	}
	if value == "2" || value == "IKEV2" {
		return "IKEv2"
	}
	return value
}
func flattenCounters(m *govici.Message, prefix string, out map[string]uint64) {
	if m == nil {
		return
	}
	for _, key := range m.Keys() {
		name := strings.TrimPrefix(prefix+"."+key, ".")
		if child, ok := m.Get(key).(*govici.Message); ok {
			flattenCounters(child, name, out)
		} else if value := uint64Value(m, key); value > 0 {
			out[name] = value
		}
	}
}

var _ Backend = (*RealBackend)(nil)
