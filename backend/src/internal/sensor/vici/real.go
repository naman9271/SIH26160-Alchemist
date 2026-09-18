package vici

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
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

var errUnsupportedVICIView = errors.New("VICI view is not implemented by this collector")

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
	// Advertise only views that this backend actually decodes. Returning an
	// empty successful result for an unimplemented command would incorrectly
	// turn missing evidence into an observed empty configuration.
	return &viciv1.ViciCapabilities{ListSas: true, ListConnections: true, ListPolicies: true, ListAlgorithms: true, Stats: true, Counters: true, ListCertificates: true, ListAuthorities: true, Events: false}, nil
}
func (b *RealBackend) DaemonStats(ctx context.Context, uri string) (*viciv1.ViciDaemonStats, error) {
	message, err := b.command(ctx, uri, "stats", nil)
	if err != nil {
		return nil, err
	}
	uptime, workers, ikesas := sectionValue(message, "uptime"), sectionValue(message, "workers"), sectionValue(message, "ikesas")
	return &viciv1.ViciDaemonStats{UptimeSeconds: durationSeconds(stringValue(uptime, "running")), WorkerThreadsTotal: uint32(uint64Value(workers, "total")), WorkerThreadsIdle: uint32(uint64Value(workers, "idle")), IkeSaTotal: uint32(uint64Value(ikesas, "total")), IkeSaHalfOpen: uint32(uint64Value(ikesas, "half-open")), LoadedPlugins: listValue(message, "plugins")}, nil
}
func (b *RealBackend) IkeSas(ctx context.Context, uri string) ([]*viciv1.IkeSa, error) {
	ikes, _, err := b.SAs(ctx, uri)
	return ikes, err
}

// SAs decodes one list-sas stream so parent and child state comes from the
// same gateway observation interval.
func (b *RealBackend) SAs(ctx context.Context, uri string) ([]*viciv1.IkeSa, []*viciv1.ChildSa, error) {
	messages, err := b.streamed(ctx, uri, "list-sas", "list-sa")
	if err != nil {
		return nil, nil, err
	}
	ikes := make([]*viciv1.IkeSa, 0)
	children := make([]*viciv1.ChildSa, 0)
	observedAt := time.Now().UTC()
	for _, message := range messages {
		for _, name := range message.Keys() {
			if section, ok := message.Get(name).(*govici.Message); ok {
				ike := decodeIkeAt(name, section, observedAt)
				ikes = append(ikes, ike)
				children = append(children, ike.GetAssociatedChildSas()...)
			}
		}
	}
	return ikes, children, nil
}
func (b *RealBackend) ChildSas(ctx context.Context, uri string) ([]*viciv1.ChildSa, error) {
	_, children, err := b.SAs(ctx, uri)
	return children, err
}
func decodeIkeAt(name string, m *govici.Message, observedAt time.Time) *viciv1.IkeSa {
	ike := &viciv1.IkeSa{Name: name, UniqueId: uint64Value(m, "uniqueid"), State: stringValue(m, "state"), IkeVersion: normalizeIKEVersion(stringValue(m, "version")), LocalHost: stringValue(m, "local-host"), LocalPort: uint32(uint64Value(m, "local-port")), RemoteHost: stringValue(m, "remote-host"), RemotePort: uint32(uint64Value(m, "remote-port")), LocalIdentity: stringValue(m, "local-id"), RemoteIdentity: stringValue(m, "remote-id"), Initiator: yes(stringValue(m, "initiator")), InitiatorSpi: stringValue(m, "initiator-spi"), ResponderSpi: stringValue(m, "responder-spi"), EncryptionAlgorithm: stringValue(m, "encr-alg"), EncryptionKeySize: uint32(uint64Value(m, "encr-keysize")), IntegrityAlgorithm: stringValue(m, "integ-alg"), IntegrityKeySize: uint32(uint64Value(m, "integ-keysize")), Prf: stringValue(m, "prf-alg"), DhGroup: stringValue(m, "dh-group"), AdditionalKeyExchanges: additionalKE(m), EstablishedDuration: uint64Value(m, "established"), RekeyTime: uint64Value(m, "rekey-time"), ReauthTime: uint64Value(m, "reauth-time"), EvidenceStatus: commonv1.EvidenceStatus_VERIFIED_GATEWAY}
	if children := sectionValue(m, "child-sas"); children != nil {
		for _, childName := range children.Keys() {
			if child := sectionValue(children, childName); child != nil {
				ike.AssociatedChildSas = append(ike.AssociatedChildSas, decodeChildAt(childName, child, observedAt))
			}
		}
	}
	return ike
}
func decodeChild(name string, m *govici.Message) *viciv1.ChildSa {
	return decodeChildAt(name, m, time.Now().UTC())
}
func decodeChildAt(name string, m *govici.Message, observedAt time.Time) *viciv1.ChildSa {
	installedFor := time.Duration(uint64Value(m, "install-time")) * time.Second
	installedAt := observedAt.UTC().Add(-installedFor)
	return &viciv1.ChildSa{Name: name, UniqueId: uint64Value(m, "uniqueid"), Reqid: uint32(uint64Value(m, "reqid")), State: stringValue(m, "state"), Mode: strings.ToUpper(stringValue(m, "mode")), Protocol: strings.ToUpper(stringValue(m, "protocol")), SpiIn: uint32(hexOrDecimal(m, "spi-in")), SpiOut: uint32(hexOrDecimal(m, "spi-out")), EncryptionAlgorithm: stringValue(m, "encr-alg"), KeyLength: uint32(uint64Value(m, "encr-keysize")), IntegrityAlgorithm: stringValue(m, "integ-alg"), IntegrityKeySize: uint32(uint64Value(m, "integ-keysize")), Prf: stringValue(m, "prf-alg"), DhGroup: stringValue(m, "dh-group"), AdditionalKeyExchanges: additionalKE(m), ExtendedSequenceNumbers: yes(stringValue(m, "esn")), BytesIn: uint64Value(m, "bytes-in"), BytesOut: uint64Value(m, "bytes-out"), PacketsIn: uint64Value(m, "packets-in"), PacketsOut: uint64Value(m, "packets-out"), InstallTime: timestamppb.New(installedAt), InstallDuration: uint64Value(m, "install-time"), RekeyTime: uint64Value(m, "rekey-time"), LifeTime: uint64Value(m, "life-time"), LocalTrafficSelectors: listValue(m, "local-ts"), RemoteTrafficSelectors: listValue(m, "remote-ts"), EvidenceStatus: commonv1.EvidenceStatus_VERIFIED_GATEWAY}
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
				result = append(result, decodeConnection(name, m))
			}
		}
	}
	return result, nil
}
func (b *RealBackend) Policies(ctx context.Context, uri string) ([]*viciv1.ViciPolicy, error) {
	messages, err := b.streamed(ctx, uri, "list-policies", "list-policy")
	if err != nil {
		return nil, err
	}
	result := make([]*viciv1.ViciPolicy, 0)
	for _, message := range messages {
		for _, name := range message.Keys() {
			if m := sectionValue(message, name); m != nil {
				localTS, remoteTS := listValue(m, "local-ts"), listValue(m, "remote-ts")
				result = append(result, &viciv1.ViciPolicy{
					Name:                   name,
					Source:                 strings.Join(localTS, ","),
					Destination:            strings.Join(remoteTS, ","),
					Mode:                   strings.ToUpper(stringValue(m, "mode")),
					IkeName:                stringValue(m, "ike"),
					ChildName:              stringValue(m, "child"),
					LocalTrafficSelectors:  localTS,
					RemoteTrafficSelectors: remoteTS,
					EvidenceStatus:         commonv1.EvidenceStatus_VERIFIED_GATEWAY,
				})
			}
		}
	}
	return result, nil
}
func (b *RealBackend) Algorithms(ctx context.Context, uri string) ([]*viciv1.ViciAlgorithm, error) {
	message, err := b.command(ctx, uri, "get-algorithms", nil)
	if err != nil {
		return nil, err
	}
	result := make([]*viciv1.ViciAlgorithm, 0)
	for _, kind := range message.Keys() {
		if algorithms := sectionValue(message, kind); algorithms != nil {
			for _, name := range algorithms.Keys() {
				result = append(result, &viciv1.ViciAlgorithm{Name: name, AlgorithmType: kind, Implementations: listValue(algorithms, name), EvidenceStatus: commonv1.EvidenceStatus_VERIFIED_GATEWAY})
			}
		}
	}
	return result, nil
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
	messages, err := b.streamed(ctx, uri, "list-certs", "list-cert")
	if err != nil {
		return nil, err
	}
	result := make([]*viciv1.Certificate, 0, len(messages))
	for _, message := range messages {
		result = append(result, decodeCertificate(message))
	}
	return result, nil
}
func (b *RealBackend) Authorities(ctx context.Context, uri string) ([]*viciv1.Authority, error) {
	messages, err := b.streamed(ctx, uri, "list-authorities", "list-authority")
	if err != nil {
		return nil, err
	}
	result := make([]*viciv1.Authority, 0)
	for _, message := range messages {
		for _, name := range message.Keys() {
			if m := sectionValue(message, name); m != nil {
				result = append(result, &viciv1.Authority{Name: name, Subject: stringValue(m, "cacert"), EvidenceStatus: commonv1.EvidenceStatus_VERIFIED_GATEWAY})
			}
		}
	}
	return result, nil
}
func (b *RealBackend) Events(context.Context, string, uint32) (<-chan *viciv1.ViciEvent, error) {
	return nil, errUnsupportedVICIView
}

func stringValue(m *govici.Message, key string) string {
	if m == nil {
		return ""
	}
	value, _ := m.Get(key).(string)
	return strings.TrimSpace(value)
}
func rawStringValue(m *govici.Message, key string) string {
	if m == nil {
		return ""
	}
	value, _ := m.Get(key).(string)
	return value
}
func sectionValue(m *govici.Message, key string) *govici.Message {
	if m == nil {
		return nil
	}
	value, _ := m.Get(key).(*govici.Message)
	return value
}
func uint64Value(m *govici.Message, key string) uint64 {
	value, _ := strconv.ParseUint(strings.TrimPrefix(stringValue(m, key), "0x"), 10, 64)
	return value
}
func hexOrDecimal(m *govici.Message, key string) uint64 {
	value := stringValue(m, key)
	base := 10
	if strings.HasPrefix(value, "0x") || strings.IndexFunc(value, func(r rune) bool {
		return r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F'
	}) >= 0 {
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
	section := sectionValue(m, key)
	if section == nil {
		return nil
	}
	return section.Keys()
}
func additionalKE(m *govici.Message) []string {
	result := make([]string, 0, 7)
	for index := 1; index <= 7; index++ {
		if value := stringValue(m, "ake"+strconv.Itoa(index)); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func durationSeconds(value string) uint64 {
	value = strings.TrimSpace(value)
	if parsed, err := strconv.ParseUint(value, 10, 64); err == nil {
		return parsed
	}
	var total uint64
	fields := strings.Fields(strings.ToLower(value))
	for index := 0; index+1 < len(fields); index += 2 {
		amount, err := strconv.ParseUint(fields[index], 10, 64)
		if err != nil {
			continue
		}
		switch strings.TrimSuffix(fields[index+1], "s") {
		case "day":
			total += amount * 86400
		case "hour":
			total += amount * 3600
		case "minute":
			total += amount * 60
		case "second":
			total += amount
		}
	}
	return total
}

func decodeProposal(m *govici.Message) *viciv1.ViciProposal {
	if m == nil {
		return nil
	}
	additional := make([]string, 0)
	for index := 1; index <= 7; index++ {
		additional = append(additional, listValue(m, "ake"+strconv.Itoa(index))...)
	}
	return &viciv1.ViciProposal{Encryption: listValue(m, "encr"), Integrity: listValue(m, "integ"), Prf: listValue(m, "prf"), KeyExchange: listValue(m, "ke"), AdditionalKeyExchange: additional, SequenceNumber: listValue(m, "sn")}
}

func decodeProposals(parent *govici.Message, key string) []*viciv1.ViciProposal {
	section := sectionValue(parent, key)
	if section == nil {
		return nil
	}
	result := make([]*viciv1.ViciProposal, 0, len(section.Keys()))
	for _, name := range section.Keys() {
		if proposal := decodeProposal(sectionValue(section, name)); proposal != nil {
			result = append(result, proposal)
		}
	}
	return result
}

func decodeConnection(name string, m *govici.Message) *viciv1.StrongSwanConnection {
	connection := &viciv1.StrongSwanConnection{Name: name, IkeVersion: normalizeIKEVersion(stringValue(m, "version")), LocalAddresses: listValue(m, "local_addrs"), RemoteAddresses: listValue(m, "remote_addrs"), LifeTime: uint64Value(m, "life_time"), RekeyTime: uint64Value(m, "rekey_time"), ConfiguredIkeProposals: decodeProposals(m, "proposals"), EvidenceStatus: commonv1.EvidenceStatus_VERIFIED_GATEWAY}
	for _, key := range m.Keys() {
		section := sectionValue(m, key)
		if section == nil {
			continue
		}
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "local") || strings.HasPrefix(lower, "remote") {
			side := "local"
			if strings.HasPrefix(lower, "remote") {
				side = "remote"
			}
			auth := &viciv1.ViciAuthConfig{Side: side, SectionName: key, AuthClass: stringValue(section, "class"), EapType: stringValue(section, "eap-type"), EapVendor: stringValue(section, "eap-vendor"), XauthBackend: stringValue(section, "xauth"), RevocationPolicy: stringValue(section, "revocation"), Identity: stringValue(section, "id"), AaaIdentity: stringValue(section, "aaa_id"), EapIdentity: stringValue(section, "eap_id"), XauthIdentity: stringValue(section, "xauth_id"), Groups: listValue(section, "groups"), Certificates: listValue(section, "certs"), CaCertificates: listValue(section, "cacerts")}
			connection.Authentication = append(connection.Authentication, auth)
			if auth.AuthClass != "" {
				connection.AuthenticationMethods = append(connection.AuthenticationMethods, side+":"+auth.AuthClass)
			}
		}
	}
	if children := sectionValue(m, "children"); children != nil {
		for _, childName := range children.Keys() {
			if child := sectionValue(children, childName); child != nil {
				config := &viciv1.ViciChildConfig{Name: childName, Mode: strings.ToUpper(stringValue(child, "mode")), RekeyTime: uint64Value(child, "rekey_time"), RekeyBytes: uint64Value(child, "rekey_bytes"), RekeyPackets: uint64Value(child, "rekey_packets"), EspProposals: decodeProposals(child, "esp_proposals"), AhProposals: decodeProposals(child, "ah_proposals"), LocalTrafficSelectors: listValue(child, "local-ts"), RemoteTrafficSelectors: listValue(child, "remote-ts")}
				for _, proposal := range append(append([]*viciv1.ViciProposal{}, config.EspProposals...), config.AhProposals...) {
					config.ConfiguredPfsGroups = append(config.ConfiguredPfsGroups, proposal.GetKeyExchange()...)
					config.ConfiguredPfsGroups = append(config.ConfiguredPfsGroups, proposal.GetAdditionalKeyExchange()...)
				}
				connection.ConfiguredChildren = append(connection.ConfiguredChildren, config)
				connection.ChildDefinitions = append(connection.ChildDefinitions, childName)
			}
		}
	}
	return connection
}

func decodeCertificate(m *govici.Message) *viciv1.Certificate {
	result := &viciv1.Certificate{CertificateType: stringValue(m, "type"), Subject: stringValue(m, "subject"), EvidenceStatus: commonv1.EvidenceStatus_VERIFIED_GATEWAY}
	raw := []byte(rawStringValue(m, "data"))
	if len(raw) == 0 {
		return result
	}
	digest := sha256.Sum256(raw)
	result.Fingerprint = hex.EncodeToString(digest[:])
	if certificate, err := x509.ParseCertificate(raw); err == nil {
		result.Subject = certificate.Subject.String()
		result.Issuer = certificate.Issuer.String()
		result.ValidFrom = timestamppb.New(certificate.NotBefore.UTC())
		result.ValidUntil = timestamppb.New(certificate.NotAfter.UTC())
		result.PublicKeyType = certificate.PublicKeyAlgorithm.String()
	}
	return result
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
