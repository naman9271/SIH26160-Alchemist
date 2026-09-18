package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
)

type tcpdumpEngine struct{ path string }

func NewTCPDumpEngine() Engine {
	path, _ := exec.LookPath("tcpdump")
	return &tcpdumpEngine{path: path}
}
func (e *tcpdumpEngine) Available() bool { return e.path != "" }
func (e *tcpdumpEngine) ValidateFilter(ctx context.Context, filter string) error {
	if !e.Available() {
		return shared.NewError(shared.Unavailable, "", "tcpdump is unavailable")
	}
	args := []string{"-d"}
	if filter != "" {
		args = append(args, filter)
	}
	if output, err := exec.CommandContext(ctx, e.path, args...).CombinedOutput(); err != nil {
		message := string(output)
		if strings.Contains(message, "Operation not permitted") || strings.Contains(message, "Permission denied") {
			return shared.NewError(shared.Unavailable, "", "tcpdump cannot validate BPF without capture permission")
		}
		return shared.NewError(shared.InvalidArgument, "", "invalid BPF filter: "+message)
	}
	return nil
}

type tcpdumpHandle struct {
	cancel   context.CancelFunc
	done     chan error
	started  chan error
	mu       sync.RWMutex
	counters Counters
	files    []string
	stderr   bytes.Buffer
	once     sync.Once
}

func (h *tcpdumpHandle) Done() <-chan error { return h.done }
func (h *tcpdumpHandle) Counters() Counters { h.mu.RLock(); defer h.mu.RUnlock(); return h.counters }
func (h *tcpdumpHandle) TemporaryFiles() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return append([]string(nil), h.files...)
}
func (h *tcpdumpHandle) Stop(ctx context.Context) error {
	h.once.Do(h.cancel)
	select {
	case err := <-h.done:
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *tcpdumpEngine) Start(_ context.Context, config Config) (Handle, error) {
	if !e.Available() {
		return nil, shared.NewError(shared.Unavailable, "", "tcpdump is unavailable")
	}
	ctx, cancel := context.WithCancel(context.Background())
	args := []string{"-U", "-n", "-i", config.InterfaceName, "-w", "-"}
	if !config.PromiscuousMode {
		args = append(args, "-p")
	}
	if config.Filter != "" {
		args = append(args, config.Filter)
	}
	cmd := exec.CommandContext(ctx, e.path, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, shared.NewError(shared.Internal, "", "open tcpdump output: "+err.Error())
	}
	h := &tcpdumpHandle{cancel: cancel, done: make(chan error, 1), started: make(chan error, 1)}
	if config.SavePCAP {
		file, fileErr := os.CreateTemp("", "sensor-capture-*.pcap")
		if fileErr != nil {
			cancel()
			return nil, shared.NewError(shared.ResourceExhausted, "", "create capture file: "+fileErr.Error())
		}
		h.files = []string{file.Name()}
		_ = file.Close()
	}
	cmd.Stderr = &h.stderr
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, shared.NewError(shared.Unavailable, "", "start tcpdump: "+err.Error())
	}
	var writer io.Writer
	if len(h.files) > 0 {
		file, fileErr := os.OpenFile(h.files[0], os.O_WRONLY|os.O_APPEND, 0)
		if fileErr == nil {
			writer = file
		}
	}
	go func() {
		err := readPCAP(stdout, writer, h, config)
		if closer, ok := writer.(io.Closer); ok {
			_ = closer.Close()
		}
		if err != nil && !errors.Is(err, io.EOF) {
			select {
			case h.started <- err:
			default:
			}
		}
	}()
	go func() {
		err := cmd.Wait()
		h.mu.Lock()
		if err != nil && ctx.Err() != nil {
			err = nil
		}
		h.counters.PacketDrops += parseDrops(h.stderr.String())
		h.mu.Unlock()
		select {
		case h.started <- err:
		default:
		}
		h.done <- err
		close(h.done)
		cancel()
	}()
	select {
	case err := <-h.started:
		if err != nil {
			_ = h.Stop(context.Background())
			return nil, shared.NewError(shared.Unavailable, "", "tcpdump could not start: "+err.Error())
		}
		return h, nil
	case <-time.After(time.Second):
		_ = h.Stop(context.Background())
		return nil, shared.NewError(shared.Unavailable, "", "tcpdump did not initialize")
	}
}

func readPCAP(reader io.Reader, writer io.Writer, h *tcpdumpHandle, config Config) error {
	header := make([]byte, 24)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	if writer != nil {
		_, _ = writer.Write(header)
	}
	format, ok := pcapFormatForMagic(header[:4])
	if !ok {
		return errors.New("tcpdump emitted an unsupported capture format")
	}
	select {
	case h.started <- nil:
	default:
	}
	recordHeader := make([]byte, 16)
	for {
		if _, err := io.ReadFull(reader, recordHeader); err != nil {
			return err
		}
		length := format.order.Uint32(recordHeader[8:12])
		if length > 16<<20 {
			return errors.New("capture packet exceeds safety limit")
		}
		packet := make([]byte, length)
		if _, err := io.ReadFull(reader, packet); err != nil {
			return err
		}
		if writer != nil {
			_, _ = writer.Write(recordHeader)
			_, _ = writer.Write(packet)
		}
		fraction := int64(format.order.Uint32(recordHeader[4:8]))
		if !format.nanosecond {
			fraction *= 1_000
		}
		seenAt := time.Unix(int64(format.order.Uint32(recordHeader[:4])), fraction).UTC()
		if config.PacketObserver != nil {
			if metadata, ok := decodePacketMetadata(packet, uint64(length), seenAt); ok {
				metadata.SessionID = config.SessionID
				// A telemetry failure must not interrupt packet capture; the flow store
				// owns its bounded-memory/backpressure policy.
				_ = config.PacketObserver(context.Background(), metadata)
			}
		}
		h.mu.Lock()
		h.counters.PacketsTotal++
		h.counters.BytesTotal += uint64(length)
		classify(packet, &h.counters)
		maximumReached := config.MaxCaptureBytes > 0 && h.counters.BytesTotal >= config.MaxCaptureBytes
		h.mu.Unlock()
		if maximumReached {
			h.once.Do(h.cancel)
		}
	}
}

// ReadOfflinePCAP decodes a finite classic-PCAP stream with the same metadata
// decoder as live tcpdump capture. It is intentionally limited to classic
// PCAP or supported PCAPNG streams. Packet records are decoded through the
// same metadata-only packet path in both formats.
func ReadOfflinePCAP(ctx context.Context, reader io.Reader, sessionID string, observer PacketObserver) (OfflineResult, error) {
	if ctx == nil {
		return OfflineResult{}, shared.NewError(shared.InvalidArgument, "", "context is required")
	}
	if reader == nil {
		return OfflineResult{}, shared.NewError(shared.InvalidArgument, "", "PCAP reader is required")
	}
	if strings.TrimSpace(sessionID) == "" {
		return OfflineResult{}, shared.NewError(shared.InvalidArgument, "", "session_id is required")
	}
	header := make([]byte, 24)
	if _, err := io.ReadFull(reader, header); err != nil {
		return OfflineResult{}, shared.NewError(shared.InvalidArgument, shared.InvalidPCAP, "read PCAP header: "+err.Error())
	}
	format, ok := pcapFormatForMagic(header[:4])
	if !ok {
		if bytes.Equal(header[:4], []byte{0x0a, 0x0d, 0x0d, 0x0a}) {
			return readOfflinePCAPNG(ctx, io.MultiReader(bytes.NewReader(header), reader), sessionID, observer)
		}
		return OfflineResult{}, shared.NewError(shared.InvalidArgument, shared.InvalidPCAP, "unsupported PCAP format")
	}
	result := OfflineResult{}
	recordHeader := make([]byte, 16)
	for {
		if err := ctx.Err(); err != nil {
			return OfflineResult{}, err
		}
		if _, err := io.ReadFull(reader, recordHeader); err != nil {
			if errors.Is(err, io.EOF) {
				return result, nil
			}
			return OfflineResult{}, shared.NewError(shared.InvalidArgument, shared.InvalidPCAP, "read PCAP record: "+err.Error())
		}
		length := format.order.Uint32(recordHeader[8:12])
		if length > 16<<20 {
			return OfflineResult{}, shared.NewError(shared.InvalidArgument, shared.InvalidPCAP, "PCAP packet exceeds safety limit")
		}
		packet := make([]byte, length)
		if _, err := io.ReadFull(reader, packet); err != nil {
			return OfflineResult{}, shared.NewError(shared.InvalidArgument, shared.InvalidPCAP, "read PCAP packet: "+err.Error())
		}
		fraction := int64(format.order.Uint32(recordHeader[4:8]))
		if !format.nanosecond {
			fraction *= 1_000
		}
		seenAt := time.Unix(int64(format.order.Uint32(recordHeader[:4])), fraction).UTC()
		if result.FirstSeen.IsZero() {
			result.FirstSeen = seenAt
		}
		result.LastSeen = seenAt
		result.Counters.PacketsTotal++
		result.Counters.BytesTotal += uint64(length)
		classify(packet, &result.Counters)
		if observer != nil {
			if metadata, decoded := decodePacketMetadata(packet, uint64(length), seenAt); decoded {
				metadata.SessionID = sessionID
				if err := observer(ctx, metadata); err != nil {
					return OfflineResult{}, err
				}
			}
		}
	}
}

// readOfflinePCAPNG supports the packet-bearing PCAPNG blocks used by
// tcpdump/Wireshark (SHB, IDB, EPB and SPB). It validates every block length,
// supports both section byte orders, and intentionally ignores non-packet
// blocks rather than interpreting their payload as traffic.
func readOfflinePCAPNG(ctx context.Context, reader io.Reader, sessionID string, observer PacketObserver) (OfflineResult, error) {
	var result OfflineResult
	interfaces := map[uint32]uint16{}
	var order binary.ByteOrder
	for {
		if err := ctx.Err(); err != nil {
			return OfflineResult{}, err
		}
		header := make([]byte, 8)
		if _, err := io.ReadFull(reader, header); err != nil {
			if errors.Is(err, io.EOF) {
				return result, nil
			}
			return OfflineResult{}, shared.NewError(shared.InvalidArgument, shared.InvalidPCAP, "read PCAPNG block header: "+err.Error())
		}
		blockType := binary.LittleEndian.Uint32(header[:4])
		if blockType == 0x0a0d0d0a { // Section Header has a byte-order magic.
			byteOrderMagic := make([]byte, 4)
			if _, err := io.ReadFull(reader, byteOrderMagic); err != nil {
				return OfflineResult{}, shared.NewError(shared.InvalidArgument, shared.InvalidPCAP, "read PCAPNG byte-order magic: "+err.Error())
			}
			if bytes.Equal(byteOrderMagic, []byte{0x4d, 0x3c, 0x2b, 0x1a}) {
				order = binary.LittleEndian
			} else if bytes.Equal(byteOrderMagic, []byte{0x1a, 0x2b, 0x3c, 0x4d}) {
				order = binary.BigEndian
			} else {
				return OfflineResult{}, shared.NewError(shared.InvalidArgument, shared.InvalidPCAP, "invalid PCAPNG byte-order magic")
			}
			length := order.Uint32(header[4:])
			if length < 28 || length > 16<<20 || length%4 != 0 {
				return OfflineResult{}, shared.NewError(shared.InvalidArgument, shared.InvalidPCAP, "invalid PCAPNG section length")
			}
			body := append(byteOrderMagic, make([]byte, length-12)...)
			if _, err := io.ReadFull(reader, body[4:]); err != nil {
				return OfflineResult{}, shared.NewError(shared.InvalidArgument, shared.InvalidPCAP, "read PCAPNG section: "+err.Error())
			}
			if order.Uint32(body[len(body)-4:]) != length {
				return OfflineResult{}, shared.NewError(shared.InvalidArgument, shared.InvalidPCAP, "PCAPNG section length mismatch")
			}
			interfaces = map[uint32]uint16{}
			continue
		}
		if order == nil {
			return OfflineResult{}, shared.NewError(shared.InvalidArgument, shared.InvalidPCAP, "PCAPNG is missing a section header")
		}
		length := order.Uint32(header[4:])
		if length < 12 || length > 16<<20 || length%4 != 0 {
			return OfflineResult{}, shared.NewError(shared.InvalidArgument, shared.InvalidPCAP, "invalid PCAPNG block length")
		}
		body := make([]byte, length-8)
		if _, err := io.ReadFull(reader, body); err != nil {
			return OfflineResult{}, shared.NewError(shared.InvalidArgument, shared.InvalidPCAP, "read PCAPNG block: "+err.Error())
		}
		if order.Uint32(body[len(body)-4:]) != length {
			return OfflineResult{}, shared.NewError(shared.InvalidArgument, shared.InvalidPCAP, "PCAPNG block length mismatch")
		}
		content := body[:len(body)-4]
		switch blockType {
		case 1: // Interface Description Block
			if len(content) < 8 {
				return OfflineResult{}, shared.NewError(shared.InvalidArgument, shared.InvalidPCAP, "truncated PCAPNG interface block")
			}
			interfaces[uint32(len(interfaces))] = order.Uint16(content[:2])
		case 6: // Enhanced Packet Block
			if len(content) < 20 {
				return OfflineResult{}, shared.NewError(shared.InvalidArgument, shared.InvalidPCAP, "truncated PCAPNG packet block")
			}
			interfaceID, capturedLength := order.Uint32(content[:4]), order.Uint32(content[12:16])
			if capturedLength > 16<<20 || int(capturedLength) > len(content)-20 {
				return OfflineResult{}, shared.NewError(shared.InvalidArgument, shared.InvalidPCAP, "invalid PCAPNG captured length")
			}
			timestamp := (uint64(order.Uint32(content[4:8])) << 32) | uint64(order.Uint32(content[8:12]))
			updated, observeErr := observeOfflinePacket(ctx, result, content[20:20+capturedLength], interfaces[interfaceID], time.Unix(0, int64(timestamp)*1000).UTC(), sessionID, observer)
			if observeErr != nil {
				return OfflineResult{}, observeErr
			}
			result = updated
		case 3: // Simple Packet Block, no timestamp/interface. Use interface zero.
			if len(content) < 4 {
				return OfflineResult{}, shared.NewError(shared.InvalidArgument, shared.InvalidPCAP, "truncated PCAPNG simple packet")
			}
			originalLength := order.Uint32(content[:4])
			data := content[4:]
			if originalLength < uint32(len(data)) {
				data = data[:originalLength]
			}
			updated, observeErr := observeOfflinePacket(ctx, result, data, interfaces[0], time.Time{}, sessionID, observer)
			if observeErr != nil {
				return OfflineResult{}, observeErr
			}
			result = updated
		}
	}
}

func observeOfflinePacket(ctx context.Context, result OfflineResult, packet []byte, linkType uint16, seenAt time.Time, sessionID string, observer PacketObserver) (OfflineResult, error) {
	if result.FirstSeen.IsZero() && !seenAt.IsZero() {
		result.FirstSeen = seenAt
	}
	if !seenAt.IsZero() {
		result.LastSeen = seenAt
	}
	result.Counters.PacketsTotal++
	result.Counters.BytesTotal += uint64(len(packet))
	metadata, decoded := decodePacketMetadataLink(packet, uint64(len(packet)), seenAt, linkType)
	if decoded {
		classifyMetadata(metadata, &result.Counters)
		if observer != nil {
			metadata.SessionID = sessionID
			if err := observer(ctx, metadata); err != nil {
				return OfflineResult{}, err
			}
		}
	}
	return result, nil
}

func decodePacketMetadata(packet []byte, length uint64, seenAt time.Time) (PacketMetadata, bool) {
	return decodePacketMetadataLink(packet, length, seenAt, 1)
}
func decodePacketMetadataLink(packet []byte, length uint64, seenAt time.Time, linkType uint16) (PacketMetadata, bool) {
	protocol, payload, source, destination, ok := networkPayloadLink(packet, linkType)
	if !ok {
		return PacketMetadata{}, false
	}
	m := PacketMetadata{Protocol: protocol, SourceAddress: source, DestinationAddress: destination, Length: length, SeenAt: seenAt}
	if protocol == 17 && len(payload) >= 8 {
		m.SourcePort = binary.BigEndian.Uint16(payload[:2])
		m.DestinationPort = binary.BigEndian.Uint16(payload[2:4])
		udpPayload := payload[8:]
		switch {
		case m.SourcePort == 500 || m.DestinationPort == 500:
			m.IKE = true
			parseIKE(&m, udpPayload)
		case m.SourcePort == 4500 || m.DestinationPort == 4500:
			m.NATT = true
			switch {
			case len(udpPayload) == 1 && udpPayload[0] == 0xff:
				m.NATKeepalive = true
			case len(udpPayload) >= 4 && bytes.Equal(udpPayload[:4], []byte{0, 0, 0, 0}):
				m.IKE = true
				parseIKE(&m, udpPayload[4:])
			case len(udpPayload) >= 4:
				m.EncapsulatedESP = true
				m.SPI = binary.BigEndian.Uint32(udpPayload[:4])
			}
		}
	}
	if protocol == 50 && len(payload) >= 4 {
		m.SPI = binary.BigEndian.Uint32(payload[:4])
	}
	if protocol == 51 && len(payload) >= 8 {
		m.SPI = binary.BigEndian.Uint32(payload[4:8])
	}
	return m, true
}
func setIKESPIs(metadata *PacketMetadata, payload []byte) {
	if len(payload) < 16 {
		return
	}
	metadata.IKEInitiatorSPI = binary.BigEndian.Uint64(payload[:8])
	metadata.IKEResponderSPI = binary.BigEndian.Uint64(payload[8:16])
	if len(payload) < 28 {
		return
	}
	declaredLength := binary.BigEndian.Uint32(payload[24:28])
	if declaredLength < 28 || uint64(declaredLength) > uint64(len(payload)) {
		return
	}
	major, minor := payload[17]>>4, payload[17]&0x0f
	if major == 1 || major == 2 {
		metadata.IKEVersion = "IKEv" + strconv.Itoa(int(major)) + "." + strconv.Itoa(int(minor))
	}
	metadata.IKEExchangeType = payload[18]
	metadata.IKEFlags = payload[19]
	metadata.IKEMessageID = binary.BigEndian.Uint32(payload[20:24])
}

// parseIKE recognizes the clear-text, length-delimited portion of IKEv1/v2.
// It is intentionally conservative: malformed payloads simply stop parsing
// and encrypted payload bodies are never read.
func parseIKE(metadata *PacketMetadata, payload []byte) {
	setIKESPIs(metadata, payload)
	if len(payload) < 28 {
		return
	}
	declared := int(binary.BigEndian.Uint32(payload[24:28]))
	if declared < 28 || declared > len(payload) {
		return
	}
	major := payload[17] >> 4
	firstPayload := payload[16]
	if major == 2 {
		// IKEv2 bit 0x20 is the RESPONSE flag, not an encryption flag. The
		// payload chain below marks encryption only when it reaches SK/SKF.
		parseIKEv2Payloads(metadata, firstPayload, payload[28:declared])
		return
	}
	if major == 1 {
		if payload[19]&0x01 != 0 { // IKEv1 encrypted flag.
			metadata.IKEPayloadEncrypted = true
			return
		}
		parseIKEv1Payloads(metadata, firstPayload, payload[28:declared])
	}
}

func parseIKEv2Payloads(metadata *PacketMetadata, kind uint8, body []byte) {
	for len(body) >= 4 && kind != 0 {
		next, length := body[0], int(binary.BigEndian.Uint16(body[2:4]))
		if length < 4 || length > len(body) {
			return
		}
		payload := body[4:length]
		switch kind {
		case 33: // SA
			parseIKEv2SA(metadata, payload)
		case 39: // AUTH
			if len(payload) > 0 {
				metadata.IKEAuthMethods = appendUnique(metadata.IKEAuthMethods, ikeAuthName(payload[0]))
			}
		case 37: // CERT
			if len(payload) > 0 {
				metadata.IKECertificateTypes = appendUnique(metadata.IKECertificateTypes, certificateName(payload[0]))
			}
		case 44, 45: // TSi/TSr
			parseTrafficSelectors(metadata, payload)
		case 46, 53: // SK/SKF: ciphertext begins after its generic header.
			metadata.IKEPayloadEncrypted = true
			return
		}
		kind, body = next, body[length:]
	}
}

func parseIKEv2SA(metadata *PacketMetadata, body []byte) {
	for len(body) >= 8 {
		next, length := body[0], int(binary.BigEndian.Uint16(body[2:4]))
		if length < 8 || length > len(body) {
			return
		}
		proposalNumber, protocolID, spiSize := body[4], body[5], int(body[6])
		transforms := int(body[7])
		if 8+spiSize > length {
			return
		}
		proposal := IKEProposal{Number: proposalNumber, ProtocolID: protocolID, SPI: fmt.Sprintf("%x", body[8:8+spiSize]), Selected: metadata.IKEFlags&0x20 != 0}
		part := body[8+spiSize : length]
		for i := 0; i < transforms && len(part) >= 8; i++ {
			tNext, tLen := part[0], int(binary.BigEndian.Uint16(part[2:4]))
			if tLen < 8 || tLen > len(part) {
				return
			}
			transformType, transformID := part[4], binary.BigEndian.Uint16(part[6:8])
			transform := proposalTransform(part[8:tLen], transformType, transformID)
			proposal.Transforms = append(proposal.Transforms, transform)
			// Retain legacy packet fields for callers that only need an offer
			// inventory. Pipeline evidence uses IKEProposals and never promotes
			// an offer into a negotiated configuration fact.
			addTransform(metadata, transform)
			part = part[tLen:]
			if tNext == 0 && i+1 < transforms {
				return
			}
		}
		metadata.IKEProposals = append(metadata.IKEProposals, proposal)
		body = body[length:]
		if next == 0 {
			return
		}
	}
}

func parseIKEv1Payloads(metadata *PacketMetadata, kind uint8, body []byte) {
	for len(body) >= 4 && kind != 0 {
		next, length := body[0], int(binary.BigEndian.Uint16(body[2:4]))
		if length < 4 || length > len(body) {
			return
		}
		payload := body[4:length]
		switch kind {
		case 1:
			parseIKEv1SA(metadata, payload)
		case 6:
			if len(payload) > 0 {
				metadata.IKECertificateTypes = appendUnique(metadata.IKECertificateTypes, certificateName(payload[0]))
			}
		case 8, 9:
			metadata.IKEAuthMethods = appendUnique(metadata.IKEAuthMethods, "IKEv1_AUTH")
		}
		kind, body = next, body[length:]
	}
}

func parseIKEv1SA(metadata *PacketMetadata, body []byte) {
	if len(body) < 8 {
		return
	} // DOI and situation.
	body = body[8:]
	for len(body) >= 8 {
		next, length := body[0], int(binary.BigEndian.Uint16(body[2:4]))
		if length < 8 || length > len(body) {
			return
		}
		// ISAKMP proposal payload: proposal #, protocol, SPI size, transform count.
		proposalNumber, protocolID := body[4], body[5]
		spiSize, transforms := int(body[6]), int(body[7])
		if 8+spiSize > length {
			return
		}
		proposal := IKEProposal{Number: proposalNumber, ProtocolID: protocolID, SPI: fmt.Sprintf("%x", body[8:8+spiSize])}
		part := body[8+spiSize : length]
		for i := 0; i < transforms && len(part) >= 8; i++ {
			tNext, tLen := part[0], int(binary.BigEndian.Uint16(part[2:4]))
			if tLen < 8 || tLen > len(part) {
				return
			}
			// IKEv1 transform IDs identify the transform payload itself. The
			// cryptographic suite is carried by ISAKMP attributes inside it.
			proposal.Transforms = append(proposal.Transforms, parseIKEv1Attributes(metadata, part[8:tLen])...)
			part = part[tLen:]
			if tNext == 0 && i+1 < transforms {
				return
			}
		}
		metadata.IKEProposals = append(metadata.IKEProposals, proposal)
		body = body[length:]
		if next == 0 {
			return
		}
	}
}

func parseIKEv1Attributes(metadata *PacketMetadata, attributes []byte) []IKETransform {
	var encryptionID, keyLength uint16
	transforms := make([]IKETransform, 0, 4)
	for len(attributes) >= 4 {
		typeAndFlag, value := binary.BigEndian.Uint16(attributes[:2]), binary.BigEndian.Uint16(attributes[2:4])
		attributeType := typeAndFlag & 0x7fff
		if typeAndFlag&0x8000 == 0 { // variable length attribute
			length := int(value)
			if length > len(attributes)-4 {
				return transforms
			}
			// Life Duration and other variable-length attributes are not
			// cryptographic identifiers. Skip their bounded value.
			attributes = attributes[4+length:]
			continue
		}
		switch attributeType {
		case 1: // Encryption Algorithm (RFC 2409 Appendix A).
			encryptionID = value
		case 2: // Hash Algorithm.
			name := ikev1HashName(value)
			metadata.IKEIntegrityAlgorithms = appendUnique(metadata.IKEIntegrityAlgorithms, name)
			transforms = append(transforms, IKETransform{Type: 3, ID: value, Name: name})
		case 3: // Authentication Method.
			metadata.IKEAuthMethods = appendUnique(metadata.IKEAuthMethods, ikev1AuthName(value))
		case 4: // Group Description.
			name := ikeTransformName(4, value, 0)
			metadata.IKEDHGroups = appendUnique(metadata.IKEDHGroups, name)
			transforms = append(transforms, IKETransform{Type: 4, ID: value, Name: name})
		case 14: // Key Length.
			keyLength = value
		}
		attributes = attributes[4:]
	}
	if encryptionID != 0 {
		name := ikev1EncryptionName(encryptionID, keyLength)
		metadata.IKEEncryptionAlgorithms = appendUnique(metadata.IKEEncryptionAlgorithms, name)
		transforms = append(transforms, IKETransform{Type: 1, ID: encryptionID, Name: name, KeyLengthBits: keyLength})
	}
	return transforms
}

func ikev1EncryptionName(id, keyLength uint16) string {
	name := map[uint16]string{1: "DES-CBC", 2: "IDEA-CBC", 3: "BLOWFISH-CBC", 4: "RC5-CBC", 5: "3DES-CBC", 6: "CAST-CBC", 7: "AES-CBC"}[id]
	if name == "" {
		name = fmt.Sprintf("IKEV1-ENCR-%d", id)
	}
	if keyLength != 0 && (id == 7 || id == 6) {
		return fmt.Sprintf("%s-%d", name, keyLength)
	}
	return name
}

func ikev1HashName(id uint16) string {
	if name := map[uint16]string{1: "HMAC-MD5", 2: "HMAC-SHA1", 4: "HMAC-SHA2-256", 5: "HMAC-SHA2-384", 6: "HMAC-SHA2-512"}[id]; name != "" {
		return name
	}
	return fmt.Sprintf("IKEV1-HASH-%d", id)
}

func ikev1AuthName(id uint16) string {
	if name := map[uint16]string{1: "PSK", 3: "RSA-SIGNATURE", 9: "ECDSA-SHA256", 10: "ECDSA-SHA384", 11: "ECDSA-SHA512"}[id]; name != "" {
		return name
	}
	return fmt.Sprintf("IKEV1-AUTH-%d", id)
}

func parseTrafficSelectors(metadata *PacketMetadata, body []byte) {
	if len(body) < 4 {
		return
	}
	count := int(body[0])
	body = body[4:]
	for i := 0; i < count && len(body) >= 8; i++ {
		typeID, protocol, length := body[0], body[1], int(binary.BigEndian.Uint16(body[2:4]))
		if length < 8 || length > len(body) {
			return
		}
		startPort, endPort := binary.BigEndian.Uint16(body[4:6]), binary.BigEndian.Uint16(body[6:8])
		addresses := body[8:length]
		addressLength := 0
		if typeID == 7 {
			addressLength = 4
		} else if typeID == 8 {
			addressLength = 16
		}
		if addressLength > 0 && len(addresses) == 2*addressLength {
			metadata.IKETrafficSelectors = appendUnique(metadata.IKETrafficSelectors, fmt.Sprintf("proto=%d ports=%d-%d", protocol, startPort, endPort))
		}
		body = body[length:]
	}
}

func addTransform(metadata *PacketMetadata, transform IKETransform) {
	value := transform.Name
	switch transform.Type {
	case 1:
		metadata.IKEEncryptionAlgorithms = appendUnique(metadata.IKEEncryptionAlgorithms, value)
	case 2:
		metadata.IKEPRFs = appendUnique(metadata.IKEPRFs, value)
	case 3:
		metadata.IKEIntegrityAlgorithms = appendUnique(metadata.IKEIntegrityAlgorithms, value)
	case 4:
		metadata.IKEDHGroups = appendUnique(metadata.IKEDHGroups, value)
	}
}
func appendUnique(values []string, value string) []string {
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
func ikeAuthName(value byte) string     { return "AUTH_" + strconv.Itoa(int(value)) }
func certificateName(value byte) string { return "CERT_" + strconv.Itoa(int(value)) }

type pcapFormat struct {
	order      binary.ByteOrder
	nanosecond bool
}

func pcapFormatForMagic(magic []byte) (pcapFormat, bool) {
	switch string(magic) {
	case "\xd4\xc3\xb2\xa1":
		return pcapFormat{order: binary.LittleEndian}, true
	case "\x4d\x3c\xb2\xa1":
		return pcapFormat{order: binary.LittleEndian, nanosecond: true}, true
	case "\xa1\xb2\xc3\xd4":
		return pcapFormat{order: binary.BigEndian}, true
	case "\xa1\xb2\x3c\x4d":
		return pcapFormat{order: binary.BigEndian, nanosecond: true}, true
	default:
		return pcapFormat{}, false
	}
}
func classify(packet []byte, counters *Counters) {
	metadata, ok := decodePacketMetadata(packet, uint64(len(packet)), time.Time{})
	if !ok {
		return
	}
	classifyMetadata(metadata, counters)
}
func classifyMetadata(metadata PacketMetadata, counters *Counters) {
	if metadata.NATT {
		counters.NATTPackets++
	}
	if metadata.IKE {
		counters.IKEPackets++
	}
	switch metadata.Protocol {
	case 50:
		counters.ESPPackets++
	case 51:
		counters.AHPackets++
	}
	if metadata.EncapsulatedESP {
		counters.ESPPackets++
	}
}

func networkPayload(packet []byte) (uint8, []byte, string, string, bool) {
	return networkPayloadLink(packet, 1)
}
func networkPayloadLink(packet []byte, linkType uint16) (uint8, []byte, string, string, bool) {
	if linkType == 101 { // DLT_RAW
		if len(packet) == 0 {
			return 0, nil, "", "", false
		}
		if packet[0]>>4 == 4 {
			packet = append([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0}, packet...)
		} else if packet[0]>>4 == 6 {
			packet = append([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x86, 0xdd}, packet...)
		} else {
			return 0, nil, "", "", false
		}
	}
	if linkType != 0 && linkType != 1 && linkType != 101 {
		return 0, nil, "", "", false
	}
	if len(packet) < 14 {
		return 0, nil, "", "", false
	}
	offset, etherType := 14, binary.BigEndian.Uint16(packet[12:14])
	for etherType == 0x8100 || etherType == 0x88a8 {
		if len(packet) < offset+4 {
			return 0, nil, "", "", false
		}
		etherType = binary.BigEndian.Uint16(packet[offset+2 : offset+4])
		offset += 4
	}
	switch etherType {
	case 0x0800:
		if len(packet) < offset+20 {
			return 0, nil, "", "", false
		}
		ihl := int(packet[offset]&15) * 4
		if ihl < 20 || len(packet) < offset+ihl {
			return 0, nil, "", "", false
		}
		source := netip.AddrFrom4([4]byte(packet[offset+12 : offset+16])).String()
		destination := netip.AddrFrom4([4]byte(packet[offset+16 : offset+20])).String()
		return packet[offset+9], packet[offset+ihl:], source, destination, true
	case 0x86dd:
		if len(packet) < offset+40 {
			return 0, nil, "", "", false
		}
		source := netip.AddrFrom16([16]byte(packet[offset+8 : offset+24])).String()
		destination := netip.AddrFrom16([16]byte(packet[offset+24 : offset+40])).String()
		next, payload := packet[offset+6], packet[offset+40:]
		for {
			switch next {
			case 0, 43, 60: // Hop-by-Hop, Routing, Destination Options.
				if len(payload) < 2 {
					return 0, nil, "", "", false
				}
				headerLength := (int(payload[1]) + 1) * 8
				if len(payload) < headerLength {
					return 0, nil, "", "", false
				}
				next, payload = payload[0], payload[headerLength:]
			case 44: // Fragment header; only the first fragment has a transport header.
				if len(payload) < 8 || binary.BigEndian.Uint16(payload[2:4])&0xfff8 != 0 {
					return 0, nil, "", "", false
				}
				next, payload = payload[0], payload[8:]
			default:
				return next, payload, source, destination, true
			}
		}
	default:
		return 0, nil, "", "", false
	}
}

var dropsPattern = regexp.MustCompile(`(\d+) packets dropped by kernel`)

func parseDrops(text string) uint64 {
	matches := dropsPattern.FindStringSubmatch(text)
	if len(matches) != 2 {
		return 0
	}
	var value uint64
	for _, digit := range matches[1] {
		value = value*10 + uint64(digit-'0')
	}
	return value
}
