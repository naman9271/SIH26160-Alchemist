package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
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
// PCAP; PCAPNG is rejected until a real parser is added.
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

func decodePacketMetadata(packet []byte, length uint64, seenAt time.Time) (PacketMetadata, bool) {
	protocol, payload, source, destination, ok := networkPayload(packet)
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
			setIKESPIs(&m, udpPayload)
		case m.SourcePort == 4500 || m.DestinationPort == 4500:
			m.NATT = true
			switch {
			case len(udpPayload) == 1 && udpPayload[0] == 0xff:
				m.NATKeepalive = true
			case len(udpPayload) >= 4 && bytes.Equal(udpPayload[:4], []byte{0, 0, 0, 0}):
				m.IKE = true
				setIKESPIs(&m, udpPayload[4:])
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
