// Package flow aggregates packet metadata into bounded, payload-free telemetry.
package flow

import (
	"context"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	flowv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/flow"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/featurespec"
)

const (
	SequenceSchemaVersion = "sequence.v1"
	maxSequencePackets    = 256
)

var featureSpec = featurespec.MustLoad()
var FeatureSchemaVersion = featureSpec.SchemaVersion
var FeatureNames = append([]string(nil), featureSpec.Features...)
var defaultWindowDuration = time.Duration(featureSpec.WindowSeconds * float64(time.Second))
var defaultBurstGap = time.Duration(featureSpec.BurstGapSeconds * float64(time.Second))
var defaultIdleGap = time.Duration(featureSpec.IdleGapSeconds * float64(time.Second))

type Config struct {
	WindowDuration time.Duration
	BurstGap       time.Duration
	IdleGap        time.Duration
}

type Packet struct {
	SessionID                         string
	Protocol                          flowv1.FlowProtocol
	SourceAddress, DestinationAddress string
	SourcePort, DestinationPort, SPI  uint32
	Size                              uint64
	SeenAt                            time.Time
}
type Warning struct {
	SessionID, Reason string
	Count             uint64
	At                time.Time
}
type packet struct {
	size    int64
	at      time.Time
	forward bool
}
type aggregate struct {
	count, bytes, forwardPackets, reversePackets, forwardBytes, reverseBytes, min, max uint64
	mean, m2                                                                           float64
	first, last, lastPacket                                                            time.Time
	iaMean, iaM2                                                                       float64
	iaCount, bursts, burstPackets, idles                                               uint64
	idleTotal                                                                          time.Duration
}
type record struct {
	id                string
	key               string
	session           string
	protocol          flowv1.FlowProtocol
	src, dst          string
	sport, dport, spi uint32
	stats             aggregate
	spis              map[uint32]struct{}
	active            bool
	pending           []packet
	windows           []string
}
type window struct {
	id, flowID, sessionID, reason string
	aggregationScope              string
	start, end                    time.Time
	burstGap, idleGap             time.Duration
	finalized                     bool
	packets                       []packet
}

func (w *window) IsFinalized() bool { return w.finalized }
func (w *window) IsMLReady() bool {
	return w.finalized && len(w.packets) >= 2 && w.end.After(w.start)
}

type subscriber struct {
	session string
	policy  flowv1.FeatureBackpressurePolicy
	ch      chan string
	done    chan struct{}
	once    sync.Once
}
type Service struct {
	mu             sync.RWMutex
	flows          map[string]*record
	byKey          map[string]string
	windows        map[string]*window
	subscribers    map[*subscriber]struct{}
	warnings       []Warning
	windowDuration time.Duration
	burstGap       time.Duration
	idleGap        time.Duration
}

func New(config Config) *Service {
	if config.WindowDuration <= 0 {
		config.WindowDuration = defaultWindowDuration
	}
	if config.BurstGap <= 0 {
		config.BurstGap = defaultBurstGap
	}
	if config.WindowDuration <= config.BurstGap {
		config.WindowDuration = defaultWindowDuration
	}
	if config.IdleGap <= config.BurstGap || config.IdleGap > config.WindowDuration {
		config.IdleGap = defaultIdleGap
		if config.IdleGap > config.WindowDuration {
			config.IdleGap = config.WindowDuration
		}
	}
	return &Service{flows: map[string]*record{}, byKey: map[string]string{}, windows: map[string]*window{}, subscribers: map[*subscriber]struct{}{}, windowDuration: config.WindowDuration, burstGap: config.BurstGap, idleGap: config.IdleGap}
}
func (s *Service) ObservePacket(ctx context.Context, p Packet) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if strings.TrimSpace(p.SessionID) == "" || strings.TrimSpace(p.SourceAddress) == "" || strings.TrimSpace(p.DestinationAddress) == "" || p.Protocol == flowv1.FlowProtocol_FLOW_PROTOCOL_UNSPECIFIED {
		return "", shared.NewError(shared.InvalidArgument, "", "session, protocol and addresses are required")
	}
	if p.SeenAt.IsZero() {
		p.SeenAt = time.Now().UTC()
	} else {
		p.SeenAt = p.SeenAt.UTC()
	}
	key := flowKey(p)
	s.mu.Lock()
	id := s.byKey[key]
	r := s.flows[id]
	if r == nil {
		fid, e := shared.NewFlowID()
		if e != nil {
			s.mu.Unlock()
			return "", shared.NewError(shared.Internal, "", "could not create flow")
		}
		r = &record{id: string(fid), key: key, session: p.SessionID, protocol: p.Protocol, src: p.SourceAddress, dst: p.DestinationAddress, sport: p.SourcePort, dport: p.DestinationPort, spi: p.SPI, spis: make(map[uint32]struct{}), active: true}
		s.flows[r.id] = r
		s.byKey[key] = r.id
	}
	if p.SPI != 0 {
		r.spis[p.SPI] = struct{}{}
	}
	forward := p.SourceAddress == r.src && p.DestinationAddress == r.dst && p.SourcePort == r.sport && p.DestinationPort == r.dport
	var ready *window
	if len(r.pending) > 0 && windowBucket(p.SeenAt, r.stats.first, s.windowDuration) > windowBucket(r.pending[0].at, r.stats.first, s.windowDuration) {
		ready = s.finalizeLocked(r, "WINDOW_DURATION")
	}
	update(&r.stats, p, forward, s.burstGap, s.idleGap)
	signed := int64(p.Size)
	if !forward {
		signed = -signed
	}
	r.pending = append(r.pending, packet{size: signed, at: p.SeenAt, forward: forward})
	s.mu.Unlock()
	if ready != nil {
		s.publish(ready)
	}
	return r.id, nil
}

func windowBucket(at, anchor time.Time, duration time.Duration) int64 {
	if duration <= 0 || at.Before(anchor) {
		return 0
	}
	return int64(at.Sub(anchor) / duration)
}
func flowKey(p Packet) string {
	a := p.SourceAddress + ":" + strconv.FormatUint(uint64(p.SourcePort), 10)
	b := p.DestinationAddress + ":" + strconv.FormatUint(uint64(p.DestinationPort), 10)
	if b < a {
		a, b = b, a
	}
	// ESP SAs are directional and opposite directions normally use different
	// SPIs. SPI is retained as protocol evidence but excluded from the
	// bidirectional ML-flow key.
	return p.SessionID + "|" + strconv.Itoa(int(p.Protocol)) + "|" + a + "|" + b
}
func update(a *aggregate, p Packet, forward bool, burstGap, idleGap time.Duration) {
	if a.count == 0 {
		a.first = p.SeenAt
		a.min = p.Size
	}
	a.last = p.SeenAt
	a.count++
	a.bytes += p.Size
	if p.Size < a.min {
		a.min = p.Size
	}
	if p.Size > a.max {
		a.max = p.Size
	}
	d := float64(p.Size) - a.mean
	a.mean += d / float64(a.count)
	a.m2 += d * (float64(p.Size) - a.mean)
	if forward {
		a.forwardPackets++
		a.forwardBytes += p.Size
	} else {
		a.reversePackets++
		a.reverseBytes += p.Size
	}
	if !a.lastPacket.IsZero() {
		ia := p.SeenAt.Sub(a.lastPacket)
		if ia < 0 {
			ia = 0
		}
		us := float64(ia.Microseconds())
		a.iaCount++
		d = us - a.iaMean
		a.iaMean += d / float64(a.iaCount)
		a.iaM2 += d * (us - a.iaMean)
		if ia >= idleGap {
			a.idles++
			a.idleTotal += ia
		}
		if ia > burstGap {
			a.bursts++
			a.burstPackets = 1
		} else {
			a.burstPackets++
		}
	} else {
		a.bursts = 1
		a.burstPackets = 1
	}
	a.lastPacket = p.SeenAt
}
func (s *Service) finalizeLocked(r *record, reason string) *window {
	if len(r.pending) == 0 {
		return nil
	}
	id, e := shared.NewProtocolEventID()
	if e != nil {
		return nil
	}
	p := append([]packet(nil), r.pending...)
	scope := "aggregate_endpoint_channel_estimate"
	forward, reverse := false, false
	for _, packet := range p {
		forward = forward || packet.forward
		reverse = reverse || !packet.forward
	}
	if forward && reverse && len(r.spis) >= 2 {
		scope = "paired_bidirectional_sa_channel"
	}
	w := &window{id: string(id), flowID: r.id, sessionID: r.session, reason: reason, aggregationScope: scope, start: p[0].at, end: p[len(p)-1].at, burstGap: s.burstGap, idleGap: s.idleGap, finalized: true, packets: p}
	s.windows[w.id] = w
	r.windows = append(r.windows, w.id)
	r.pending = nil
	return w
}
func (s *Service) FinalizeFlow(ctx context.Context, id, reason string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	r := s.flows[id]
	if r == nil {
		s.mu.Unlock()
		return shared.NewError(shared.NotFound, "", "flow was not found")
	}
	r.active = false
	w := s.finalizeLocked(r, reason)
	s.mu.Unlock()
	if w != nil {
		s.publish(w)
	}
	return nil
}
func (s *Service) StopForSession(ctx context.Context, sessionID string) error {
	return s.closeSession(ctx, sessionID, "SESSION_STOPPED", false)
}
func (s *Service) ResetForSession(ctx context.Context, sessionID string, _ bool) error {
	return s.closeSession(ctx, sessionID, "SESSION_RESET", true)
}
func (s *Service) closeSession(ctx context.Context, sessionID, reason string, remove bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var out []*window
	s.mu.Lock()
	for id, r := range s.flows {
		if r.session != sessionID {
			continue
		}
		r.active = false
		if w := s.finalizeLocked(r, reason); w != nil {
			out = append(out, w)
		}
		if remove {
			delete(s.byKey, r.key)
			delete(s.flows, id)
		}
	}
	for sub := range s.subscribers {
		if sub.session == sessionID {
			sub.once.Do(func() { close(sub.done); close(sub.ch) })
			delete(s.subscribers, sub)
		}
	}
	if remove {
		for id, w := range s.windows {
			if w.sessionID == sessionID {
				delete(s.windows, id)
			}
		}
	}
	s.mu.Unlock()
	for _, w := range out {
		s.publish(w)
	}
	return nil
}
func (s *Service) List(ctx context.Context, req *flowv1.ListFlowsRequest) ([]*record, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	if req == nil {
		return nil, "", shared.NewError(shared.InvalidArgument, "", "request is required")
	}
	s.mu.RLock()
	items := make([]*record, 0, len(s.flows))
	for _, r := range s.flows {
		if req.GetSensorSessionId() != "" && r.session != req.GetSensorSessionId() {
			continue
		}
		if req.GetProtocol() != flowv1.FlowProtocol_FLOW_PROTOCOL_UNSPECIFIED && r.protocol != req.GetProtocol() {
			continue
		}
		if req.GetSpi() != 0 {
			if _, ok := r.spis[req.GetSpi()]; !ok {
				continue
			}
		}
		if req.GetSourceAddress() != "" && r.src != req.GetSourceAddress() {
			continue
		}
		if req.GetDestinationAddress() != "" && r.dst != req.GetDestinationAddress() {
			continue
		}
		if req.Active != nil && r.active != req.GetActive() {
			continue
		}
		c := *r
		items = append(items, &c)
	}
	s.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool { return items[i].id < items[j].id })
	return page(items, req.GetPageSize(), req.GetPageToken(), func(x *record) string { return x.id })
}
func page[T any](in []T, size uint32, token string, id func(T) string) ([]T, string, error) {
	if size == 0 {
		size = 100
	}
	if size > 1000 {
		return nil, "", shared.NewError(shared.InvalidArgument, "", "page_size must not exceed 1000")
	}
	start := 0
	if token != "" {
		for start < len(in) && id(in[start]) <= token {
			start++
		}
	}
	end := start + int(size)
	if end > len(in) {
		end = len(in)
	}
	next := ""
	if end < len(in) {
		next = id(in[end-1])
	}
	return in[start:end], next, nil
}
func (s *Service) Flow(ctx context.Context, id string) (*record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	r := s.flows[id]
	if r != nil {
		c := *r
		r = &c
	}
	s.mu.RUnlock()
	if r == nil {
		return nil, shared.NewError(shared.NotFound, "", "flow was not found")
	}
	return r, nil
}
func (s *Service) Window(ctx context.Context, id string) (*window, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	w := s.windows[id]
	if w != nil {
		c := *w
		c.packets = append([]packet(nil), w.packets...)
		w = &c
	}
	s.mu.RUnlock()
	if w == nil {
		return nil, shared.NewError(shared.NotFound, "", "feature window was not found")
	}
	return w, nil
}
func (s *Service) Windows(ctx context.Context, flowID string, size uint32, token string) ([]*window, string, error) {
	r, e := s.Flow(ctx, flowID)
	if e != nil {
		return nil, "", e
	}
	s.mu.RLock()
	out := make([]*window, 0, len(r.windows))
	for _, id := range r.windows {
		if w := s.windows[id]; w != nil {
			c := *w
			out = append(out, &c)
		}
	}
	s.mu.RUnlock()
	return page(out, size, token, func(w *window) string { return w.id })
}
func (s *Service) Subscribe(ctx context.Context, session string, policy flowv1.FeatureBackpressurePolicy, buffer uint32) (<-chan string, func(), error) {
	if strings.TrimSpace(session) == "" {
		return nil, nil, shared.NewError(shared.InvalidArgument, "", "sensor_session_id is required")
	}
	if buffer == 0 {
		buffer = 32
	}
	if buffer > 1024 {
		return nil, nil, shared.NewError(shared.InvalidArgument, "", "buffer_size must not exceed 1024")
	}
	if policy == flowv1.FeatureBackpressurePolicy_FEATURE_BACKPRESSURE_POLICY_UNSPECIFIED {
		policy = flowv1.FeatureBackpressurePolicy_DROP_FEATURE_WINDOW
	}
	if policy == flowv1.FeatureBackpressurePolicy_BLOCK_CAPTURE {
		return nil, nil, shared.NewError(shared.InvalidArgument, "", "BLOCK_CAPTURE is unsafe and unsupported; use DROP_FEATURE_WINDOW or CANCEL_SESSION")
	}
	sub := &subscriber{session: session, policy: policy, ch: make(chan string, buffer), done: make(chan struct{})}
	s.mu.Lock()
	s.subscribers[sub] = struct{}{}
	s.mu.Unlock()
	cancel := func() {
		s.mu.Lock()
		if _, ok := s.subscribers[sub]; ok {
			delete(s.subscribers, sub)
			sub.once.Do(func() { close(sub.done); close(sub.ch) })
		}
		s.mu.Unlock()
	}
	go func() {
		select {
		case <-ctx.Done():
			cancel()
		case <-sub.done:
		}
	}()
	return sub.ch, cancel, nil
}
func (s *Service) publish(w *window) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !w.IsMLReady() {
		s.warnings = append(s.warnings, Warning{SessionID: w.sessionID, Reason: "INSUFFICIENT_WINDOW_DATA", Count: 1, At: time.Now().UTC()})
		return
	}
	for sub := range s.subscribers {
		if sub.session != w.sessionID {
			continue
		}
		select {
		case sub.ch <- w.id:
		default:
			s.warnings = append(s.warnings, Warning{SessionID: w.sessionID, Reason: "FEATURE_STREAM_BACKPRESSURE", Count: 1, At: time.Now().UTC()})
			if sub.policy == flowv1.FeatureBackpressurePolicy_CANCEL_SESSION {
				sub.once.Do(func() { close(sub.done); close(sub.ch) })
				delete(s.subscribers, sub)
			}
		}
	}
}
func (s *Service) Warnings() []Warning {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Warning(nil), s.warnings...)
}

func (s *Service) RuntimeCounts() (activeFlows, pendingPackets, subscribers uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, record := range s.flows {
		if record.active {
			activeFlows++
		}
		pendingPackets += uint64(len(record.pending))
	}
	return activeFlows, pendingPackets, uint64(len(s.subscribers))
}
func ToProto(r *record) *flowv1.Flow {
	return &flowv1.Flow{FlowId: r.id, SessionId: r.session, Protocol: r.protocol, SourceAddress: r.src, DestinationAddress: r.dst, SourcePort: r.sport, DestinationPort: r.dport, Spi: r.spi, FirstSeen: shared.Timestamp(r.stats.first), LastSeen: shared.Timestamp(r.stats.last), PacketCount: r.stats.count, ByteCount: r.stats.bytes, Active: r.active}
}
func Stats(r *record) *flowv1.FlowStats {
	a := r.stats
	std := 0.0
	if a.count > 1 {
		std = math.Sqrt(a.m2 / float64(a.count))
	}
	ia := 0.0
	if a.iaCount > 1 {
		ia = math.Sqrt(a.iaM2 / float64(a.iaCount))
	}
	meanBurst := 0.0
	if a.bursts > 0 {
		meanBurst = float64(a.count) / float64(a.bursts)
	}
	meanIdle := 0.0
	if a.idles > 0 {
		meanIdle = float64(a.idleTotal.Milliseconds()) / float64(a.idles)
	}
	return &flowv1.FlowStats{FlowId: r.id, PacketCount: a.count, ByteCount: a.bytes, DurationMs: uint64(a.last.Sub(a.first).Milliseconds()), MinPacketSize: a.min, MaxPacketSize: a.max, MeanPacketSize: a.mean, PacketSizeStddev: std, ForwardPackets: a.forwardPackets, ReversePackets: a.reversePackets, ForwardBytes: a.forwardBytes, ReverseBytes: a.reverseBytes, MeanInterarrivalUs: a.iaMean, InterarrivalStddevUs: ia, BurstCount: a.bursts, MeanBurstPackets: meanBurst, IdlePeriodCount: a.idles, MeanIdleMs: meanIdle}
}
func ToFeature(w *window) *flowv1.FeatureWindow {
	f := &flowv1.FeatureWindow{WindowId: w.id, FlowId: w.flowID, SessionId: w.sessionID, WindowStart: shared.Timestamp(w.start), WindowEnd: shared.Timestamp(w.end), FeatureSchemaVersion: FeatureSchemaVersion, SequenceSchemaVersion: SequenceSchemaVersion, NormalizationProfile: "none", DirectionConvention: featureSpec.DirectionConvention, WindowDurationMs: uint64(w.end.Sub(w.start).Milliseconds()), PacketCount: uint64(len(w.packets)), Finalized: w.finalized, EvictionReason: w.reason, AggregationScope: w.aggregationScope}
	f.FeatureNames = append([]string(nil), FeatureNames...)
	f.FeatureValues = featureValues(w)
	return f
}

func featureValues(w *window) []float64 {
	packets := append([]packet(nil), w.packets...)
	sort.SliceStable(packets, func(i, j int) bool { return packets[i].at.Before(packets[j].at) })
	if len(packets) == 0 {
		return make([]float64, len(FeatureNames))
	}
	sizes := make([]float64, 0, len(packets))
	interarrivals := make([]float64, 0, len(packets)-1)
	var totalBytes, uploadBytes, downloadBytes, uploadPackets, downloadPackets float64
	var idleTime float64
	burstCount := 1.0
	for i, p := range packets {
		size := float64(abs(p.size))
		sizes = append(sizes, size)
		totalBytes += size
		if p.forward {
			uploadPackets++
			uploadBytes += size
		} else {
			downloadPackets++
			downloadBytes += size
		}
		if i > 0 {
			gap := p.at.Sub(packets[i-1].at).Seconds()
			if gap < 0 {
				gap = 0
			}
			interarrivals = append(interarrivals, gap)
			if gap > w.burstGap.Seconds() {
				burstCount++
			}
			if gap >= w.idleGap.Seconds() {
				idleTime += gap
			}
		}
	}
	duration := packets[len(packets)-1].at.Sub(packets[0].at).Seconds()
	meanSize, stdSize := populationStats(sizes)
	meanIA, stdIA := populationStats(interarrivals)
	sort.Float64s(sizes)
	packetsPerSecond, bytesPerSecond := 0.0, 0.0
	idleRatio := 0.0
	if duration > 0 {
		packetsPerSecond = float64(len(packets)) / duration
		bytesPerSecond = totalBytes / duration
		idleRatio = math.Min(1, idleTime/duration)
	}
	uploadDownloadRatio := uploadBytes
	if downloadBytes > 0 {
		uploadDownloadRatio = uploadBytes / downloadBytes
	}
	return []float64{
		duration, float64(len(packets)), totalBytes, packetsPerSecond,
		bytesPerSecond, meanSize, stdSize, sizes[0], sizes[len(sizes)-1],
		percentile(sizes, .25), percentile(sizes, .5), percentile(sizes, .75),
		percentile(sizes, .95), meanIA, stdIA, uploadPackets, downloadPackets,
		uploadBytes, downloadBytes, uploadDownloadRatio, burstCount,
		float64(len(packets)) / burstCount, idleRatio,
	}
}

func populationStats(values []float64) (float64, float64) {
	if len(values) == 0 {
		return 0, 0
	}
	var mean, m2 float64
	for i, value := range values {
		delta := value - mean
		mean += delta / float64(i+1)
		m2 += delta * (value - mean)
	}
	return mean, math.Sqrt(m2 / float64(len(values)))
}

func percentile(sortedValues []float64, fraction float64) float64 {
	position := float64(len(sortedValues)-1) * fraction
	lower := int(math.Floor(position))
	upper := lower + 1
	if upper >= len(sortedValues) {
		upper = len(sortedValues) - 1
	}
	return sortedValues[lower] + (sortedValues[upper]-sortedValues[lower])*(position-float64(lower))
}

// CaptureMetrics supplies the capture service with live, in-memory counts.
func (s *Service) CaptureMetrics(ctx context.Context, _ string) (uint64, uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, 0, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var activeFlows uint64
	sessions := make(map[string]struct{})
	for _, record := range s.flows {
		if record.active {
			activeFlows++
			sessions[record.session] = struct{}{}
		}
	}
	return activeFlows, uint64(len(sessions)), nil
}
func abs(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}
func ToSequence(w *window) *flowv1.SequenceSketch {
	x := &flowv1.SequenceSketch{FlowId: w.flowID, WindowId: w.id, SequenceSchemaVersion: SequenceSchemaVersion}
	last := w.start
	for i, p := range w.packets {
		if i >= maxSequencePackets {
			break
		}
		delta := uint64(0)
		if i > 0 && p.at.After(last) {
			delta = uint64(p.at.Sub(last).Microseconds())
		}
		x.Packets = append(x.Packets, &flowv1.SequencePacket{SignedSize: p.size, DeltaTimeUs: delta})
		last = p.at
	}
	return x
}
