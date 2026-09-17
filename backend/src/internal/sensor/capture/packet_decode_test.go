package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestDecodeNATTDiscriminatesIKEESPAndKeepalive(t *testing.T) {
	ikePayload := make([]byte, 28)
	binary.BigEndian.PutUint64(ikePayload[:8], 0x0102030405060708)
	binary.BigEndian.PutUint64(ikePayload[8:16], 0x1112131415161718)
	ikePayload[17] = 0x20
	ikePayload[18] = 34
	ikePayload[19] = 0x08
	binary.BigEndian.PutUint32(ikePayload[20:24], 7)
	binary.BigEndian.PutUint32(ikePayload[24:28], uint32(len(ikePayload)))

	tests := []struct {
		name  string
		data  []byte
		check func(t *testing.T, metadata PacketMetadata, counters Counters)
	}{
		{
			name: "IKE with non-ESP marker",
			data: append([]byte{0, 0, 0, 0}, ikePayload...),
			check: func(t *testing.T, metadata PacketMetadata, counters Counters) {
				if !metadata.NATT || !metadata.IKE || metadata.EncapsulatedESP || metadata.SPI != 0 {
					t.Fatalf("unexpected metadata: %+v", metadata)
				}
				if metadata.IKEInitiatorSPI != 0x0102030405060708 || metadata.IKEResponderSPI != 0x1112131415161718 {
					t.Fatalf("IKE SPIs were not decoded as 64-bit values: %+v", metadata)
				}
				if metadata.IKEVersion != "IKEv2.0" || metadata.IKEExchangeType != 34 || metadata.IKEMessageID != 7 {
					t.Fatalf("IKE header fields were not decoded: %+v", metadata)
				}
				if counters.NATTPackets != 1 || counters.IKEPackets != 1 || counters.ESPPackets != 0 {
					t.Fatalf("unexpected counters: %+v", counters)
				}
			},
		},
		{
			name: "UDP encapsulated ESP",
			data: []byte{0x12, 0x34, 0x56, 0x78, 1, 2, 3, 4},
			check: func(t *testing.T, metadata PacketMetadata, counters Counters) {
				if !metadata.NATT || metadata.IKE || !metadata.EncapsulatedESP || metadata.SPI != 0x12345678 {
					t.Fatalf("unexpected metadata: %+v", metadata)
				}
				if counters.NATTPackets != 1 || counters.IKEPackets != 0 || counters.ESPPackets != 1 {
					t.Fatalf("unexpected counters: %+v", counters)
				}
			},
		},
		{
			name: "NAT keepalive",
			data: []byte{0xff},
			check: func(t *testing.T, metadata PacketMetadata, counters Counters) {
				if !metadata.NATT || !metadata.NATKeepalive || metadata.IKE || metadata.EncapsulatedESP {
					t.Fatalf("unexpected metadata: %+v", metadata)
				}
				if counters.NATTPackets != 1 || counters.IKEPackets != 0 || counters.ESPPackets != 0 {
					t.Fatalf("unexpected counters: %+v", counters)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			frame := ipv4UDPFrame(4500, 4500, test.data)
			metadata, ok := decodePacketMetadata(frame, uint64(len(frame)), time.Unix(1, 0))
			if !ok {
				t.Fatal("packet did not decode")
			}
			var counters Counters
			classify(frame, &counters)
			test.check(t, metadata, counters)
		})
	}
}

func TestIPv6ExtensionHeaderIsTraversedForESP(t *testing.T) {
	frame := make([]byte, 14+40+8+8)
	binary.BigEndian.PutUint16(frame[12:14], 0x86dd)
	ip := frame[14:]
	ip[0] = 0x60
	ip[6] = 0 // Hop-by-Hop Options.
	copy(ip[8:24], []byte{0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	copy(ip[24:40], []byte{0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	ip[40] = 50 // ESP follows the eight-byte options header.
	binary.BigEndian.PutUint32(ip[48:52], 0x01020304)

	metadata, ok := decodePacketMetadata(frame, uint64(len(frame)), time.Now())
	if !ok || metadata.Protocol != 50 || metadata.SPI != 0x01020304 {
		t.Fatalf("IPv6 ESP metadata = %+v, ok=%v", metadata, ok)
	}
}

func TestReadPCAPPreservesNanosecondTimestamps(t *testing.T) {
	frame := ipv4UDPFrame(500, 500, make([]byte, 16))
	var capture bytes.Buffer
	header := make([]byte, 24)
	copy(header[:4], []byte{0x4d, 0x3c, 0xb2, 0xa1})
	binary.LittleEndian.PutUint32(header[20:24],1)
	capture.Write(header)
	record := make([]byte, 16)
	binary.LittleEndian.PutUint32(record[:4], 7)
	binary.LittleEndian.PutUint32(record[4:8], 123)
	binary.LittleEndian.PutUint32(record[8:12], uint32(len(frame)))
	binary.LittleEndian.PutUint32(record[12:16], uint32(len(frame)))
	capture.Write(record)
	capture.Write(frame)

	handle := &tcpdumpHandle{started: make(chan error, 1)}
	var observed time.Time
	err := readPCAP(&capture, nil, handle, Config{PacketObserver: func(_ context.Context, metadata PacketMetadata) error {
		observed = metadata.SeenAt
		return nil
	}})
	if !errors.Is(err, io.EOF) {
		t.Fatalf("readPCAP error = %v", err)
	}
	if observed.Unix() != 7 || observed.Nanosecond() != 123 {
		t.Fatalf("timestamp = %s, want 7s + 123ns", observed)
	}
}

func TestReadOfflinePCAPUsesTheLivePacketDecoder(t *testing.T) {
	frame := ipv4UDPFrame(4500, 4500, []byte{0x12, 0x34, 0x56, 0x78, 1, 2, 3, 4})
	var input bytes.Buffer
	header := make([]byte, 24)
	copy(header[:4], []byte{0xd4, 0xc3, 0xb2, 0xa1})
	binary.LittleEndian.PutUint32(header[20:24],1)
	input.Write(header)
	record := make([]byte, 16)
	binary.LittleEndian.PutUint32(record[:4], 7)
	binary.LittleEndian.PutUint32(record[4:8], 500_000)
	binary.LittleEndian.PutUint32(record[8:12], uint32(len(frame)))
	binary.LittleEndian.PutUint32(record[12:16], uint32(len(frame)))
	input.Write(record)
	input.Write(frame)

	var observed PacketMetadata
	result, err := ReadOfflinePCAP(context.Background(), &input, "offline-session", func(_ context.Context, metadata PacketMetadata) error {
		observed = metadata
		return nil
	})
	if err != nil {
		t.Fatalf("ReadOfflinePCAP error = %v", err)
	}
	if result.Counters.PacketsTotal != 1 || result.Counters.NATTPackets != 1 || result.Counters.ESPPackets != 1 {
		t.Fatalf("offline counters = %+v", result.Counters)
	}
	if observed.SessionID != "offline-session" || !observed.EncapsulatedESP || observed.SPI != 0x12345678 {
		t.Fatalf("offline metadata = %+v", observed)
	}
	if result.FirstSeen.Unix() != 7 || result.LastSeen.Nanosecond() != 500_000_000 {
		t.Fatalf("offline time range = %+v", result)
	}
}

func TestDecodeIKEv2CleartextPayloadsAndEncryptedBoundary(t *testing.T) {
	// A bounded SA proposal followed by an AUTH payload. The parser may expose
	// proposal metadata but must never interpret an encrypted body.
	proposal := make([]byte, 16)
	binary.BigEndian.PutUint16(proposal[2:4], uint16(len(proposal)))
	proposal[4], proposal[5], proposal[7] = 1, 1, 1
	binary.BigEndian.PutUint16(proposal[10:12], 8)
	proposal[12] = 1 // encryption transform
	binary.BigEndian.PutUint16(proposal[14:16], 12)
	sa := append([]byte{39, 0, 0, 20}, proposal...)
	auth := []byte{0, 0, 0, 5, 2}
	ike := make([]byte, 28)
	binary.BigEndian.PutUint64(ike[:8], 1)
	ike[16], ike[17], ike[18] = 33, 0x20, 34
	binary.BigEndian.PutUint32(ike[24:28], uint32(len(ike)+len(sa)+len(auth)))
	ike = append(ike, sa...)
	ike = append(ike, auth...)
	metadata, ok := decodePacketMetadata(ipv4UDPFrame(500, 500, ike), uint64(len(ike)), time.Now())
	if !ok || !metadata.IKE || len(metadata.IKEEncryptionAlgorithms) != 1 || metadata.IKEEncryptionAlgorithms[0] != "AES-CBC" || len(metadata.IKEAuthMethods) != 1 || metadata.IKEPayloadEncrypted {
		t.Fatalf("clear-text IKE parsing = %+v, ok=%v", metadata, ok)
	}
	ike[19] = 0x20 // Response bit does not imply encryption.
	metadata, ok = decodePacketMetadata(ipv4UDPFrame(500, 500, ike), uint64(len(ike)), time.Now())
	if !ok || metadata.IKEPayloadEncrypted { t.Fatal("response flag must not imply encryption") }
	ike[16]=46 // SK payload: stop before interpreting ciphertext.
	metadata, ok = decodePacketMetadata(ipv4UDPFrame(500, 500, ike), uint64(len(ike)), time.Now())
	if !ok || !metadata.IKEPayloadEncrypted || len(metadata.IKEProposals)!=0 {
		t.Fatalf("encrypted IKE payload was not marked: %+v", metadata)
	}
}

func TestReadOfflinePCAPRejectsMalformedPCAPNG(t *testing.T) {
	_, err := ReadOfflinePCAP(context.Background(), bytes.NewReader(append([]byte{0x0a, 0x0d, 0x0d, 0x0a}, make([]byte, 20)...)), "session", nil)
	if err == nil || !strings.Contains(err.Error(), "invalid byte-order magic") {
		t.Fatalf("PCAPNG error = %v", err)
	}
}

func ipv4UDPFrame(sourcePort, destinationPort uint16, data []byte) []byte {
	frame := make([]byte, 14+20+8+len(data))
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	ip := frame[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+8+len(data)))
	ip[9] = 17
	copy(ip[12:16], []byte{192, 0, 2, 1})
	copy(ip[16:20], []byte{198, 51, 100, 2})
	udp := ip[20:]
	binary.BigEndian.PutUint16(udp[:2], sourcePort)
	binary.BigEndian.PutUint16(udp[2:4], destinationPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(data)))
	copy(udp[8:], data)
	return frame
}
