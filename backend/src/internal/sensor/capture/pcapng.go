package capture

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"time"
)

// ReadOfflinePCAP dispatches by magic, never by an untrusted filename. Both
// formats use the same payload-free decoder. Block allocations are bounded.
func ReadOfflinePCAP(ctx context.Context, reader io.Reader, sessionID string, observer PacketObserver) (OfflineResult,error) {
	if ctx==nil || reader==nil || sessionID=="" { return OfflineResult{},fmt.Errorf("context, reader and session_id are required") }
	r:=bufio.NewReader(reader)
	magic,err:=r.Peek(4); if err!=nil { return OfflineResult{},fmt.Errorf("capture header: %w",err) }
	if binary.BigEndian.Uint32(magic)==0x0a0d0d0a { return readPCAPNG(ctx,r,sessionID,observer) }
	return readClassicPCAP(ctx,r,sessionID,observer)
}

func supportedLink(link uint32) bool { switch link { case 0,1,101,113,228,229,276: return true }; return false }

func ethernetFrame(frame []byte,link uint32) []byte {
	if link==1 { return frame }
	var proto uint16; offset:=0
	switch link {
	case 113: if len(frame)<16 { return nil }; proto=binary.BigEndian.Uint16(frame[14:16]); offset=16
	case 276: if len(frame)<20 { return nil }; proto=binary.BigEndian.Uint16(frame[:2]); offset=20
	case 0: offset=4
	}
	if len(frame)<=offset { return nil }
	if proto==0 { switch frame[offset]>>4 { case 4:proto=0x0800; case 6:proto=0x86dd; default:return nil } }
	out:=make([]byte,14+len(frame)-offset); binary.BigEndian.PutUint16(out[12:14],proto); copy(out[14:],frame[offset:]); return out
}

type ngInterface struct { link uint32; resolution float64; offset int64; snap uint32 }

func readPCAPNG(ctx context.Context,r io.Reader,session string,observer PacketObserver) (OfflineResult,error) {
	var result OfflineResult
	var order binary.ByteOrder
	var interfaces []ngInterface
	for {
		if err:=ctx.Err();err!=nil { return result,err }
		header:=make([]byte,12); _,err:=io.ReadFull(r,header)
		if err==io.EOF { return result,nil }; if err!=nil { return result,fmt.Errorf("PCAPNG block header: %w",err) }
		section:=binary.BigEndian.Uint32(header[:4])==0x0a0d0d0a
		if section {
			switch binary.BigEndian.Uint32(header[8:12]) { case 0x1a2b3c4d:order=binary.BigEndian; case 0x4d3c2b1a:order=binary.LittleEndian; default:return result,fmt.Errorf("PCAPNG invalid byte-order magic") }
			interfaces=nil
		}
		if order==nil { return result,fmt.Errorf("PCAPNG requires section header") }
		length:=order.Uint32(header[4:8]); if length<12 || length>16<<20 || length%4!=0 { return result,fmt.Errorf("PCAPNG invalid block length %d",length) }
		block:=make([]byte,int(length)); copy(block,header)
		if _,err=io.ReadFull(r,block[12:]);err!=nil { return result,fmt.Errorf("PCAPNG truncated block: %w",err) }
		if order.Uint32(block[len(block)-4:])!=length { return result,fmt.Errorf("PCAPNG block length mismatch") }
		body:=block[8:len(block)-4]
		kind:=order.Uint32(header[:4])
		switch kind {
		case 0x0a0d0d0a:
			if len(body)<16 || order.Uint16(body[4:6])!=1 { return result,fmt.Errorf("PCAPNG unsupported section version") }
		case 1:
			if len(body)<8 { return result,fmt.Errorf("PCAPNG short interface") }
			iface:=ngInterface{link:uint32(order.Uint16(body[:2])),resolution:1e6,snap:order.Uint32(body[4:8])}
			if !supportedLink(iface.link) { return result,fmt.Errorf("unsupported PCAPNG link type %d",iface.link) }
			if err:=ngOptions(body[8:],order,func(code uint16,value []byte) error {
				if code==9 { if len(value)!=1 { return fmt.Errorf("invalid timestamp resolution") }; base:=10.0; exp:=value[0]; if exp&0x80!=0 { base=2; exp&=0x7f }; if exp>63 { return fmt.Errorf("unsupported timestamp resolution") }; iface.resolution=math.Pow(base,float64(exp)) }
				if code==14 { if len(value)!=8 { return fmt.Errorf("invalid timestamp offset") }; iface.offset=int64(order.Uint64(value)) }; return nil
			});err!=nil { return result,err }
			if len(interfaces)>=4096 { return result,fmt.Errorf("PCAPNG interface limit exceeded") }; interfaces=append(interfaces,iface)
		case 6,2:
			if len(body)<20 { return result,fmt.Errorf("PCAPNG short packet block") }
			idx:=order.Uint32(body[:4]); if kind==2 { idx=uint32(order.Uint16(body[:2])) }
			if int(idx)>=len(interfaces) { return result,fmt.Errorf("PCAPNG unknown interface") }; iface:=interfaces[idx]
			captured,original:=order.Uint32(body[12:16]),order.Uint32(body[16:20])
			padded:=(uint64(captured)+3)&^uint64(3)
			if padded>uint64(len(body)-20) || captured>original || iface.snap>0 && captured>iface.snap { return result,fmt.Errorf("PCAPNG invalid packet lengths") }
			if err:=ngOptions(body[20+int(padded):],order,func(uint16,[]byte)error{return nil});err!=nil { return result,err }
			ticks:=uint64(order.Uint32(body[4:8]))<<32|uint64(order.Uint32(body[8:12]))
			seconds:=float64(ticks)/iface.resolution
			if seconds>float64(math.MaxInt64/2) { return result,fmt.Errorf("PCAPNG timestamp out of range") }
			at:=time.Unix(int64(seconds)+iface.offset,int64((seconds-math.Floor(seconds))*1e9)).UTC()
			packet:=ethernetFrame(body[20:20+int(captured)],iface.link)
			result.Counters.PacketsTotal++; result.Counters.BytesTotal+=uint64(captured)
			if captured<original { result.Counters.TruncatedPackets++ }; classify(packet,&result.Counters)
			if result.FirstSeen.IsZero() || at.Before(result.FirstSeen) { result.FirstSeen=at }; if result.LastSeen.IsZero() || at.After(result.LastSeen) { result.LastSeen=at }
			if observer!=nil { if m,ok:=decodePacketMetadata(packet,uint64(captured),at);ok { m.SessionID=session; if err:=observer(ctx,m);err!=nil { return result,err } } }
		case 3:
			// Simple packet blocks have no timestamps: reject instead of silently
			// manufacturing timing features for the metadata classifier.
			return result,fmt.Errorf("PCAPNG simple packet blocks lack timestamps; export enhanced packet blocks")
		case 5:
			if len(body)<12 { return result,fmt.Errorf("PCAPNG short statistics block") }
			if err:=ngOptions(body[12:],order,func(code uint16,value []byte)error{ if code==5 { if len(value)!=8 { return fmt.Errorf("invalid drop counter") }; drops:=order.Uint64(value); if drops>result.Counters.PacketDrops { result.Counters.PacketDrops=drops } };return nil });err!=nil { return result,err }
		}
	}
}

func ngOptions(data []byte,order binary.ByteOrder,visit func(uint16,[]byte)error)error {
	for len(data)>0 {
		if len(data)<4 { return fmt.Errorf("PCAPNG truncated option") }
		code,n:=order.Uint16(data[:2]),int(order.Uint16(data[2:4]));data=data[4:]
		if code==0 { if n!=0 { return fmt.Errorf("PCAPNG invalid end option") };return nil }
		padded:=(n+3)&^3; if padded>len(data) { return fmt.Errorf("PCAPNG invalid option length") }
		if err:=visit(code,data[:n]);err!=nil{return err};data=data[padded:]
	};return nil
}
