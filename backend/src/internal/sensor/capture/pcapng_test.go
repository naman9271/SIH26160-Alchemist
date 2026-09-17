package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
)

func ngBlock(order binary.ByteOrder, kind uint32, body []byte) []byte {
	length:=12+(len(body)+3)&^3
	block:=make([]byte,length); order.PutUint32(block,kind);order.PutUint32(block[4:],uint32(length));copy(block[8:],body);order.PutUint32(block[length-4:],uint32(length));return block
}
func ngFile(order binary.ByteOrder, frame []byte, link uint16) []byte {
	section:=make([]byte,16);order.PutUint32(section,0x1a2b3c4d);order.PutUint16(section[4:],1)
	for i:=8;i<16;i++{section[i]=255}
	iface:=make([]byte,8);order.PutUint16(iface,link);order.PutUint32(iface[4:],65535)
	packet:=make([]byte,20+len(frame));order.PutUint32(packet[8:],7123456);order.PutUint32(packet[12:],uint32(len(frame)));order.PutUint32(packet[16:],uint32(len(frame)+5));copy(packet[20:],frame)
	return append(append(ngBlock(order,0x0a0d0d0a,section),ngBlock(order,1,iface)...),ngBlock(order,6,packet)...)
}

func TestPCAPNGByteOrdersInterfacesQualityAndSections(t *testing.T) {
	frame:=ipv4UDPFrame(4500,4500,[]byte{0,0,0,7,0,0,0,1})
	for _,order:=range []binary.ByteOrder{binary.LittleEndian,binary.BigEndian} {
		data:=ngFile(order,frame,1)
		seen:=0
		result,err:=ReadOfflinePCAP(context.Background(),bytes.NewReader(data),"test",func(_ context.Context,p PacketMetadata)error{
			seen++;if !p.EncapsulatedESP || p.SPI!=7 || p.SeenAt.Unix()!=7 {t.Fatalf("wrong metadata: %+v",p)};return nil
		})
		if err!=nil || seen!=1 || result.Counters.TruncatedPackets!=1 || result.Counters.IPv4Packets!=1 {t.Fatalf("result=%+v err=%v",result,err)}
		data=append(data,ngFile(binary.BigEndian,frame[14:],101)...)
		result,err=ReadOfflinePCAP(context.Background(),bytes.NewReader(data),"test",nil)
		if err!=nil || result.Counters.ESPPackets!=2 { t.Fatalf("section reset: %+v %v",result,err) }
	}
}

func TestPCAPNGRejectsCorruptionAndUnsupportedLinks(t *testing.T) {
	frame:=ipv4UDPFrame(4500,4500,make([]byte,8))
	valid:=ngFile(binary.LittleEndian,frame,1)
	badTrailer:=append([]byte(nil),valid...);badTrailer[len(badTrailer)-1]=1
	for _,data:=range [][]byte{valid[:len(valid)-1],badTrailer,ngFile(binary.LittleEndian,frame,999)} {
		if _,err:=ReadOfflinePCAP(context.Background(),bytes.NewReader(data),"test",nil);err==nil {t.Fatal("accepted corrupt capture")}
	}
}

func TestIKETransformAttributesAndUnknownIDs(t *testing.T) {
	part:=[]byte{0,0,0,12,1,0,0,12,0x80,14,0,128}
	value,ok:=parseTransform(part)
	if !ok || value.Name!="AES-CBC-128" || value.KeyBits!=128 {t.Fatalf("transform=%+v",value)}
	part[8]=0;part[10]=0;part[11]=10
	if _,ok:=parseTransform(part);ok { t.Fatal("accepted out of bounds TLV") }
	if transformLabel(4,65535,0)!="UNKNOWN-TRANSFORM-4-65535" { t.Fatal("unknown IDs must be preserved") }
}

func FuzzOfflineCapture(f *testing.F) {
	f.Add(ngFile(binary.LittleEndian,ipv4UDPFrame(500,500,make([]byte,28)),1))
	f.Fuzz(func(t *testing.T,data []byte){ if len(data)>1<<20 {t.Skip()};_,_=ReadOfflinePCAP(context.Background(),bytes.NewReader(data),"fuzz",nil) })
}
