package analysis

import (
	"fmt"
	"encoding/json"
	"sort"
	"strings"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/ingest"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/capture"
)

// negotiationEvidence only promotes a matching IKE_SA_INIT response. Child-SA
// proposals inside SK/SKF stay opaque. Selection is observed, not authenticated.
func negotiationEvidence(packets []capture.PacketMetadata) []ingest.EvidenceInput {
	requests := map[string]capture.PacketMetadata{}
	var items []ingest.EvidenceInput
	for _, p := range packets {
		if !p.IKE || !strings.HasPrefix(p.IKEVersion,"IKEv2") { continue }
		id := fmt.Sprintf("%016x-%016x",p.IKEInitiatorSPI,p.IKEResponderSPI)
		meta := map[string]string{"sensor_session_id":p.SessionID,"registry_version":capture.RegistryVersion,"source":p.SourceAddress,"destination":p.DestinationAddress}
		if len(p.IKEProposals)>0 { data,_ := json.Marshal(p.IKEProposals); items=append(items,stringEvidence("ike.proposals",string(data),"IKE_SA",id,p.SeenAt,meta)) }
		if p.IKEExchangeType != 34 || p.IKEMessageID != 0 || p.IKEPayloadEncrypted { continue }
		key := fmt.Sprintf("%s/%016x",p.SessionID,p.IKEInitiatorSPI)
		if p.IKEFlags&0x20 == 0 {
			if p.IKEResponderSPI==0 && p.IKEFlags&0x08!=0 { requests[key]=p }
			continue
		}
		r, ok := requests[key]
		if !ok || p.IKEResponderSPI==0 || p.IKEFlags&0x08!=0 || r.SourceAddress!=p.DestinationAddress || r.DestinationAddress!=p.SourceAddress || len(p.IKEProposals)!=1 { continue }
		selected:=p.IKEProposals[0]
		if selected.Protocol!=1 || selected.SPI!="" || !validSelection(selected) { continue }
		matched:=false
		for _, offered:=range r.IKEProposals {
			if offered.Number!=selected.Number || offered.Protocol!=selected.Protocol { continue }
			all:=true
			for _, t:=range selected.Transforms { found:=false; for _, o:=range offered.Transforms { if t.Type==o.Type && t.ID==o.ID && t.KeyBits==o.KeyBits { found=true } }; all=all&&found }
			if all { matched=true }
		}
		if !matched { continue }
		meta["negotiation"]="MATCHED_RESPONSE"; meta["peer_authentication"]="NOT_VERIFIED"
		items=append(items,stringEvidence("ike.negotiation","SELECTED_OBSERVED","IKE_SA",id,p.SeenAt,meta))
		for _, t:=range selected.Transforms {
			property:=map[uint8]string{1:"ike.encryption",2:"ike.prf",3:"ike.integrity",4:"ike.dh_group"}[t.Type]
			if property!="" { items=append(items,stringEvidence(property,t.Name,"IKE_SA",id,p.SeenAt,meta)) }
		}
	}
	return items
}

func validSelection(p capture.IKEProposal) bool {
	types:=map[uint8]bool{}; aead:=false
	for _, t:=range p.Transforms {
		if types[t.Type] || t.Type<1 || t.Type>4 { return false }; types[t.Type]=true
		if t.Type==1 { aead=t.ID==18 || t.ID==19 || t.ID==20 || t.ID==28; if (t.ID==12 || t.ID==13 || t.ID>=18 && t.ID<=20) && t.KeyBits!=128 && t.KeyBits!=192 && t.KeyBits!=256 { return false } }
	}
	return types[1] && types[2] && types[4] && (aead && !types[3] || !aead && types[3])
}

func streamID(p capture.PacketMetadata) string {
	protocol:=p.Protocol; if p.EncapsulatedESP { protocol=50 }
	return fmt.Sprintf("%s/%s>%s/%d/%08x",p.SessionID,p.SourceAddress,p.DestinationAddress,protocol,p.SPI)
}

// An observed SPI replacement is only a rekey candidate: two parallel SAs can
// share endpoints. Bidirectional pairing and installed mode need gateway proof.
func streamEvidence(packets []capture.PacketMetadata) []ingest.EvidenceInput {
	type stream struct { first,last capture.PacketMetadata; count uint64; previous string }
	streams:=map[string]*stream{}; latest:=map[string]string{}
	for _, p:=range packets {
		if p.SPI==0 || !(p.Protocol==50 || p.Protocol==51 || p.EncapsulatedESP) { continue }
		id:=streamID(p); direction:=fmt.Sprintf("%s/%s>%s/%t",p.SessionID,p.SourceAddress,p.DestinationAddress,p.Protocol==51)
		s:=streams[id]
		if s==nil { s=&stream{first:p, previous:latest[direction]}; streams[id]=s; latest[direction]=id }
		s.last=p; s.count++
	}
	ids:=make([]string,0,len(streams)); for id:=range streams { ids=append(ids,id) }; sort.Strings(ids)
	var out []ingest.EvidenceInput
	for _, id:=range ids {
		s:=streams[id]; typ:="ESP_STREAM"; if s.first.Protocol==51 { typ="AH_STREAM" }
		meta:=map[string]string{"sensor_session_id":s.first.SessionID,"source":s.first.SourceAddress,"destination":s.first.DestinationAddress,"bidirectional_pairing":"UNKNOWN"}
		for key,value:=range map[string]string{"child.state":"OBSERVED","sa.first_seen":s.first.SeenAt.UTC().Format("2006-01-02T15:04:05.999999999Z"),"sa.last_seen":s.last.SeenAt.UTC().Format("2006-01-02T15:04:05.999999999Z"),"sa.packet_count":fmt.Sprint(s.count),"sa.rekey_candidate_previous":s.previous} {
			if value!="" { out=append(out,stringEvidence(key,value,typ,id,s.last.SeenAt,meta)) }
		}
	}
	return out
}
