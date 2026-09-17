package analysis

import (
	"testing"
	"time"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/capture"
)

func TestOfferSelectionAndUnmatchedResponse(t *testing.T) {
	proposal:=capture.IKEProposal{Number:1,Protocol:1,Transforms:[]capture.IKETransform{{Type:1,ID:20,KeyBits:128,Name:"AES-GCM-16-128"},{Type:2,ID:5,Name:"PRF-HMAC-SHA256"},{Type:4,ID:19,Name:"ECP256"}}}
	request:=capture.PacketMetadata{SessionID:"s",IKE:true,IKEVersion:"IKEv2.0",IKEInitiatorSPI:1,IKEExchangeType:34,IKEFlags:8,SourceAddress:"192.0.2.1",DestinationAddress:"192.0.2.2",IKEProposals:[]capture.IKEProposal{proposal},SeenAt:time.Now()}
	response:=request;response.SourceAddress=request.DestinationAddress;response.DestinationAddress=request.SourceAddress;response.IKEFlags=0x20;response.IKEResponderSPI=2
	if hasEvidence(negotiationEvidence([]capture.PacketMetadata{request}),"ike.encryption") { t.Fatal("offered cipher promoted to selected") }
	if hasEvidence(negotiationEvidence([]capture.PacketMetadata{response}),"ike.encryption") { t.Fatal("unmatched response promoted") }
	items:=negotiationEvidence([]capture.PacketMetadata{request,response})
	if !hasEvidence(items,"ike.encryption") || hasEvidence(items,"child.encryption_algorithm") {t.Fatal("IKE and Child SA scopes mixed")}
	response.DestinationAddress="192.0.2.99"
	if hasEvidence(negotiationEvidence([]capture.PacketMetadata{request,response}),"ike.encryption") {t.Fatal("wrong endpoint matched")}
	response.DestinationAddress=request.SourceAddress;response.IKEPayloadEncrypted=true
	if hasEvidence(negotiationEvidence([]capture.PacketMetadata{request,response}),"ike.encryption") {t.Fatal("encrypted message parsed")}
}

func TestSPIIdentityAndRekeyCandidatesDoNotInventMode(t *testing.T) {
	p:=capture.PacketMetadata{SessionID:"s",Protocol:50,SPI:1,SourceAddress:"192.0.2.1",DestinationAddress:"192.0.2.2",SeenAt:time.Now()}
	other:=p;other.DestinationAddress="192.0.2.3"
	if streamID(p)==streamID(other) {t.Fatal("SPI collision across peers")}
	rekey:=p;rekey.SPI=2;rekey.SeenAt=p.SeenAt.Add(time.Second)
	items:=streamEvidence([]capture.PacketMetadata{p,other,rekey})
	if !hasEvidence(items,"sa.rekey_candidate_previous") || hasEvidence(items,"child.mode") {t.Fatal("incorrect stream lifecycle")}
}
