package analysis

import (
	"fmt"
	"sort"
	"strings"
	"time"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	viciv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/vici"
	xfrmv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/xfrm"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/ingest"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func VICIEvidence(snapshot *viciv1.GatewaySnapshot) []ingest.EvidenceInput {
	if snapshot == nil {
		return nil
	}
	at := snapshotTime(snapshot.GetSnapshotTimestamp(), time.Now().UTC())
	items := make([]ingest.EvidenceInput, 0)
	children := make(map[uint64]*viciv1.ChildSa)
	for _, child := range snapshot.GetChildSas() {
		if child != nil {
			children[child.GetUniqueId()] = child
		}
	}
	for _, ike := range snapshot.GetIkeSas() {
		if ike == nil {
			continue
		}
		id := fmt.Sprintf("vici-ike-%d", ike.GetUniqueId())
		metadata := map[string]string{"ike_name": ike.GetName(), "ike_unique_id": fmt.Sprint(ike.GetUniqueId()), "ike_initiator_spi": ike.GetInitiatorSpi(), "ike_responder_spi": ike.GetResponderSpi()}
		addStrings := map[string]string{"ike.version": ike.GetIkeVersion(), "ike.state": ike.GetState(), "ike.local_identity": ike.GetLocalIdentity(), "ike.remote_identity": ike.GetRemoteIdentity(), "ike.local_endpoint": endpoint(ike.GetLocalHost(), ike.GetLocalPort()), "ike.remote_endpoint": endpoint(ike.GetRemoteHost(), ike.GetRemotePort()), "ike.encryption": ike.GetEncryptionAlgorithm(), "ike.integrity": ike.GetIntegrityAlgorithm(), "ike.prf": ike.GetPrf(), "ike.dh_group": ike.GetDhGroup(), "ike.initiator_spi": ike.GetInitiatorSpi(), "ike.responder_spi": ike.GetResponderSpi()}
		for key, value := range addStrings {
			items = appendString(items, model.SourceVICI, key, value, "VICI_IKE_SA", id, at, metadata, "vici:ike-sa/"+ike.GetName())
		}
		items = appendNumber(items, model.SourceVICI, "ike.established_duration_seconds", float64(ike.GetEstablishedDuration()), "VICI_IKE_SA", id, at, metadata)
		if ike.GetEncryptionKeySize()>0 { items=appendNumber(items,model.SourceVICI,"ike.encryption_key_bits",float64(ike.GetEncryptionKeySize()),"VICI_IKE_SA",id,at,metadata) }
		items = appendNumber(items, model.SourceVICI, "ike.rekey_seconds", float64(ike.GetRekeyTime()), "VICI_IKE_SA", id, at, metadata)
		items = appendNumber(items, model.SourceVICI, "ike.reauth_seconds", float64(ike.GetReauthTime()), "VICI_IKE_SA", id, at, metadata)
		for _, child := range ike.GetAssociatedChildSas() {
			if child != nil {
				children[child.GetUniqueId()] = child
			}
		}
	}
	childIDs := make([]uint64, 0, len(children))
	for id := range children {
		childIDs = append(childIDs, id)
	}
	sort.Slice(childIDs, func(i, j int) bool { return childIDs[i] < childIDs[j] })
	for _, childID := range childIDs {
		child := children[childID]
		id := fmt.Sprintf("vici-child-%d", child.GetUniqueId())
		metadata := map[string]string{"child_name": child.GetName(), "child_unique_id": fmt.Sprint(child.GetUniqueId()), "reqid": fmt.Sprint(child.GetReqid()), "spi_in": fmt.Sprintf("0x%08x", child.GetSpiIn()), "spi_out": fmt.Sprintf("0x%08x", child.GetSpiOut())}
		childAt := at
		if child.GetInstallTime() != nil && child.GetInstallTime().IsValid() {
			childAt = child.GetInstallTime().AsTime().UTC()
		}
		for key, value := range map[string]string{"child.state": child.GetState(), "child.mode": child.GetMode(), "child.protocol": child.GetProtocol(), "child.encryption_algorithm": child.GetEncryptionAlgorithm(), "child.integrity_algorithm": child.GetIntegrityAlgorithm(), "child.spi_in": fmt.Sprintf("0x%08x", child.GetSpiIn()), "child.spi_out": fmt.Sprintf("0x%08x", child.GetSpiOut()), "child.local_traffic_selectors": strings.Join(child.GetLocalTrafficSelectors(), ","), "child.remote_traffic_selectors": strings.Join(child.GetRemoteTrafficSelectors(), ",")} {
			items = appendString(items, model.SourceVICI, key, value, "VICI_CHILD_SA", id, childAt, metadata, "vici:child-sa/"+child.GetName())
		}
		if child.GetKeyLength()>0 { items=appendNumber(items,model.SourceVICI,"child.encryption_key_bits",float64(child.GetKeyLength()),"VICI_CHILD_SA",id,at,metadata) }
		for key, value := range map[string]uint64{"child.bytes_in": child.GetBytesIn(), "child.bytes_out": child.GetBytesOut(), "child.packets_in": child.GetPacketsIn(), "child.packets_out": child.GetPacketsOut(), "child.rekey_seconds": child.GetRekeyTime(), "child.remaining_lifetime_seconds": child.GetLifeTime()} {
			items = appendNumber(items, model.SourceVICI, key, float64(value), "VICI_CHILD_SA", id, childAt, metadata)
		}
	}
	for _, connection := range snapshot.GetConnections() {
		if connection == nil {
			continue
		}
		id := "vici-connection-" + connection.GetName()
		metadata := map[string]string{"connection_name": connection.GetName()}
		items = appendString(items, model.SourceVICI, "ike.authentication_methods", strings.Join(connection.GetAuthenticationMethods(), ","), "VICI_CONNECTION", id, at, metadata, "vici:connection/"+connection.GetName())
		items = appendString(items, model.SourceVICI, "ike.proposals", strings.Join(connection.GetIkeProposals(), ","), "VICI_CONNECTION", id, at, metadata, "vici:connection/"+connection.GetName())
		items = appendString(items, model.SourceVICI, "child.pfs_group", connection.GetPfsKeyExchange(), "VICI_CONNECTION", id, at, metadata, "vici:connection/"+connection.GetName())
		if connection.GetPfsKeyExchange() != "" {
			items = appendBool(items, model.SourceVICI, "child.pfs", true, "VICI_CONNECTION", id, at, metadata)
		}
	}
	for index, certificate := range snapshot.GetCertificates() {
		if certificate == nil {
			continue
		}
		id := fmt.Sprintf("vici-certificate-%d", index)
		metadata := map[string]string{"fingerprint": certificate.GetFingerprint()}
		for key, value := range map[string]string{"ike.certificate.subject": certificate.GetSubject(), "ike.certificate.issuer": certificate.GetIssuer(), "ike.certificate.public_key_type": certificate.GetPublicKeyType(), "ike.certificate.type": certificate.GetCertificateType()} {
			items = appendString(items, model.SourceVICI, key, value, "VICI_CERTIFICATE", id, at, metadata, "vici:certificate/"+certificate.GetFingerprint())
		}
	}
	return items
}

func XFRMEvidence(snapshot *xfrmv1.KernelSnapshot) []ingest.EvidenceInput {
	if snapshot == nil {
		return nil
	}
	at := snapshotTime(snapshot.GetSnapshotTimestamp(), time.Now().UTC())
	items := make([]ingest.EvidenceInput, 0)
	for _, state := range snapshot.GetStates() {
		if state == nil {
			continue
		}
		id := fmt.Sprintf("xfrm-%s-%s-%s-%08x", strings.ToLower(state.GetProtocol()), state.GetSource(),state.GetDestination(),state.GetSpi())
		metadata := map[string]string{"reqid": fmt.Sprint(state.GetReqid()), "spi": fmt.Sprintf("0x%08x", state.GetSpi()), "source": state.GetSource(), "destination": state.GetDestination()}
		for key, value := range map[string]string{"child.protocol": state.GetProtocol(), "esp.state": "INSTALLED", "esp.spi": fmt.Sprintf("0x%08x", state.GetSpi()), "child.mode": state.GetMode(), "child.encryption_algorithm": first(state.GetAeadAlgorithm(), state.GetEncryptionAlgorithm()), "child.integrity_algorithm": state.GetAuthenticationAlgorithm(), "child.encapsulation": state.GetEncapsulation(), "xfrm.direction": state.GetDirection()} {
			items = appendString(items, model.SourceXFRM, key, value, "XFRM_STATE", id, at, metadata, "netlink:xfrm-state/"+id)
		}
		items = appendBool(items, model.SourceXFRM, "replay.enabled", state.GetReplayWindow() > 0, "XFRM_STATE", id, at, metadata)
		items = appendBool(items, model.SourceXFRM, "replay.extended_sequence_numbers", state.GetExtendedSequenceNumbers(), "XFRM_STATE", id, at, metadata)
		items = appendBool(items, model.SourceXFRM, "sa.runtime_verified", true, "XFRM_STATE", id, at, metadata)
		if state.GetEncryptionKeyLength()>0 { items=appendNumber(items,model.SourceXFRM,"child.encryption_key_bits",float64(state.GetEncryptionKeyLength()),"XFRM_STATE",id,at,metadata) }
		for key, value := range map[string]uint64{"replay.window": uint64(state.GetReplayWindow()), "replay.sequence": state.GetSequence(), "traffic.bytes": state.GetBytes(), "traffic.packet_count": state.GetPackets(), "sa.byte_limit": state.GetByteLimit(), "sa.packet_limit": state.GetPacketLimit()} {
			items = appendNumber(items, model.SourceXFRM, key, float64(value), "XFRM_STATE", id, at, metadata)
		}
	}
	for index, policy := range snapshot.GetPolicies() {
		if policy == nil {
			continue
		}
		id := fmt.Sprintf("xfrm-policy-%d-%d", policy.GetReqid(), index)
		metadata := map[string]string{"reqid": fmt.Sprint(policy.GetReqid())}
		for key, value := range map[string]string{"xfrm.policy.direction": policy.GetDirection(), "xfrm.policy.source_selector": policy.GetSourceSelector(), "xfrm.policy.destination_selector": policy.GetDestinationSelector(), "xfrm.policy.source_template": policy.GetSourceTemplate(), "xfrm.policy.destination_template": policy.GetDestinationTemplate(), "xfrm.policy.mode": policy.GetMode(), "xfrm.policy.protocol": policy.GetProtocol()} {
			items = appendString(items, model.SourceXFRM, key, value, "XFRM_POLICY", id, at, metadata, "netlink:xfrm-policy/"+id)
		}
	}
	return items
}

func appendString(items []ingest.EvidenceInput, source model.Source, key, value, resourceType, resourceID string, at time.Time, metadata map[string]string, reference string) []ingest.EvidenceInput {
	if strings.TrimSpace(value) == "" {
		return items
	}
	return append(items, evidenceValue(source, key, structpb.NewStringValue(value), resourceType, resourceID, at, metadata, reference))
}
func appendNumber(items []ingest.EvidenceInput, source model.Source, key string, value float64, resourceType, resourceID string, at time.Time, metadata map[string]string) []ingest.EvidenceInput {
	return append(items, evidenceValue(source, key, structpb.NewNumberValue(value), resourceType, resourceID, at, metadata, ""))
}
func appendBool(items []ingest.EvidenceInput, source model.Source, key string, value bool, resourceType, resourceID string, at time.Time, metadata map[string]string) []ingest.EvidenceInput {
	return append(items, evidenceValue(source, key, structpb.NewBoolValue(value), resourceType, resourceID, at, metadata, ""))
}
func evidenceValue(source model.Source, key string, value *structpb.Value, resourceType, resourceID string, at time.Time, metadata map[string]string, reference string) ingest.EvidenceInput {
	return ingest.EvidenceInput{PropertyKey: key, Value: value, Source: source, Status: commonv1.EvidenceStatus_VERIFIED_GATEWAY, Confidence: 1, ObservedAt: at.UTC(), ResourceType: resourceType, ResourceID: resourceID, SourceReference: reference, SchemaVersion: model.EvidenceSchemaVersion, Metadata: metadata}
}
func snapshotTime(value *timestamppb.Timestamp, fallback time.Time) time.Time {
	if value != nil && value.IsValid() {
		return value.AsTime().UTC()
	}
	return fallback.UTC()
}
func endpoint(host string, port uint32) string {
	if host == "" {
		return ""
	}
	if port == 0 {
		return host
	}
	return fmt.Sprintf("%s:%d", host, port)
}
func first(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
