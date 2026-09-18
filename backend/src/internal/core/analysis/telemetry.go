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
	childParents := make(map[uint64]map[string]string)
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
		metadata := map[string]string{
			"ike_name":           ike.GetName(),
			"ike_unique_id":      fmt.Sprint(ike.GetUniqueId()),
			"ike_initiator_spi":  ike.GetInitiatorSpi(),
			"ike_responder_spi":  ike.GetResponderSpi(),
			"local_endpoint":     ike.GetLocalHost(),
			"remote_endpoint":    ike.GetRemoteHost(),
			"endpoint_pair":      canonicalEndpointPair(ike.GetLocalHost(), ike.GetRemoteHost()),
			"suite_disposition":  "installed",
			"uncertainty_reason": "GATEWAY_VERIFIED",
		}
		addStrings := map[string]string{"ike.version": ike.GetIkeVersion(), "ike.state": ike.GetState(), "ike.local_identity": ike.GetLocalIdentity(), "ike.remote_identity": ike.GetRemoteIdentity(), "ike.local_endpoint": endpoint(ike.GetLocalHost(), ike.GetLocalPort()), "ike.remote_endpoint": endpoint(ike.GetRemoteHost(), ike.GetRemotePort()), "ike.encryption": ike.GetEncryptionAlgorithm(), "ike.integrity": ike.GetIntegrityAlgorithm(), "ike.prf": ike.GetPrf(), "ike.dh_group": ike.GetDhGroup(), "ike.initiator_spi": ike.GetInitiatorSpi(), "ike.responder_spi": ike.GetResponderSpi()}
		for key, value := range addStrings {
			items = appendString(items, model.SourceVICI, key, value, "VICI_IKE_SA", id, at, metadata, "vici:ike-sa/"+ike.GetName())
		}
		items = appendNumber(items, model.SourceVICI, "ike.established_duration_seconds", float64(ike.GetEstablishedDuration()), "VICI_IKE_SA", id, at, metadata)
		items = appendNumber(items, model.SourceVICI, "ike.rekey_seconds", float64(ike.GetRekeyTime()), "VICI_IKE_SA", id, at, metadata)
		items = appendNumber(items, model.SourceVICI, "ike.reauth_seconds", float64(ike.GetReauthTime()), "VICI_IKE_SA", id, at, metadata)
		items = appendNumber(items, model.SourceVICI, "ike.encryption_key_length_bits", float64(ike.GetEncryptionKeySize()), "VICI_IKE_SA", id, at, metadata)
		items = appendNumber(items, model.SourceVICI, "ike.integrity_key_length_bits", float64(ike.GetIntegrityKeySize()), "VICI_IKE_SA", id, at, metadata)
		for _, child := range ike.GetAssociatedChildSas() {
			if child != nil {
				children[child.GetUniqueId()] = child
				childParents[child.GetUniqueId()] = map[string]string{
					"parent_ike_resource_id": id,
					"parent_ike_unique_id":   fmt.Sprint(ike.GetUniqueId()),
					"ike_initiator_spi":      ike.GetInitiatorSpi(),
					"ike_responder_spi":      ike.GetResponderSpi(),
					"local_endpoint":         ike.GetLocalHost(),
					"remote_endpoint":        ike.GetRemoteHost(),
					"endpoint_pair":          canonicalEndpointPair(ike.GetLocalHost(), ike.GetRemoteHost()),
				}
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
		metadata := map[string]string{"child_name": child.GetName(), "child_unique_id": fmt.Sprint(child.GetUniqueId()), "strongswan_unique_id": fmt.Sprint(child.GetUniqueId()), "reqid": fmt.Sprint(child.GetReqid()), "spi_in": fmt.Sprintf("0x%08x", child.GetSpiIn()), "spi_out": fmt.Sprintf("0x%08x", child.GetSpiOut()), "suite_disposition": "installed", "uncertainty_reason": "GATEWAY_VERIFIED"}
		for key, value := range childParents[child.GetUniqueId()] {
			metadata[key] = value
		}
		if destination := metadata["local_endpoint"]; destination != "" && child.GetSpiIn() != 0 {
			metadata["spi_in_destination"] = destination
			metadata["esp_directional_wire_in"] = fmt.Sprintf("esp|%s|0x%08x", destination, child.GetSpiIn())
		}
		if destination := metadata["remote_endpoint"]; destination != "" && child.GetSpiOut() != 0 {
			metadata["spi_out_destination"] = destination
			metadata["esp_directional_wire_out"] = fmt.Sprintf("esp|%s|0x%08x", destination, child.GetSpiOut())
		}
		childAt := at
		if child.GetInstallTime() != nil && child.GetInstallTime().IsValid() {
			childAt = child.GetInstallTime().AsTime().UTC()
		}
		for key, value := range map[string]string{"child.state": child.GetState(), "child.mode": child.GetMode(), "child.protocol": child.GetProtocol(), "child.encryption_algorithm": child.GetEncryptionAlgorithm(), "child.integrity_algorithm": child.GetIntegrityAlgorithm(), "child.prf": child.GetPrf(), "child.exchange_dh_group": child.GetDhGroup(), "child.spi_in": fmt.Sprintf("0x%08x", child.GetSpiIn()), "child.spi_out": fmt.Sprintf("0x%08x", child.GetSpiOut()), "child.local_traffic_selectors": strings.Join(child.GetLocalTrafficSelectors(), ","), "child.remote_traffic_selectors": strings.Join(child.GetRemoteTrafficSelectors(), ",")} {
			items = appendString(items, model.SourceVICI, key, value, "VICI_CHILD_SA", id, childAt, metadata, "vici:child-sa/"+child.GetName())
		}
		items = appendString(items, model.SourceVICI, "sa.installed_at", childAt.Format(time.RFC3339Nano), "VICI_CHILD_SA", id, childAt, metadata, "vici:child-sa/"+child.GetName())
		items = appendString(items, model.SourceVICI, "sa.lifecycle_state", "INSTALLED", "VICI_CHILD_SA", id, at, metadata, "vici:child-sa/"+child.GetName())
		if child.GetLifeTime() > 0 {
			expiresAt := at.Add(time.Duration(child.GetLifeTime()) * time.Second)
			items = appendString(items, model.SourceVICI, "sa.expected_expiry_at", expiresAt.Format(time.RFC3339Nano), "VICI_CHILD_SA", id, at, metadata, "vici:child-sa/"+child.GetName())
		}
		// VICI reports rekey-time and life-time as remaining durations for an
		// installed CHILD_SA, not as its configured hard lifetime.
		items = appendBool(items, model.SourceVICI, "child.fresh_exchange_observed", child.GetDhGroup() != "" || len(child.GetAdditionalKeyExchanges()) > 0, "VICI_CHILD_SA", id, at, metadata)
		items = appendBool(items, model.SourceVICI, "replay.extended_sequence_numbers", child.GetExtendedSequenceNumbers(), "VICI_CHILD_SA", id, at, metadata)
		for key, value := range map[string]uint64{"child.bytes_in": child.GetBytesIn(), "child.bytes_out": child.GetBytesOut(), "child.packets_in": child.GetPacketsIn(), "child.packets_out": child.GetPacketsOut(), "child.encryption_key_length_bits": uint64(child.GetKeyLength()), "child.integrity_key_length_bits": uint64(child.GetIntegrityKeySize()), "child.install_age_seconds": child.GetInstallDuration(), "child.remaining_rekey_seconds": child.GetRekeyTime(), model.PropertyChildRemainingLifetimeSeconds: child.GetLifeTime()} {
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
		for _, auth := range connection.GetAuthentication() {
			authMeta := cloneMetadata(metadata)
			authMeta["auth_side"] = auth.GetSide()
			authMeta["auth_section"] = auth.GetSectionName()
			items = appendString(items, model.SourceVICI, "config.ike.authentication_class", auth.GetAuthClass(), "VICI_CONNECTION", id, at, authMeta, "vici:connection/"+connection.GetName())
		}
		for _, child := range connection.GetConfiguredChildren() {
			childMeta := cloneMetadata(metadata)
			childMeta["configured_child_name"] = child.GetName()
			groups := uniqueStrings(child.GetConfiguredPfsGroups())
			items = appendString(items, model.SourceVICI, "config.child.mode", child.GetMode(), "VICI_CONNECTION", id, at, childMeta, "vici:connection/"+connection.GetName())
			items = appendBool(items, model.SourceVICI, "config.child.pfs_enabled", len(groups) > 0, "VICI_CONNECTION", id, at, childMeta)
			items = appendString(items, model.SourceVICI, "config.child.pfs_groups", strings.Join(groups, ","), "VICI_CONNECTION", id, at, childMeta, "vici:connection/"+connection.GetName())
			items = appendNumber(items, model.SourceVICI, "config.child.rekey_seconds", float64(child.GetRekeyTime()), "VICI_CONNECTION", id, at, childMeta)
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
		id := fmt.Sprintf("xfrm-%s-%s-%08x", strings.ToLower(state.GetProtocol()), state.GetDestination(), state.GetSpi())
		metadata := map[string]string{"reqid": fmt.Sprint(state.GetReqid()), "spi": fmt.Sprintf("0x%08x", state.GetSpi()), "esp_spi": fmt.Sprintf("0x%08x", state.GetSpi()), "source": state.GetSource(), "destination": state.GetDestination(), "source_endpoint": state.GetSource(), "destination_endpoint": state.GetDestination(), "endpoint_pair": canonicalEndpointPair(state.GetSource(), state.GetDestination()), "esp_destination": state.GetDestination(), "esp_protocol": strings.ToUpper(state.GetProtocol()), "esp_directional_wire": fmt.Sprintf("%s|%s|0x%08x", strings.ToLower(state.GetProtocol()), state.GetDestination(), state.GetSpi()), "suite_disposition": "installed", "uncertainty_reason": "GATEWAY_VERIFIED"}
		for key, value := range map[string]string{"child.protocol": state.GetProtocol(), "esp.state": "INSTALLED", "esp.spi": fmt.Sprintf("0x%08x", state.GetSpi()), "child.mode": state.GetMode(), "child.encryption_algorithm": first(state.GetAeadAlgorithm(), state.GetEncryptionAlgorithm()), "child.integrity_algorithm": state.GetAuthenticationAlgorithm(), "child.encapsulation": state.GetEncapsulation(), "xfrm.direction": state.GetDirection()} {
			items = appendString(items, model.SourceXFRM, key, value, "XFRM_STATE", id, at, metadata, "netlink:xfrm-state/"+id)
		}
		if state.GetReplayApplicable() {
			items = appendBool(items, model.SourceXFRM, "replay.enabled", state.GetReplayWindow() > 0, "XFRM_STATE", id, at, metadata)
			items = appendBool(items, model.SourceXFRM, "replay.extended_sequence_numbers", state.GetExtendedSequenceNumbers(), "XFRM_STATE", id, at, metadata)
		}
		items = appendBool(items, model.SourceXFRM, "sa.runtime_verified", true, "XFRM_STATE", id, at, metadata)
		items = appendString(items, model.SourceXFRM, "sa.lifecycle_state", "INSTALLED", "XFRM_STATE", id, at, metadata, "netlink:xfrm-state/"+id)
		for key, value := range map[string]uint64{"replay.window": uint64(state.GetReplayWindow()), "replay.sequence": state.GetSequence(), "replay.outbound_sequence": state.GetOutboundSequence(), "child.encryption_key_length_bits": uint64(state.GetEncryptionKeyLength()), "child.aead_salt_length_bits": uint64(state.GetAeadSaltLength()), "child.authentication_key_length_bits": uint64(state.GetAuthenticationKeyLength()), "traffic.bytes": state.GetBytes(), "traffic.packet_count": state.GetPackets(), "sa.byte_soft_limit": state.GetByteSoftLimit(), "sa.byte_limit": state.GetByteLimit(), "sa.packet_soft_limit": state.GetPacketSoftLimit(), "sa.packet_limit": state.GetPacketLimit()} {
			items = appendNumber(items, model.SourceXFRM, key, float64(value), "XFRM_STATE", id, at, metadata)
		}
		if state.GetInstallTimeEpochSeconds() > 0 {
			items = appendString(items, model.SourceXFRM, "sa.installed_at", time.Unix(int64(state.GetInstallTimeEpochSeconds()), 0).UTC().Format(time.RFC3339Nano), "XFRM_STATE", id, at, metadata, "netlink:xfrm-state/"+id)
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
	if reference == "" {
		reference = fmt.Sprintf("%s:%s/%s", strings.ToLower(string(source)), strings.ToLower(resourceType), resourceID)
	}
	evidenceMetadata := cloneMetadata(metadata)
	evidenceMetadata["evidence_reference"] = reference
	if evidenceMetadata["uncertainty_reason"] == "" {
		evidenceMetadata["uncertainty_reason"] = "GATEWAY_VERIFIED"
	}
	return ingest.EvidenceInput{PropertyKey: key, Value: value, Source: source, Status: commonv1.EvidenceStatus_VERIFIED_GATEWAY, Confidence: 1, ObservedAt: at.UTC(), ResourceType: resourceType, ResourceID: resourceID, SourceReference: reference, SchemaVersion: model.EvidenceSchemaVersion, Metadata: evidenceMetadata}
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

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
