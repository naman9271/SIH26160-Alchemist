package sensor

import (
	"context"
	"reflect"

	networkv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/network"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/network"
)

type NetworkInterfaceHandler struct {
	networkv1.UnimplementedNetworkInterfaceServiceServer
	service *network.Service
}

func NewNetworkInterfaceHandler(service *network.Service) *NetworkInterfaceHandler {
	return &NetworkInterfaceHandler{service: service}
}
func (h *NetworkInterfaceHandler) ListInterfaces(ctx context.Context, request *networkv1.ListInterfacesRequest) (*networkv1.ListInterfacesResponse, error) {
	if err := h.validate(request); err != nil {
		return nil, shared.ToGRPC(err)
	}
	values, err := h.service.List(ctx)
	if err != nil {
		return nil, shared.ToGRPC(err)
	}
	result := make([]*networkv1.NetworkInterface, 0, len(values))
	for _, value := range values {
		result = append(result, networkInterfaceResponse(value))
	}
	return &networkv1.ListInterfacesResponse{Interfaces: result}, nil
}
func (h *NetworkInterfaceHandler) GetInterface(ctx context.Context, request *networkv1.GetInterfaceRequest) (*networkv1.NetworkInterface, error) {
	if err := h.validate(request); err != nil {
		return nil, shared.ToGRPC(err)
	}
	value, err := h.service.Get(ctx, request.GetInterfaceName())
	if err != nil {
		return nil, shared.ToGRPC(err)
	}
	return networkInterfaceResponse(value), nil
}
func (h *NetworkInterfaceHandler) GetInterfaceStats(ctx context.Context, request *networkv1.GetInterfaceStatsRequest) (*networkv1.InterfaceStats, error) {
	if err := h.validate(request); err != nil {
		return nil, shared.ToGRPC(err)
	}
	value, err := h.service.Stats(ctx, request.GetInterfaceName())
	if err != nil {
		return nil, shared.ToGRPC(err)
	}
	return &networkv1.InterfaceStats{RxPackets: value.RXPackets, TxPackets: value.TXPackets, RxBytes: value.RXBytes, TxBytes: value.TXBytes, RxBytesPerSecond: value.RXBytesPerSecond, TxBytesPerSecond: value.TXBytesPerSecond}, nil
}
func (h *NetworkInterfaceHandler) validate(request any) error {
	if h.service == nil {
		return shared.NewError(shared.Internal, "", "network interface service is not configured")
	}
	if request == nil || (reflect.ValueOf(request).Kind() == reflect.Ptr && reflect.ValueOf(request).IsNil()) {
		return shared.NewError(shared.InvalidArgument, "", "request is required")
	}
	return nil
}
func networkInterfaceResponse(value network.Interface) *networkv1.NetworkInterface {
	return &networkv1.NetworkInterface{Name: value.Name, Index: value.Index, MacAddress: value.MACAddress, Addresses: value.Addresses, Up: value.Up, Loopback: value.Loopback, CaptureSupported: value.CaptureSupported}
}
