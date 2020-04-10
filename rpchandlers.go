package wireguardrpc

import (
	"context"

	"github.com/joncooperworks/wireguardrpc/pb"
)

// TODO: Expose operations on struct Wireguard as RPC operations.
type WireguardRPCServer struct {
}

func (w *WireguardRPCServer) CreatePeer(ctx context.Context, request *pb.CreatePeerRequest) (*pb.CreatePeerResponse, error) {
	return nil, nil
}

func (w *WireguardRPCServer) RekeyPeer(ctx context.Context, request *pb.RekeyPeerRequest) (*pb.RekeyPeerResponse, error) {
	return nil, nil
}

func (w *WireguardRPCServer) RemovePeer(ctx context.Context, request *pb.RemovePeerRequest) (*pb.RemovePeerResponse, error) {
	return nil, nil
}

func (w *WireguardRPCServer) ListPeers(ctx context.Context, request *pb.ListPeersRequest) (*pb.ListPeersResponse, error) {
	return nil, nil
}

func (w *WireguardRPCServer) ChangeListenPort(ctx context.Context, request *pb.ChangeListenPortRequest) (*pb.ChangeListenPortResponse, error) {
	return nil, nil
}
