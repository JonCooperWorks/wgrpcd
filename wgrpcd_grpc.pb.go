// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package wgrpcd

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion7

// WireguardRPCClient is the client API for WireguardRPC service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type WireguardRPCClient interface {
	ChangeListenPort(ctx context.Context, in *ChangeListenPortRequest, opts ...grpc.CallOption) (*ChangeListenPortResponse, error)
	CreatePeer(ctx context.Context, in *CreatePeerRequest, opts ...grpc.CallOption) (*CreatePeerResponse, error)
	RekeyPeer(ctx context.Context, in *RekeyPeerRequest, opts ...grpc.CallOption) (*RekeyPeerResponse, error)
	RemovePeer(ctx context.Context, in *RemovePeerRequest, opts ...grpc.CallOption) (*RemovePeerResponse, error)
	ListPeers(ctx context.Context, in *ListPeersRequest, opts ...grpc.CallOption) (*ListPeersResponse, error)
	Devices(ctx context.Context, in *DevicesRequest, opts ...grpc.CallOption) (*DevicesResponse, error)
}

type wireguardRPCClient struct {
	cc grpc.ClientConnInterface
}

func NewWireguardRPCClient(cc grpc.ClientConnInterface) WireguardRPCClient {
	return &wireguardRPCClient{cc}
}

func (c *wireguardRPCClient) ChangeListenPort(ctx context.Context, in *ChangeListenPortRequest, opts ...grpc.CallOption) (*ChangeListenPortResponse, error) {
	out := new(ChangeListenPortResponse)
	err := c.cc.Invoke(ctx, "/wgrpcd.WireguardRPC/ChangeListenPort", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *wireguardRPCClient) CreatePeer(ctx context.Context, in *CreatePeerRequest, opts ...grpc.CallOption) (*CreatePeerResponse, error) {
	out := new(CreatePeerResponse)
	err := c.cc.Invoke(ctx, "/wgrpcd.WireguardRPC/CreatePeer", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *wireguardRPCClient) RekeyPeer(ctx context.Context, in *RekeyPeerRequest, opts ...grpc.CallOption) (*RekeyPeerResponse, error) {
	out := new(RekeyPeerResponse)
	err := c.cc.Invoke(ctx, "/wgrpcd.WireguardRPC/RekeyPeer", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *wireguardRPCClient) RemovePeer(ctx context.Context, in *RemovePeerRequest, opts ...grpc.CallOption) (*RemovePeerResponse, error) {
	out := new(RemovePeerResponse)
	err := c.cc.Invoke(ctx, "/wgrpcd.WireguardRPC/RemovePeer", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *wireguardRPCClient) ListPeers(ctx context.Context, in *ListPeersRequest, opts ...grpc.CallOption) (*ListPeersResponse, error) {
	out := new(ListPeersResponse)
	err := c.cc.Invoke(ctx, "/wgrpcd.WireguardRPC/ListPeers", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *wireguardRPCClient) Devices(ctx context.Context, in *DevicesRequest, opts ...grpc.CallOption) (*DevicesResponse, error) {
	out := new(DevicesResponse)
	err := c.cc.Invoke(ctx, "/wgrpcd.WireguardRPC/Devices", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// WireguardRPCServer is the server API for WireguardRPC service.
// All implementations must embed UnimplementedWireguardRPCServer
// for forward compatibility
type WireguardRPCServer interface {
	ChangeListenPort(context.Context, *ChangeListenPortRequest) (*ChangeListenPortResponse, error)
	CreatePeer(context.Context, *CreatePeerRequest) (*CreatePeerResponse, error)
	RekeyPeer(context.Context, *RekeyPeerRequest) (*RekeyPeerResponse, error)
	RemovePeer(context.Context, *RemovePeerRequest) (*RemovePeerResponse, error)
	ListPeers(context.Context, *ListPeersRequest) (*ListPeersResponse, error)
	Devices(context.Context, *DevicesRequest) (*DevicesResponse, error)
	mustEmbedUnimplementedWireguardRPCServer()
}

// UnimplementedWireguardRPCServer must be embedded to have forward compatible implementations.
type UnimplementedWireguardRPCServer struct {
}

func (UnimplementedWireguardRPCServer) ChangeListenPort(context.Context, *ChangeListenPortRequest) (*ChangeListenPortResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ChangeListenPort not implemented")
}
func (UnimplementedWireguardRPCServer) CreatePeer(context.Context, *CreatePeerRequest) (*CreatePeerResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreatePeer not implemented")
}
func (UnimplementedWireguardRPCServer) RekeyPeer(context.Context, *RekeyPeerRequest) (*RekeyPeerResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RekeyPeer not implemented")
}
func (UnimplementedWireguardRPCServer) RemovePeer(context.Context, *RemovePeerRequest) (*RemovePeerResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RemovePeer not implemented")
}
func (UnimplementedWireguardRPCServer) ListPeers(context.Context, *ListPeersRequest) (*ListPeersResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListPeers not implemented")
}
func (UnimplementedWireguardRPCServer) Devices(context.Context, *DevicesRequest) (*DevicesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Devices not implemented")
}
func (UnimplementedWireguardRPCServer) mustEmbedUnimplementedWireguardRPCServer() {}

// UnsafeWireguardRPCServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to WireguardRPCServer will
// result in compilation errors.
type UnsafeWireguardRPCServer interface {
	mustEmbedUnimplementedWireguardRPCServer()
}

func RegisterWireguardRPCServer(s grpc.ServiceRegistrar, srv WireguardRPCServer) {
	s.RegisterService(&_WireguardRPC_serviceDesc, srv)
}

func _WireguardRPC_ChangeListenPort_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ChangeListenPortRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WireguardRPCServer).ChangeListenPort(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/wgrpcd.WireguardRPC/ChangeListenPort",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WireguardRPCServer).ChangeListenPort(ctx, req.(*ChangeListenPortRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _WireguardRPC_CreatePeer_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreatePeerRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WireguardRPCServer).CreatePeer(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/wgrpcd.WireguardRPC/CreatePeer",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WireguardRPCServer).CreatePeer(ctx, req.(*CreatePeerRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _WireguardRPC_RekeyPeer_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RekeyPeerRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WireguardRPCServer).RekeyPeer(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/wgrpcd.WireguardRPC/RekeyPeer",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WireguardRPCServer).RekeyPeer(ctx, req.(*RekeyPeerRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _WireguardRPC_RemovePeer_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RemovePeerRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WireguardRPCServer).RemovePeer(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/wgrpcd.WireguardRPC/RemovePeer",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WireguardRPCServer).RemovePeer(ctx, req.(*RemovePeerRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _WireguardRPC_ListPeers_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListPeersRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WireguardRPCServer).ListPeers(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/wgrpcd.WireguardRPC/ListPeers",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WireguardRPCServer).ListPeers(ctx, req.(*ListPeersRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _WireguardRPC_Devices_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DevicesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WireguardRPCServer).Devices(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/wgrpcd.WireguardRPC/Devices",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WireguardRPCServer).Devices(ctx, req.(*DevicesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _WireguardRPC_serviceDesc = grpc.ServiceDesc{
	ServiceName: "wgrpcd.WireguardRPC",
	HandlerType: (*WireguardRPCServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ChangeListenPort",
			Handler:    _WireguardRPC_ChangeListenPort_Handler,
		},
		{
			MethodName: "CreatePeer",
			Handler:    _WireguardRPC_CreatePeer_Handler,
		},
		{
			MethodName: "RekeyPeer",
			Handler:    _WireguardRPC_RekeyPeer_Handler,
		},
		{
			MethodName: "RemovePeer",
			Handler:    _WireguardRPC_RemovePeer_Handler,
		},
		{
			MethodName: "ListPeers",
			Handler:    _WireguardRPC_ListPeers_Handler,
		},
		{
			MethodName: "Devices",
			Handler:    _WireguardRPC_Devices_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "wgrpcd.proto",
}
