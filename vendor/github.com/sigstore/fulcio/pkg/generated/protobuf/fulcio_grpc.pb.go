// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.21.11
// source: fulcio.proto

package protobuf

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// CAClient is the client API for CA service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type CAClient interface {
	// *
	// Returns an X.509 certificate created by the Fulcio certificate authority for the given request parameters
	CreateSigningCertificate(ctx context.Context, in *CreateSigningCertificateRequest, opts ...grpc.CallOption) (*SigningCertificate, error)
	// *
	// Returns the bundle of certificates that can be used to validate code signing certificates issued by this Fulcio instance
	GetTrustBundle(ctx context.Context, in *GetTrustBundleRequest, opts ...grpc.CallOption) (*TrustBundle, error)
	// *
	// Returns the configuration of supported OIDC issuers, including the required challenge for each issuer.
	GetConfiguration(ctx context.Context, in *GetConfigurationRequest, opts ...grpc.CallOption) (*Configuration, error)
}

type cAClient struct {
	cc grpc.ClientConnInterface
}

func NewCAClient(cc grpc.ClientConnInterface) CAClient {
	return &cAClient{cc}
}

func (c *cAClient) CreateSigningCertificate(ctx context.Context, in *CreateSigningCertificateRequest, opts ...grpc.CallOption) (*SigningCertificate, error) {
	out := new(SigningCertificate)
	err := c.cc.Invoke(ctx, "/dev.sigstore.fulcio.v2.CA/CreateSigningCertificate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cAClient) GetTrustBundle(ctx context.Context, in *GetTrustBundleRequest, opts ...grpc.CallOption) (*TrustBundle, error) {
	out := new(TrustBundle)
	err := c.cc.Invoke(ctx, "/dev.sigstore.fulcio.v2.CA/GetTrustBundle", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cAClient) GetConfiguration(ctx context.Context, in *GetConfigurationRequest, opts ...grpc.CallOption) (*Configuration, error) {
	out := new(Configuration)
	err := c.cc.Invoke(ctx, "/dev.sigstore.fulcio.v2.CA/GetConfiguration", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CAServer is the server API for CA service.
// All implementations must embed UnimplementedCAServer
// for forward compatibility
type CAServer interface {
	// *
	// Returns an X.509 certificate created by the Fulcio certificate authority for the given request parameters
	CreateSigningCertificate(context.Context, *CreateSigningCertificateRequest) (*SigningCertificate, error)
	// *
	// Returns the bundle of certificates that can be used to validate code signing certificates issued by this Fulcio instance
	GetTrustBundle(context.Context, *GetTrustBundleRequest) (*TrustBundle, error)
	// *
	// Returns the configuration of supported OIDC issuers, including the required challenge for each issuer.
	GetConfiguration(context.Context, *GetConfigurationRequest) (*Configuration, error)
	mustEmbedUnimplementedCAServer()
}

// UnimplementedCAServer must be embedded to have forward compatible implementations.
type UnimplementedCAServer struct {
}

func (UnimplementedCAServer) CreateSigningCertificate(context.Context, *CreateSigningCertificateRequest) (*SigningCertificate, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateSigningCertificate not implemented")
}
func (UnimplementedCAServer) GetTrustBundle(context.Context, *GetTrustBundleRequest) (*TrustBundle, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetTrustBundle not implemented")
}
func (UnimplementedCAServer) GetConfiguration(context.Context, *GetConfigurationRequest) (*Configuration, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetConfiguration not implemented")
}
func (UnimplementedCAServer) mustEmbedUnimplementedCAServer() {}

// UnsafeCAServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to CAServer will
// result in compilation errors.
type UnsafeCAServer interface {
	mustEmbedUnimplementedCAServer()
}

func RegisterCAServer(s grpc.ServiceRegistrar, srv CAServer) {
	s.RegisterService(&CA_ServiceDesc, srv)
}

func _CA_CreateSigningCertificate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateSigningCertificateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CAServer).CreateSigningCertificate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/dev.sigstore.fulcio.v2.CA/CreateSigningCertificate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CAServer).CreateSigningCertificate(ctx, req.(*CreateSigningCertificateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CA_GetTrustBundle_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetTrustBundleRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CAServer).GetTrustBundle(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/dev.sigstore.fulcio.v2.CA/GetTrustBundle",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CAServer).GetTrustBundle(ctx, req.(*GetTrustBundleRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CA_GetConfiguration_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetConfigurationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CAServer).GetConfiguration(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/dev.sigstore.fulcio.v2.CA/GetConfiguration",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CAServer).GetConfiguration(ctx, req.(*GetConfigurationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// CA_ServiceDesc is the grpc.ServiceDesc for CA service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var CA_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "dev.sigstore.fulcio.v2.CA",
	HandlerType: (*CAServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateSigningCertificate",
			Handler:    _CA_CreateSigningCertificate_Handler,
		},
		{
			MethodName: "GetTrustBundle",
			Handler:    _CA_GetTrustBundle_Handler,
		},
		{
			MethodName: "GetConfiguration",
			Handler:    _CA_GetConfiguration_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "fulcio.proto",
}