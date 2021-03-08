package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/mlswg/mls-implementations/interop/proto"

	"github.com/cisco/go-mls/v0/mls"
)

var (
	implementationName = "go-mls"
)

///
/// Mock client implementation
///
type MockClient struct {
	pb.MLSClientServer
}

func NewMockClient() *MockClient {
	return &MockClient{}
}

func (mc *MockClient) Name(ctx context.Context, req *pb.NameRequest) (*pb.NameResponse, error) {
	return &pb.NameResponse{Name: implementationName}, nil
}

func (mc *MockClient) SupportedCiphersuites(ctx context.Context, req *pb.SupportedCiphersuitesRequest) (*pb.SupportedCiphersuitesResponse, error) {
	resp := &pb.SupportedCiphersuitesResponse{
		Ciphersuites: make([]uint32, len(mls.AllSupportedCiphersuites)),
	}

	for i, id := range mls.AllSupportedCiphersuites {
		resp.Ciphersuites[i] = uint32(id)
	}

	return resp, nil
}

func (mc *MockClient) GenerateTestVector(ctx context.Context, req *pb.GenerateTestVectorRequest) (*pb.GenerateTestVectorResponse, error) {
	switch req.TestVectorType {
	default:
		return nil, status.Error(codes.InvalidArgument, "Unsupported test vector type")
	}
}

func (mc *MockClient) VerifyTestVector(ctx context.Context, req *pb.VerifyTestVectorRequest) (*pb.VerifyTestVectorResponse, error) {
	switch req.TestVectorType {
	default:
		return nil, status.Error(codes.InvalidArgument, "Unsupported test vector type")
	}
}

///
/// Run the server
///

var (
	portOpt int
)

func init() {
	flag.IntVar(&portOpt, "port", 50001, "port to listen on")
	flag.Parse()
}

func main() {
	port := fmt.Sprintf(":%d", portOpt)
	log.Printf("Listening on %s", port)

	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	pb.RegisterMLSClientServer(s, NewMockClient())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
