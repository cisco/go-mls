package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/mlswg/mls-implementations/interop/proto"

	"github.com/cisco/go-mls/v0/mls/test-vectors"
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
	return &pb.SupportedCiphersuitesResponse{}, nil
	/*
		// TODO
		return nil, status.Error(codes.Unimplemented, "Method not implemented")
	*/
}

func (mc *MockClient) GenerateTestVector(ctx context.Context, req *pb.GenerateTestVectorRequest) (*pb.GenerateTestVectorResponse, error) {
	var vecJSON []byte
	var err error
	switch req.TestVectorType {
	case pb.TestVectorType_TREE_MATH:
		var vec vectors.TreeMath
		vec, err = vectors.NewTreeMath(req.NLeaves)
		if err != nil {
			return nil, err
		}

		vecJSON, err = json.Marshal(vec)

	case pb.TestVectorType_ENCRYPTION,
		pb.TestVectorType_KEY_SCHEDULE,
		pb.TestVectorType_TRANSCRIPT,
		pb.TestVectorType_TREEKEM,
		pb.TestVectorType_MESSAGES:
		return nil, status.Error(codes.InvalidArgument, "Unsupported test vector type")

	default:
		return nil, status.Error(codes.InvalidArgument, "Invalid test vector type")
	}

	if err != nil {
		return nil, err
	}

	return &pb.GenerateTestVectorResponse{TestVector: vecJSON}, nil
}

func (mc *MockClient) VerifyTestVector(ctx context.Context, req *pb.VerifyTestVectorRequest) (*pb.VerifyTestVectorResponse, error) {
	switch req.TestVectorType {
	case pb.TestVectorType_TREE_MATH:
		vec := new(vectors.TreeMath)
		err := json.Unmarshal(req.TestVector, &vec)
		if err != nil {
			return nil, err
		}

		return &pb.VerifyTestVectorResponse{}, vec.Verify()

	case pb.TestVectorType_ENCRYPTION,
		pb.TestVectorType_KEY_SCHEDULE,
		pb.TestVectorType_TRANSCRIPT,
		pb.TestVectorType_TREEKEM,
		pb.TestVectorType_MESSAGES:
		return nil, status.Error(codes.InvalidArgument, "Unsupported test vector type")

	default:
		return nil, status.Error(codes.InvalidArgument, "Invalid test vector type")
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
