package main

import (
    "context"
    "log"
    "net"
    "google.golang.org/grpc"
    "testgrpc/message"
)

type server struct {
    msg.UnimplementedEchoServer
}

func (*server) Ping(ctx context.Context, in *msg.PingData) (*msg.PongData, error) {
    log.Printf("Received ping: %s, count=%d", in.GetName(), in.GetCount())
    resp := msg.PongData{
        Name: "Server",
        Count: in.GetCount(),
    }
    return &resp, nil
}

func main() {
    lis, err := net.Listen("tcp", "0.0.0.0:8000")
    if err != nil {
        log.Fatalf("fail to listen: %s", err)
    }
    s := grpc.NewServer()
    msg.RegisterEchoServer(s, &server{})
    log.Printf("server listening on %v", lis.Addr())
    if err := s.Serve(lis); err != nil {
        log.Fatalf("failed to serve: %v", err)
    }
}

