package main

import (
    "context"
    "log"
    "flag"
    "time"
    "google.golang.org/grpc/credentials/insecure"
    "google.golang.org/grpc"
    "testgrpc/message"
)

var (
    addr = flag.String("addr", "localhost:8000", "target")
    name = flag.String("name", "kimi",  "name")
    count = flag.Int("count", 10, "ping count")
)

func main() {
    flag.Parse()
    conn, err := grpc.Dial(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
    if err != nil {
        log.Fatalf("fail to connect: %v", err)
    }
    defer conn.Close()

    c := msg.NewEchoClient(conn)
    //ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
    //defer cancel()
    ctx := context.Background()
    for {
        ping := msg.PingData{Name: *name, Count: int32(*count)}
        log.Printf("ping: %s, count:%d\n", ping.GetName(), ping.GetCount())
        pong, err := c.Ping(ctx, &ping)
        if err != nil {
            log.Fatalf("ping failed: %v", err)
        }
        log.Printf("pong: %s, count:%d\n", pong.GetName(), pong.GetCount())
        time.Sleep(time.Second * 1)
    }
}

