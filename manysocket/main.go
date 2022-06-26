package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

const (
	SECOND_NS = 1000 * 1000 * 1000
)

var conns = []net.Conn{}
var sendCount = 1024 * 256
var buffer = make([]byte, sendCount)

func client(dest string) {
	fmt.Printf("Try New Connection...\n")
	conn, err := net.DialTimeout("tcp", dest, time.Duration(SECOND_NS*5))
	if err != nil {
		fmt.Printf("Connect error: %s\n", err)
		os.Exit(2)
	}
	conn.SetDeadline(time.Now().Add(SECOND_NS * 0.1))
	fmt.Printf("Send Data...\n")
	n, err := conn.Write(buffer[:])
	if err != nil {
		fmt.Printf("Send data error: %s\n", err)
	}
	fmt.Printf("Send: %d\n", n)
	conns = append(conns, conn)
	fmt.Printf("New Connections: %d\n", len(conns))
}

func server(listen string) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen error: %s\n", err)
		os.Exit(3)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "accept error: %s\n", err)
			continue
		} else {
			fmt.Fprintf(os.Stdout, "incoming connection: %s\n", conn.RemoteAddr())
		}
		conn.SetDeadline(time.Now().Add(SECOND_NS * 4))
		/*
			for recv := 0; recv < sendCount; {
				r, err := conn.Read(buffer[:])
				if err != nil {
					fmt.Fprintf(os.Stderr, "read data error: %s\n", err)
					break
				} else {
					fmt.Fprintf(os.Stderr, "recv: %d\n", r)
				}
				recv += r
			}
		*/
		conns = append(conns, conn)
		fmt.Printf("Accept Connections: %d\n", len(conns))
	}
}

func run_connection(conn net.Conn) {
	defer conn.Close()
	var targetConn net.Conn
	var running bool = true
	go recv(conn, targetConn, &running)
	go send(conn, targetConn, &running)
	for running {
		time.Sleep(100000000)
	}
}

func recv(conn net.Conn, targetConn net.Conn, running *bool) {
	if targetConn != nil {
		defer targetConn.Close()
	}
	for {
		buffer := make([]byte, 512)
		n, err := conn.Read(buffer[0:])
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "recv error: %s", err)
			os.Exit(3)
		}
		if n == 0 {
			fmt.Fprintf(os.Stderr, "Recv Zero byte???!!!\n")
		} else {
			if targetConn == nil {
				os.Stdout.Write(buffer[0:n])
			} else {
				n, err = targetConn.Write(buffer[0:n])
				if err != nil {
					fmt.Fprintf(os.Stderr, "relay data error: %s\n", err)
					break
				} else {
					fmt.Fprintf(os.Stdout, "relay inbound data: %d bytes\n", n)
				}

			}
		}
	}
	*running = false
}

func send(conn net.Conn, targetConn net.Conn, running *bool) {
	for {
		buffer := make([]byte, 512)
		var n int
		var err error
		if targetConn == nil {
			n, err = os.Stdin.Read(buffer[0:])
		} else {
			n, err = targetConn.Read(buffer[0:])
			if err != nil {
				fmt.Fprintf(os.Stderr, "read data error: %s\n", err)
				break
			}
			fmt.Fprintf(os.Stdout, "relay outbound data: %d bytes\n", n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "sending error, reading failed: %s\n", err)
			os.Exit(3)
		}
		conn.Write(buffer[0:n])
	}
	*running = false
}

func main() {
	dest := flag.String("c", "", "The destination address with port")
	nConn := flag.Int("n", 1, "The number of connect for client to create")
	listen := flag.String("l", "", "The destination address with port")
	flag.Parse()

	if *dest != "" {
		for i := 0; i < *nConn; i++ {
			client(*dest)
		}
		fmt.Printf("Connection test end, press any key to quit...\n")
		inputBuff := bufio.NewReader(os.Stdin)
		inputBuff.ReadString('\n')
	} else if *listen != "" {
		server(*listen)
	} else {
		flag.PrintDefaults()
		os.Exit(1)
	}

}
