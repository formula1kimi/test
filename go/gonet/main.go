package main

import (
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

func client(dest string) {
	conn, err := net.DialTimeout("tcp", dest, time.Duration(SECOND_NS*5))
	if err != nil {
		fmt.Printf("Connect error: %s\n", err)
		os.Exit(2)
	}
	//conn.SetDeadline(time.Now().Add(SECOND_NS * 100))
	run_connection(conn, "")
}

func server(listen string, relay string) {
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

		//conn.SetDeadline(time.Now().Add(SECOND_NS * 100))
		go run_connection(conn, relay)
	}
}

func run_connection(conn net.Conn, relay string) {
	defer conn.Close()
	var targetConn net.Conn
	var err error
	if relay != "" {
		targetConn, err = net.DialTimeout("tcp", relay, time.Duration(SECOND_NS*5))
		if err != nil {
			fmt.Fprintf(os.Stderr, "connect to relayed dest error: %s\n", err)
			os.Exit(3)
		}
		fmt.Fprintf(os.Stderr, "connected to relay target: %s\n", relay)
		defer targetConn.Close()
	}
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
	listen := flag.String("l", "", "The destination address with port")
	relay := flag.String("r", "", "The target address and port realy packet to")
	flag.Parse()

	stdoutPath, _ := os.Readlink("/proc/self/fd/1")
	fmt.Fprintf(os.Stderr, "stdout redirect to: %s\n", stdoutPath)

	if *dest != "" {
		client(*dest)
	} else if *listen != "" {
		server(*listen, *relay)
	} else {
		flag.PrintDefaults()
		os.Exit(1)
	}

}
