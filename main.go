package main

import (
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"
)

var (
	mode    = flag.String("mode", "client", "client/server")
	address = flag.String("address", "127.0.0.1:24873", "")
	target  = flag.String("target", "127.0.0.1:22", "")
	keyfile = flag.String("keyfile", "", "")
	period  = flag.Duration("period", 10*time.Millisecond, "")
)

type StdRWC struct {
}

func (s *StdRWC) Read(data []byte) (int, error) {
	return os.Stdin.Read(data)
}

func (s *StdRWC) Write(data []byte) (int, error) {
	return os.Stdout.Write(data)
}

func (s *StdRWC) Close() error {
	_ = os.Stdin.Close()
	_ = os.Stdout.Close()
	return nil
}

func main() {
	flag.Parse()
	if *keyfile == "" {
		log.Fatalf("Please provide -keyfile")
	}
	key, err := ioutil.ReadFile(*keyfile)
	if err != nil {
		log.Fatalf("Failed to read keyfile %s: %s", *keyfile, err)
	}
	if len(key) < 8 {
		log.Fatalf("Key is too short")
	}
	if *mode == "client" {
		conn, err := net.Dial("tcp", *address)
		if err != nil {
			log.Fatalf("Failed to connect to %s: %s", *address, err)
		}
		err = connect(
			&StdRWC{}, conn,
			string(key),
			"client->server",
			"server->client",
			1000, *period,
		)
		if err != nil {
			log.Fatalf("Failed: %s", err)
		}
	} else if *mode == "server" {
		ln, err := net.Listen("tcp", *address)
		if err != nil {
			log.Fatalf("Failed to listen on %s: %s", *address, err)
		}
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Fatalf("Failed to accept: %s", err)
			}
			go func() {
				var conn2 io.ReadWriteCloser
				if *target != "" {
					conn2, err = net.Dial("tcp", *target)
					if err != nil {
						log.Fatalf("connecting %s: %s", *target, err)
					}
				} else {
					conn2 = &StdRWC{}
				}
				err = connect(
					conn2, conn,
					string(key),
					"server->client",
					"client->server",
					1000, *period,
				)
				if err != nil {
					log.Fatalf("Failed: %s", err)
				}
			}()
		}
	}
}
