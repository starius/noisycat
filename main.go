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
	keyfile = flag.String("keyfile", "", "Path to shared key file")
	period  = flag.Duration("period", 10*time.Millisecond, "")
	timeout = flag.Duration("timeout", 5*time.Second, "")
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
		cconn := &TimeoutConn{
			c:       conn,
			timeout: *timeout,
		}
		err = connect(
			&StdRWC{}, cconn,
			key,
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
			cconn := &TimeoutConn{
				c:       conn,
				timeout: *timeout,
			}
			go func() {
				defer conn.Close()
				var pconn io.ReadWriteCloser
				if *target != "" {
					pconn, err = net.Dial("tcp", *target)
					if err != nil {
						log.Printf("connecting %s: %s", *target, err)
						return
					}
					defer pconn.Close()
				} else {
					pconn = &StdRWC{}
				}
				err = connect(
					pconn, cconn,
					key,
					"server->client",
					"client->server",
					1000, *period,
				)
				if err != nil {
					log.Printf("Failed: %s", err)
					return
				}
			}()
		}
	}
}
