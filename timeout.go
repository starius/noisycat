package main

import (
	"net"
	"time"
)

type TimeoutConn struct {
	c       net.Conn
	timeout time.Duration
}

func (t *TimeoutConn) Read(p []byte) (n int, err error) {
	if err = t.c.SetReadDeadline(time.Now().Add(t.timeout)); err != nil {
		return 0, err
	}
	return t.c.Read(p)
}

func (t *TimeoutConn) Write(p []byte) (n int, err error) {
	if err = t.c.SetWriteDeadline(time.Now().Add(t.timeout)); err != nil {
		return 0, err
	}
	return t.c.Write(p)
}

func (t *TimeoutConn) Close() error {
	return t.c.Close()
}
