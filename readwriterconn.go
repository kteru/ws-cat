package main

import (
	"io"

	"github.com/smith-30/websocket"
)

// ReadWriterConn wraps the *websocket.Conn to satisfy the io.ReadWriter interface.
type ReadWriterConn struct {
	*websocket.Conn
	rd io.Reader
}

// Read implements the io.Reader interface.
func (rwc *ReadWriterConn) Read(p []byte) (int, error) {
again:
	if rwc.rd == nil {
		_, rd, err := rwc.NextReader()
		if err != nil {
			return 0, err
		}
		rwc.rd = rd
	}

	n, err := rwc.rd.Read(p)
	if err == io.EOF {
		rwc.rd = nil
		goto again
	}

	return n, err
}

// Write implements the io.Writer interface.
func (rwc *ReadWriterConn) Write(p []byte) (int, error) {
	wr, err := rwc.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return 0, err
	}

	n, err := wr.Write(p)
	wr.Close()

	return n, err
}
