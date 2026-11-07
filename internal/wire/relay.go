package wire

import (
	"bufio"
	"io"
	"net"
)

type BufferedConn struct {
	net.Conn
	Reader *bufio.Reader
}

func (conn *BufferedConn) Read(data []byte) (int, error) {
	return conn.Reader.Read(data)
}

func (conn *BufferedConn) CloseWrite() error {
	return CloseWrite(conn.Conn)
}

func CloseWrite(conn net.Conn) error {
	if writer, ok := conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return conn.Close()
}

func Relay(client, upstream net.Conn) {
	results := make(chan error, 2)
	copyStream := func(destination, source net.Conn) {
		_, err := io.Copy(destination, source)
		if err == nil {
			err = CloseWrite(destination)
		}
		results <- err
	}
	go copyStream(upstream, client)
	go copyStream(client, upstream)
	if <-results != nil {
		client.Close()
		upstream.Close()
	}
	<-results
}
