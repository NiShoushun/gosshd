package utils

import (
	"errors"
	"io"
	"net"
)

var invalidArg = errors.New("invalid arg")

// NewCopyOnWriteConn 写入网络数据时，复制数据至指定 Writer
func NewCopyOnWriteConn(conn net.Conn, copyWriteTo io.Writer) (*copyOnWriteConn, error) {
	if conn == nil || copyWriteTo == nil {
		return nil, invalidArg
	}
	return &copyOnWriteConn{
		Conn:        conn,
		multiWriter: io.MultiWriter(conn, copyWriteTo),
	}, nil
}

// NewCopyOnReadConn 读取网络数据时时，复制数据至指定 Writer
func NewCopyOnReadConn(conn net.Conn, copyReadTo io.Writer) (*copyOnReadConn, error) {
	if conn == nil || copyReadTo == nil {
		return nil, invalidArg
	}
	return &copyOnReadConn{
		Conn:   conn,
		writer: copyReadTo,
	}, nil
}

type copyOnWriteConn struct {
	net.Conn
	multiWriter io.Writer
}

func (c *copyOnReadConn) Read(b []byte) (n int, err error) {
	_, err = c.writer.Write(b)
	if err != nil {
		return
	}
	return c.Conn.Read(b)
}

func (c *copyOnWriteConn) Write(b []byte) (n int, err error) {
	return c.multiWriter.Write(b)
}

// copyOnWriteConn 写入网络时复制数据至指定 Writer
type copyOnReadConn struct {
	net.Conn
	writer io.Writer
}
