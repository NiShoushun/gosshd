package serv

import (
	"context"
	"errors"
	"github.com/nishoushun/gosshd"
	"io"
)

var interruptedErr = errors.New("interrupted")
var errInvalidWrite = errors.New("invalid write result")

var invalidArg = errors.New("invalid arg")

// NewCopyOnWriteConn 写入网络数据时，复制数据至指定 Writer
func NewCopyOnWriteConn(channel gosshd.Channel, copyWriteTo io.Writer) (*copyWhenWrite, error) {
	if channel == nil || copyWriteTo == nil {
		return nil, invalidArg
	}
	return &copyWhenWrite{
		Channel:     channel,
		multiWriter: io.MultiWriter(channel, copyWriteTo),
	}, nil
}

// NewCopyOnReadConn 读取网络数据时时，复制数据至指定 Writer
func NewCopyOnReadConn(channel gosshd.Channel, copyReadTo io.Writer) (*copyOnReadConn, error) {
	if channel == nil || copyReadTo == nil {
		return nil, invalidArg
	}
	return &copyOnReadConn{
		Channel: channel,
		writer:  copyReadTo,
	}, nil
}

type copyWhenWrite struct {
	gosshd.Channel
	multiWriter io.Writer
}

func (c *copyOnReadConn) Read(b []byte) (n int, err error) {
	_, err = c.writer.Write(b)
	if err != nil {
		return
	}
	return c.Channel.Read(b)
}

func (c *copyWhenWrite) Write(b []byte) (n int, err error) {
	return c.multiWriter.Write(b)
}

// copyWhenWrite 写入网络时复制数据至指定 Writer
type copyOnReadConn struct {
	gosshd.Channel
	writer io.Writer
}

// CopyBufferWithContext 导出的 io.CopyBufferWithContext 函数，可传入 Context 对应的 cancelFunc 来终止流之间的复制
func CopyBufferWithContext(dst io.Writer, src io.Reader, buf []byte, ctx context.Context) (written int64, err error) {
	// If the reader has a WriteTo method, use it to do the copy.
	// Avoids an allocation and a copy.
	if wt, ok := src.(io.WriterTo); ok {
		return wt.WriteTo(dst)
	}
	// Similarly, if the writer has a ReadFrom method, use it to do the copy.
	if rt, ok := dst.(io.ReaderFrom); ok {
		return rt.ReadFrom(src)
	}
	if buf == nil {
		size := 32 * 1024
		if l, ok := src.(*io.LimitedReader); ok && int64(size) > l.N {
			if l.N < 1 {
				size = 1
			} else {
				size = int(l.N)
			}
		}
		buf = make([]byte, size)
	}
	for {
		select {
		case <-ctx.Done():
			return written, interruptedErr
		default:
			nr, er := src.Read(buf)
			if nr > 0 {
				nw, ew := dst.Write(buf[0:nr])
				if nw < 0 || nr < nw {
					nw = 0
					if ew == nil {
						ew = errInvalidWrite
					}
				}
				written += int64(nw)
				if ew != nil {
					err = ew
					goto ret
				}
				if nr != nw {
					err = io.ErrShortWrite
					goto ret
				}
			}
			if er != nil {
				if er != io.EOF {
					err = er
				}
				goto ret
			}
		}
	}
ret:
	return written, err
}
