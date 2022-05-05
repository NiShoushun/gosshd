package gosshd

import "golang.org/x/crypto/ssh"

// RFC 4254 规定的 4 种 channel 类型
const (
	SessionTypeChannel    = "session"         // session 类型的 channel open 请求. RFC 4254 6.1.
	DirectTcpIpChannel    = "direct-tcpip"    // direct-tcpip 类型的 channel open 请求. RFC 4254 7.2.
	X11Channel            = "x11"             // x11 类型的 channel open 请求. RFC 4254 6.3.2
	ForwardedTCPIPChannel = "forwarded-tcpip" // forwarded-tcpip 类型的 channel open 请求. RFC 4254 7.2.
)

// RejectionReason 拒绝客户端通道建立请求的原因， 定义于 RFC 4254 5.1.
type RejectionReason uint32

const (
	Prohibited         RejectionReason = 1
	ConnectionFailed                   = 2
	UnknownChannelType                 = 3
	ResourceShortage                   = 4
)

type SSHConn interface {
	ssh.Conn
}

type SSHNewChannel interface {
	ssh.NewChannel
}

type SSHChannel interface {
	ssh.Channel
}

type NewChannelHandleFunc func(channel SSHNewChannel, ctx Context)
