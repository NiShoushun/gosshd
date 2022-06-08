package serv

import (
	"context"
	"github.com/nishoushun/gosshd"
	"golang.org/x/crypto/ssh"
	"net"
	"sync"
	"time"
)

func NewTcpIpDirector(timeout time.Duration) *TcpIpDirector {
	return &TcpIpDirector{
		timeout: timeout,
	}
}

// TcpIpDirector direct-tcpip 类型的 channel 处理。
// 客户端将会监听发送至本地 local-addr:local-port 并向远程服务器发送一个 direct-tcpip 通道建立请求，
// 之后将数据转发至 remote-addr:remote-port
type TcpIpDirector struct {
	timeout time.Duration
}

// HandleDirectTcpIP 开始处理一个 direct-tcpip 类型的信道，连接客户端发送的目标网络，并连接双方。
// net.DialTimeout 将会被调用，timeout 为 d 的 timeout 属性；
func (d *TcpIpDirector) HandleDirectTcpIP(ctx gosshd.Context, newChannel gosshd.NewChannel) {
	if newChannel.ChannelType() != gosshd.DirectTcpIpChannel {
		return
	}
	c, cancel := context.WithCancel(ctx)
	metadata := &gosshd.ChannelOpenDirectMsg{}
	if err := ssh.Unmarshal(newChannel.ExtraData(), metadata); err != nil {
		newChannel.Reject(ssh.Prohibited, "invalid tcp-ip metadata")
		return
	}

	// 从 sshd 实例中找到对应 ChannelHandler
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return
	}

	//fmt.Println("meta", metadata)

	//src := &net.TCPAddr{
	//	IP:   net.ParseIP(metadata.Src),
	//	Port: 48494,
	//	Zone: "",
	//}

	dst := &net.TCPAddr{
		IP:   net.ParseIP(metadata.Dest),
		Port: int(metadata.DPort),
		Zone: "",
	}
	//fmt.Println("dst", dst.String())

	//var conn net.Conn
	//conn, err = net.DialTCP("tcp", src, dst)
	//fmt.Println(err)
	//if err != nil {
	conn, err := net.DialTimeout("tcp", dst.String(), d.timeout)
	if err != nil {
		return
	}
	//fmt.Println("conn")
	//}
	var wg sync.WaitGroup
	wg.Add(2)

	go gosshd.DiscardRequests(requests, ctx)

	go func() {
		CopyBufferWithContext(channel, conn, nil, c)
		defer conn.Close()
		defer channel.Close()
		wg.Done()

	}()

	go func() {
		CopyBufferWithContext(conn, channel, nil, c)
		conn.Close()
		channel.Close()
		wg.Done()
	}()
	wg.Wait()
	cancel()
}
