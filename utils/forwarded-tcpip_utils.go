package utils

import (
	"github.com/nishoushun/gosshd"
	"golang.org/x/crypto/ssh"
	"net"
	"strconv"
	"sync"
)

// ForwardedTcpIpRequestHandler 用于处理 tcpip-forward 全局请求
type ForwardedTcpIpRequestHandler struct {
	bufSize  int
	forwards map[string]net.Listener
	sync.Mutex
}

func NewForwardedTcpIpHandler(bufSize int) *ForwardedTcpIpRequestHandler {
	return &ForwardedTcpIpRequestHandler{
		bufSize:  bufSize,
		forwards: map[string]net.Listener{},
		Mutex:    sync.Mutex{},
	}
}

// HandleRequest 可用于注册 tcpip-forward 与 cancel-tcpip-forward 类型的全局请求的处理函数
func (h *ForwardedTcpIpRequestHandler) HandleRequest(request gosshd.Request, conn gosshd.SSHConn, ctx gosshd.Context) {
	switch request.Type {
	case gosshd.GlobalReqTcpIpForward:
		h.ServeForward(request, conn, ctx)
	case gosshd.GlobalReqCancelTcpIpForward:
		h.CancelForward(request, conn, ctx)
	default:
		request.Reply(false, nil)
	}
}

// ServeForward 处理 tcpip-forward 全局请求，监听请求消息中的地址与端口；
// 每当监听到一个新的网络连接，就向客户端发送一个 forwarded-tcpip 通道建立请求，转发连接内容
func (h *ForwardedTcpIpRequestHandler) ServeForward(request gosshd.Request, conn gosshd.SSHConn, ctx gosshd.Context) {
	forwardReq := &gosshd.RemoteForwardRequestMsg{}
	if err := ssh.Unmarshal(request.Payload, forwardReq); err != nil {
		request.Reply(false, invalidPayload)
		return
	}
	addr := net.JoinHostPort(forwardReq.BindAddr, strconv.Itoa(int(forwardReq.BindPort)))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		request.Reply(false, []byte(err.Error()))
		return
	}

	_, destPortStr, err := net.SplitHostPort(ln.Addr().String())
	destPort, err := strconv.Atoi(destPortStr)
	if err != nil {
		request.Reply(false, nil)
		return
	}

	request.Reply(true, nil)

	h.Lock()
	h.forwards[addr] = ln
	h.Unlock()

	go func() {
		select {
		case <-ctx.Done():
			h.CloseAndDel(addr)
		}
	}()

	for {
		remoteConn, err := ln.Accept()
		if err != nil {
			break
		}
		originAddr, orignPortStr, _ := net.SplitHostPort(ctx.RemoteAddr().String())
		originPort, _ := strconv.Atoi(orignPortStr)
		remoteForwardChannelDataMsg := ssh.Marshal(&gosshd.RemoteForwardChannelDataMsg{
			DestAddr:   forwardReq.BindAddr,
			DestPort:   uint32(destPort),
			OriginAddr: originAddr,
			OriginPort: uint32(originPort),
		})

		// 每监听到一个网络连接，就向客户端打开一个通道，然后转发数据
		go func() {
			channel, requests, err := conn.OpenChannel(gosshd.ForwardedTcpIpChannelType, remoteForwardChannelDataMsg)
			if err != nil {
				request.Reply(false, []byte(err.Error()))
				remoteConn.Close()
				return
			}

			go ssh.DiscardRequests(requests)

			var wbuf []byte = nil
			var rbuf []byte = nil

			if h.bufSize > 0 {
				wbuf = make([]byte, h.bufSize)
				rbuf = make([]byte, h.bufSize)
			}

			go func() {
				defer channel.Close()
				defer remoteConn.Close()
				CopyBufferWithContext(channel, remoteConn, rbuf, ctx.Done())
			}()

			go func() {
				defer channel.Close()
				defer remoteConn.Close()
				CopyBufferWithContext(remoteConn, channel, wbuf, ctx.Done())
			}()
		}()
	}
	h.CloseAndDel(addr)
}

func (h *ForwardedTcpIpRequestHandler) CancelForward(request gosshd.Request, conn gosshd.SSHConn, ctx gosshd.Context) {
	cancelReq := &gosshd.RemoteForwardCancelRequestMsg{}
	if err := ssh.Unmarshal(request.Payload, cancelReq); err != nil {
		request.Reply(false, invalidPayload)
		return
	}
	addr := net.JoinHostPort(cancelReq.BindAddr, strconv.Itoa(int(cancelReq.BindPort)))
	h.CloseAndDel(addr)
	request.Reply(true, nil)
}

// CloseAndDel 删除并关闭对应地址的 listener
func (h *ForwardedTcpIpRequestHandler) CloseAndDel(addr string) {
	h.Lock()
	defer h.Unlock()
	ln, ok := h.forwards[addr]
	if ok {
		ln.Close()
		delete(h.forwards, addr)
	}
}

// Del 删除对应地址的 listener
func (h *ForwardedTcpIpRequestHandler) Del(addr string) {
	h.Lock()
	defer h.Unlock()
	delete(h.forwards, addr)
}

var invalidPayload = []byte("invalid payload")
