package utils

import (
	"github.com/nishoushun/gosshd"
)

// SimpleServerOnUnix 创建一个默认的 ssh server 实例，所有的处理器均为默认处理器
// 使用 Open-SSH 服务器密钥作为主机密钥；只适用于 Unix 系统
func SimpleServerOnUnix() (*gosshd.SSHServer, error) {
	sshd := gosshd.NewSSHServer()
	err := sshd.LoadHostKey(RSAHostKeyPath)
	err = sshd.LoadHostKey(ECDSAHostKeyPath)
	err = sshd.LoadHostKey(ED25519HostKeyPath)
	if err != nil {
		return nil, err
	}
	sshd.LookupUserCallback = func(metadata gosshd.ConnMetadata) (*gosshd.User, error) {
		return UnixUserInfo(metadata.User())
	}
	sshd.SetPasswdCallback(CheckUnixPasswd)
	sshd.SetNewChanHandleFunc(gosshd.SessionTypeChannel, func(c gosshd.SSHNewChannel, ctx gosshd.Context) {
		handler := NewSessionChannelHandler(10, 10, 10, 0)
		handler.SetDefaults()
		handler.Start(c, ctx)
	})
	sshd.SetNewChanHandleFunc(gosshd.DirectTcpIpChannel, NewTcpIpDirector(0).HandleDirectTcpIP)
	fhandler := NewForwardedTcpIpHandler(0)
	sshd.SetGlobalRequestHandleFunc(gosshd.GlobalReqTcpIpForward, fhandler.ServeForward)
	sshd.SetGlobalRequestHandleFunc(gosshd.GlobalReqCancelTcpIpForward, fhandler.CancelForward)
	return sshd, nil
}
