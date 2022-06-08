package serv

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
	sshd.NewChannel(gosshd.SessionTypeChannel, func(ctx gosshd.Context, c gosshd.NewChannel) {
		handler := NewSessionChannelHandler(10, 10, 10, 0)
		handler.SetDefaults()
		handler.Start(ctx, c)
	})
	sshd.NewChannel(gosshd.DirectTcpIpChannel, NewTcpIpDirector(0).HandleDirectTcpIP)
	fhandler := NewForwardedTcpIpHandler(0)
	sshd.NewGlobalRequest(gosshd.GlobalReqTcpIpForward, fhandler.ServeForward)
	sshd.NewGlobalRequest(gosshd.GlobalReqCancelTcpIpForward, fhandler.CancelForward)
	return sshd, nil
}
