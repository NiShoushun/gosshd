package gosshd

import (
	"golang.org/x/crypto/ssh"
	"net"
)

const (
	ReqShell     = "shell"
	ReqPty       = "pty-req"
	ReqExec      = "exec"
	ReqWinCh     = "window-change"
	ReqEnv       = "env"
	ReqSignal    = "signal"
	ReqSubsystem = "subsystem"
	ReqExit      = "exit"
	ExitStatus   = "exit-status"
)

// Request ssh 包 Request 类型指针的包装
type Request struct {
	*ssh.Request
}

type Session interface {
	SSHChannel
	User() *User
	ClientVersion() string
	ServerVersion() string
	RemoteAddr() net.Addr
	LocalAddr() net.Addr

	// Permissions 用于身份验证回调函数的返回值，包含用户的权限信息，取决于具体的身份认证 callback 实现
	Permissions() *Permissions
	Conn() ssh.Conn
	Server() *SSHServer

	Channel() SSHChannel

	PtyMsg() <-chan *PtyRequestMsg
	WinchMsg() <-chan *PtyWindowChangeMsg
	SignalMsg() <-chan *SignalMsg

	PutPtyMsg(*PtyRequestMsg)
	PutWinchMsg(*PtyWindowChangeMsg)
	PutSignalMsg(*SignalMsg)

	Env() []string   // 获取保存的环境变量
	SetEnv([]string) // 设置环境变量

	Done() <-chan struct{} // 取消子协程的通知
	Ctx() Context          // 应当返回本连接对应的全局上下文
}
