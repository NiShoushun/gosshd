package gosshd

import (
	"golang.org/x/crypto/ssh"
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

// 从 ssh 包中导出的数据结构，
// 包含请求包对应结构体，用于解析 Request 的 payload. 解析方式定义于 rfc 4254 https://datatracker.ietf.org/doc/html/rfc4254；
// 以及导出的密码学算法名称。

type PtyRequestMsg struct {
	Term     string
	Columns  uint32
	Rows     uint32
	Width    uint32
	Height   uint32
	Modelist string
}
type ExecMsg struct {
	Command string
}

type PtyWindowChangeMsg struct {
	Columns uint32
	Rows    uint32
	Width   uint32
	Height  uint32
}

type SetenvRequest struct {
	Name  string
	Value string
}

type SubsystemRequestMsg struct {
	Subsystem string
}

type Signal string

const (
	SIGABRT Signal = "ABRT"
	SIGALRM Signal = "ALRM"
	SIGFPE  Signal = "FPE"
	SIGHUP  Signal = "HUP"
	SIGILL  Signal = "ILL"
	SIGINT  Signal = "INT"
	SIGKILL Signal = "KILL"
	SIGPIPE Signal = "PIPE"
	SIGQUIT Signal = "QUIT"
	SIGSEGV Signal = "SEGV"
	SIGTERM Signal = "TERM"
	SIGUSR1 Signal = "USR1"
	SIGUSR2 Signal = "USR2"
)

var Signals = map[Signal]int{
	SIGABRT: 6,
	SIGALRM: 14,
	SIGFPE:  8,
	SIGHUP:  1,
	SIGILL:  4,
	SIGINT:  2,
	SIGKILL: 9,
	SIGPIPE: 13,
	SIGQUIT: 3,
	SIGSEGV: 11,
	SIGTERM: 15,
}

type SignalMsg struct {
	Signal Signal
}

func (s Signal) String() string {
	return string(s)
}
func (s Signal) Signal() {

}
