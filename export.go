package gosshd

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

// ssh 包导出的算法密码学名称

// SupportedCiphers 支持的加密算法
var SupportedCiphers = []string{
	"aes128-ctr", "aes192-ctr", "aes256-ctr",
	"aes128-gcm@openssh.com",
	"chacha20-poly1305@openssh.com",
	"arcfour256", "arcfour128", "arcfour",
	"aes128-cbc",
	"3des-cbc",
}

// PreferredCiphers 默认使用的加密算法
var PreferredCiphers = []string{
	"aes128-gcm@openssh.com",
	"chacha20-poly1305@openssh.com",
	"aes128-ctr", "aes192-ctr", "aes256-ctr",
}

// PreferredKexAlgos 默认的密钥交换算法
var PreferredKexAlgos = []string{
	kexAlgoCurve25519SHA256, kexAlgoCurve25519SHA256LibSSH,
	kexAlgoECDH256, kexAlgoECDH384, kexAlgoECDH521,
	kexAlgoDH14SHA256, kexAlgoDH14SHA1,
}

// 密钥交换算法
const (
	kexAlgoDH1SHA1                = "diffie-hellman-group1-sha1"
	kexAlgoDH14SHA1               = "diffie-hellman-group14-sha1"
	kexAlgoDH14SHA256             = "diffie-hellman-group14-sha256"
	kexAlgoECDH256                = "ecdh-sha2-nistp256"
	kexAlgoECDH384                = "ecdh-sha2-nistp384"
	kexAlgoECDH521                = "ecdh-sha2-nistp521"
	kexAlgoCurve25519SHA256LibSSH = "curve25519-sha256@libssh.org"
	kexAlgoCurve25519SHA256       = "curve25519-sha256"

	// For the following kex only the client half contains a production
	// ready implementation. The server half only consists of a minimal
	// implementation to satisfy the automated tests.
	kexAlgoDHGEXSHA1   = "diffie-hellman-group-exchange-sha1"
	kexAlgoDHGEXSHA256 = "diffie-hellman-group-exchange-sha256"
)

// SupportedMACs 支持的消息摘要算法
var SupportedMACs = []string{
	"hmac-sha2-256-etm@openssh.com", "hmac-sha2-256", "hmac-sha1", "hmac-sha1-96",
}
