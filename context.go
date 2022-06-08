package gosshd

import (
	"context"
	"golang.org/x/crypto/ssh"
	"net"
	"sync"
)

// Context 包含各类 handler 所需信息以及一个 context.Context ，必要信息应该保证在 handler 调用之前被添加。
// Context 的作用域为单个客户端的整个连接过程。
type Context interface {
	context.Context // 用于存储键值数据，以及获取该 context 实例相关 cancel，使退出 handler 函数的执行
	sync.Locker     // 不同处理器争夺临界资源时可能会用到

	SetValue(name interface{}, data interface{})
	SetClientVersion(version string)
	SetConn(conn ssh.Conn)
	SetServerVersion(version string)
	// SetPermissions 应在 ssh 身份验证的回调函数中进行填充
	SetPermissions(permissions *Permissions)
	SetLocalAddr(addr net.Addr)
	SetRemoteAddr(addr net.Addr)
	SetUser(user *User)

	User() *User
	ClientVersion() string
	ServerVersion() string
	RemoteAddr() net.Addr
	LocalAddr() net.Addr

	// Permissions 用于身份验证回调函数的返回值，包含用户的权限信息，取决于具体的身份认证 callback 实现
	Permissions() *Permissions
	Conn() ssh.Conn
	Server() *SSHServer
}

// SSHContext 基本的上下文
type SSHContext struct {
	context.Context // 应该用于退出该 context 实例相关的 handler 函数的执行
	sync.Mutex
	permissions *Permissions
	sversion    string
	cversion    string
	laddr       net.Addr
	raddr       net.Addr
	conn        ssh.Conn
	user        *User
	server      *SSHServer
}

// NewContext 创建一个 SSHContext
func NewContext(sshd *SSHServer) (Context, context.CancelFunc) {
	innerCtx, cancel := context.WithCancel(context.Background())
	ctx := &SSHContext{
		Context: innerCtx,
		Mutex:   sync.Mutex{},
	}
	ctx.server = sshd
	return ctx, cancel
}

func (ctx *SSHContext) UseConnMeta(meta ConnMetadata) {
	ctx.SetLocalAddr(meta.LocalAddr())
	ctx.SetClientVersion(string(meta.ClientVersion()))
	ctx.SetServerVersion(string(meta.ServerVersion()))
	ctx.SetRemoteAddr(meta.RemoteAddr())
}

func (ctx *SSHContext) SetConn(conn ssh.Conn) {
	ctx.conn = conn
}
func (ctx *SSHContext) SetServerVersion(version string) {
	ctx.sversion = version
}

func (ctx *SSHContext) SetClientVersion(version string) {
	ctx.cversion = version
}

func (ctx *SSHContext) SetPermissions(permissions *Permissions) {
	ctx.permissions = permissions
}

func (ctx *SSHContext) SetLocalAddr(addr net.Addr) {
	ctx.laddr = addr
}
func (ctx *SSHContext) SetRemoteAddr(addr net.Addr) {
	ctx.raddr = addr
}

func (ctx *SSHContext) SetUser(user *User) {
	ctx.user = user
}

// SetValue 设置值，会上锁
func (ctx *SSHContext) SetValue(key, value interface{}) {
	ctx.Lock()
	defer ctx.Unlock()
	ctx.Context = context.WithValue(ctx.Context, key, value)
}

func (ctx *SSHContext) User() *User {
	return ctx.user
}

func (ctx *SSHContext) SessionID() string {
	return string(ctx.conn.SessionID())
}

func (ctx *SSHContext) ClientVersion() string {
	return ctx.cversion
}

func (ctx *SSHContext) ServerVersion() string {
	return ctx.sversion
}

func (ctx *SSHContext) RemoteAddr() net.Addr {
	return ctx.raddr
}

func (ctx *SSHContext) LocalAddr() net.Addr {
	return ctx.laddr
}

func (ctx *SSHContext) Permissions() *Permissions {
	return ctx.permissions
}

func (ctx *SSHContext) Conn() ssh.Conn {
	return ctx.conn
}

func (ctx *SSHContext) Server() *SSHServer {
	return ctx.server
}
