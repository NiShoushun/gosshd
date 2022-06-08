package gosshd

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net"
	"sync"
)

const (
	Version1 = "SSH-1.0-"
	Version2 = "SSH-2.0-"
)

// TransformConnCallback listener 监听并接受一个网络连接后，要立即执行的回调函数；返回
// 当返回的 error 不为 nil 时，将停止继续处理并关闭该网络连接
type TransformConnCallback func(net.Conn) (net.Conn, error)

// SSHConnFailedLogCallback 尝试建立 SSH 连接失败之后，要立即执行的回调函数，用于记录失败信息等
type SSHConnFailedLogCallback func(reason error, conn net.Conn)

// SSHConnLogCallback 建立 SSH 连接成功之后，要立即执行的回调函数。
// 此时的 sshCtx 中已经包含了基本的数据；
// 当该函数返回的 error 不为 nil 时，将会停止下一步，且 SSH 连接会被关闭。
type SSHConnLogCallback func(ctx Context) error

// LookupUserCallback 根据用户名，获取用户详细数据实例
type LookupUserCallback func(metadata ConnMetadata) (*User, error)

// GlobalRequestCallback 当成功建立连接后，对于全局请求的处理，例如 “tcpip-forward” 以及 “cancel-tcpip-forward“ 等请求处理，
// 这类要求通常是为了客户端让服务端向客户端打开一个通道，进行数据转发。
type GlobalRequestCallback func(ctx Context, request Request)

type ContextBuilder func(sshd *SSHServer) (Context, context.CancelFunc)

type SSHServer struct {
	*sync.Mutex
	listener         net.Listener
	ssh.ServerConfig // ssh 包下的 ServerConfig

	ContextBuilder // 用于生成自定义的 Context

	// 用于建立连接后，通过用户名，找到用户信息，如果返回的 err 不为 nil，则将终止连接
	LookupUserCallback

	// 该字段作用于身份认证之前，对服务器接受的网络连接接口实例进行相应操作，
	// 用于设置超时、原始数据处理等，也可以返回相应的接口升级实例；如果返回 error 不为 nil 则将终止该连接。
	TransformConnCallback
	SSHConnFailedLogCallback                                  // 用于记录 ssh 建立失败原因
	SSHConnLogCallback                                        // 建立 ssh 连接后的处理函数，如果返回 error 不为 nil，则终止连接
	GlobalRequestHandlers    map[string]GlobalRequestCallback // 建立 ssh 连接后的处理全局的 request；如果未设置则拒绝其请求

	// 当接收到客户端通道建立请求是，会根据类型由对应的回调函数进行处理。
	NewChannelHandlers map[string]NewChannelHandleFunc // 当 ChannelHandlers 中不存在对应类型 channel 的处理器时，由该 handler 进行处理

	conns map[SSHConn]context.CancelFunc // 已经建立的 SSHConn 连接与取消函数的映射
}

// NewSSHServer 初始化并返回一个 SSHServer 实例
func NewSSHServer() *SSHServer {
	server := &SSHServer{
		Mutex:                 &sync.Mutex{},
		ServerConfig:          ssh.ServerConfig{},
		ContextBuilder:        NewContext,
		NewChannelHandlers:    map[string]NewChannelHandleFunc{},
		GlobalRequestHandlers: map[string]GlobalRequestCallback{},
		conns:                 map[SSHConn]context.CancelFunc{},
	}
	server.ServerVersion = "SSH-2.0-GoSSHD"
	return server
}

// SetVersion 设置服务端版本号，1 表示 'SSH-1.0-'；其它 表示 'SSH-2.0-'；
// suffix 为紧跟着版本号的后缀。
func (sshd *SSHServer) SetVersion(version int, suffix string) {
	if version == 1 {
		sshd.ServerVersion = Version1 + suffix
	} else {
		sshd.ServerVersion = Version2 + suffix
	}
}

// SetPasswdCallback 设置密码认证处理回调函数
func (sshd *SSHServer) SetPasswdCallback(cb PasswdCallback) {
	sshd.PasswordCallback = WrapPasswdCallback(cb)
}

// SetPublicKeyCallback 设置主机公钥认证处理回调
func (sshd *SSHServer) SetPublicKeyCallback(cb PublicKeyCallback) {
	sshd.PublicKeyCallback = WrapPublicKeyCallback(cb)
}

// SetKeyboardInteractiveChallengeCallback 设置轮询问答认证处理回调函数
func (sshd *SSHServer) SetKeyboardInteractiveChallengeCallback(cb KeyboardInteractiveChallengeCallback) {
	sshd.KeyboardInteractiveCallback = WrapKeyboardInteractiveChallenger(cb)
}

// SetAuthLogCallback SSH 服务器与客户端进行身份认证时，调用的函数；可以利用该回调函数记录连接信息与验证方式，并做出对应处理
func (sshd *SSHServer) SetAuthLogCallback(cb AuthLogCallback) {
	sshd.AuthLogCallback = WrapAuthLogCallback(cb)
}

// SetBannerCallback 当服务器成功与客户端建立 SSH 连接时，发送至给客户端的字符串信息。
func (sshd *SSHServer) SetBannerCallback(cb BannerCallback) {
	sshd.BannerCallback = WrapBannerCallback(cb)
}

// NewChannel 添加对应类型的 channel 请求处理函数
func (sshd *SSHServer) NewChannel(ctype string, handleFunc NewChannelHandleFunc) {
	sshd.NewChannelHandlers[ctype] = handleFunc
}

// NewGlobalRequest 添加对应类型的 global request 请求处理函数
func (sshd *SSHServer) NewGlobalRequest(ctype string, handleFunc GlobalRequestCallback) {
	sshd.GlobalRequestHandlers[ctype] = handleFunc
}

func (sshd *SSHServer) addSSHConnWithCancel(conn SSHConn, cancelFunc context.CancelFunc) {
	sshd.Lock()
	defer sshd.Unlock()
	if sshd.conns == nil {
		sshd.conns = make(map[SSHConn]context.CancelFunc)
	}
	sshd.conns[conn] = cancelFunc
}

// DelSSHConn 执行 conn 对应的cancel 并删除 conn
func (sshd *SSHServer) DelSSHConn(conn SSHConn) {
	sshd.Lock()
	defer sshd.Unlock()
	if cancel, ok := sshd.conns[conn]; ok {
		cancel()
		conn.Close() // fixme 一般情况下只有关闭的  conn 才能运行到此处，为了保险再次进行关闭
	}
	delete(sshd.conns, conn)
}

// AddHostKey 加载密钥，hostkey 应该是服务端私钥文件的全部内容
// 返回的 err 不为 nil 说明密钥内容解析失败。
func (sshd *SSHServer) AddHostKey(hostKey []byte) error {
	sshd.Lock()
	defer sshd.Unlock()
	private, err := ssh.ParsePrivateKey(hostKey)
	if err != nil {
		return err
	}
	sshd.ServerConfig.AddHostKey(private)
	return nil
}

// AddHostSigner 加载 Signer 形式的密钥，
// 返回的 err 不为 nil 说明密钥内容解析失败。
func (sshd *SSHServer) AddHostSigner(signer Signer) {
	sshd.Lock()
	defer sshd.Unlock()
	sshd.ServerConfig.AddHostKey(signer)
}

// LoadHostKey 从指定的文件中加载密钥，
// 返回的 err 不为 nil 说明密钥内容解析失败。
func (sshd *SSHServer) LoadHostKey(path string) error {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	return sshd.AddHostKey(content)
}

// Close 关闭服务器网络监听器，关闭所有的已经建立的 SSH 连接
// 注意：该方法并不保证 ChannelHandler 与 RequestHandler 运行时开启的协程被取消，这取决于传入的接口的实现方式，
// 所以需要保证开启的协程可以成功接收到 Context Done() 方法的信号，并退出协程
func (sshd *SSHServer) Close() error {
	err := sshd.listener.Close()
	for con, _ := range sshd.conns {
		err = con.Close()
		sshd.DelSSHConn(con)
	}
	return err
}

// Shutdown 关闭服务器，调用所有连接产生的 cancelFunc，尝试取消所有的处理协程
func (sshd *SSHServer) Shutdown() error {
	sshd.Lock()
	defer sshd.Unlock()
	err := sshd.listener.Close()
	sshd.listener = nil

	// 遍历所有的 sshConn 对应的 cancel， 并执行
	for con, cancel := range sshd.conns {
		cancel()
		err := con.Close()
		sshd.DelSSHConn(con)
		if err != nil {
			return err
		}
	}
	return err
}

// ListenAndServe 监听tcp网络并启动 SSH 服务
// network 为 "tcp", "tcp4", "tcp6", "unix" or "unixpacket"
func (sshd *SSHServer) ListenAndServe(address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	return sshd.Serve(listener)
}

// Serve 使用传入的监听器进行监听，并启动 SSH 服务
func (sshd *SSHServer) Serve(listener net.Listener) error {
	if sshd.ContextBuilder == nil {
		return NoContextBuilderErr
	}
	sshd.listener = listener
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		// 尝试对网络接口进行转换
		if sshd.TransformConnCallback != nil {
			transformedConn, err := sshd.TransformConnCallback(conn)
			if err != nil {
				continue
			}
			conn = transformedConn
		}
		go sshd.HandleConn(conn)
	}
}

func (sshd *SSHServer) HandleConn(conn net.Conn) {
	ctx, cancel := sshd.ContextBuilder(sshd)
	// 建立 ssh 连接
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, &sshd.ServerConfig)
	if err != nil {
		if sshd.SSHConnFailedLogCallback != nil {
			sshd.SSHConnFailedLogCallback(err, conn)
		}
		conn.Close()
		return
	}
	if sshd.LookupUserCallback != nil {
		user, err := sshd.LookupUserCallback(sshConn)
		if err != nil {
			return
		}
		ctx.SetUser(user)
	}
	// 至此已经通过所有校验，添加信息至上下文中
	if sshConn.Permissions != nil {
		ctx.SetPermissions(&Permissions{
			CriticalOptions: sshConn.Permissions.CriticalOptions,
			Extensions:      sshConn.Permissions.Extensions,
		})
	} else {
		ctx.SetPermissions(nil)
	}
	ctx.SetRemoteAddr(sshConn.RemoteAddr())
	ctx.SetLocalAddr(sshConn.LocalAddr())
	ctx.SetServerVersion(string(sshConn.ServerVersion()))
	ctx.SetClientVersion(string(sshConn.ClientVersion()))
	ctx.SetConn(sshConn)

	if sshd.SSHConnLogCallback != nil {
		err := sshd.SSHConnLogCallback(ctx)
		if err != nil {
			sshConn.Close()
			return
		}
	}
	sshd.addSSHConnWithCancel(sshConn, cancel)

	// 全局请求处理
	if sshd.GlobalRequestHandlers != nil {
		go sshd.serveGlobalRequest(ctx, reqs)
	} else {
		go DiscardRequests(ctx, reqs)
	}

	// 并发处理每一个客户端请求建立的 Channel
	for {
		select {
		case newChannel := <-chans:
			if newChannel == nil {
				//fmt.Println("break")
				goto del // 连接已经关闭，删除该 SSHConn
			}
			//fmt.Println("channel:", newChannel.ChannelType())
			if handle, ok := sshd.NewChannelHandlers[newChannel.ChannelType()]; ok {
				go handle(ctx, newChannel)
			} else {
				newChannel.Reject(UnknownChannelType, fmt.Sprintf("not support %s", newChannel.ChannelType()))
			}
		case <-ctx.Done(): // 当 Context 的 cancelFunc 被调用时，退出函数
			goto del
		}
	}
del: // 删除
	sshd.DelSSHConn(sshConn)
}

func (sshd *SSHServer) serveGlobalRequest(ctx Context, requests <-chan *ssh.Request) {
	for {
		select {
		case <-ctx.Done():
			return
		case request := <-requests:
			if request == nil {
				return
			}
			//fmt.Println("global", request.Type, string(request.Payload))
			if handler, ok := sshd.GlobalRequestHandlers[request.Type]; ok {
				go handler(ctx, Request{request})
			} else {
				request.Reply(false, nil)
			}
		}
	}
}

var NoContextBuilderErr = errors.New("no context builder")
