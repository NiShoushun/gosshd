package utils

import (
	"context"
	"errors"
	"fmt"
	"github.com/anmitsu/go-shlex"
	"github.com/nishoushun/gosshd"
	"golang.org/x/crypto/ssh"
	"os/exec"
	"sync"
	"syscall"
)

type BasicSession struct {
	sync.Mutex // 修改值时的信号量
	gosshd.SSHChannel
	gosshd.Context
	winchCh chan *gosshd.PtyWindowChangeMsg // window-change 请求队列
	sigCh   chan *gosshd.SignalMsg          // signal 请求队列
	ptyCh   chan *gosshd.PtyRequestMsg      // pty-req 请求队列
	env     []string                        // 该 session 环境变量
	copyBuf []byte
}

// Channel 获取 Session 的底层通道 SSHChannel
func (session *BasicSession) Channel() gosshd.SSHChannel {
	return session.SSHChannel
}

// Close 调用 cancel 并关闭 SSHChannel
func (session *BasicSession) Close() error {
	return session.SSHChannel.Close()
}

// Env 获取设置的环境变量
func (session *BasicSession) Env() []string {
	return session.env
}

// SetEnv 设置环境变量，单个的形式应该为 %s=%s
func (session *BasicSession) SetEnv(env []string) {
	session.env = env
}

// PtyMsg 从缓存队列中取出最新的 pty-req 请求信息，若无，则阻塞至一个客户端发送一个新的 pty-req 请求
func (session *BasicSession) PtyMsg() <-chan *gosshd.PtyRequestMsg {
	return session.ptyCh
}

// WinchMsg 从缓存队列中取出最新的 window-change 请求信息，若无，则阻塞至一个客户端发送一个新的 window-change 请求
func (session *BasicSession) WinchMsg() <-chan *gosshd.PtyWindowChangeMsg {
	return session.winchCh
}

// SignalMsg 从缓存队列中取出最新的 signal 请求信息，若无，则阻塞至一个客户端发送一个新的 signal 请求
func (session *BasicSession) SignalMsg() <-chan *gosshd.SignalMsg {
	return session.sigCh
}

// PutPtyMsg 放入 pty-req 请求信息至缓存队列中，若队列满，则阻塞至一个 pty-req 请求被取出
func (session *BasicSession) PutPtyMsg(msg *gosshd.PtyRequestMsg) {
	session.ptyCh <- msg
}

// PutWinchMsg 放入 window-change 请求信息至缓存队列中，若队列满，则阻塞至一个 window-change 请求被取出
func (session *BasicSession) PutWinchMsg(msg *gosshd.PtyWindowChangeMsg) {
	session.winchCh <- msg
}

// PutSignalMsg 放入 signal 请求信息至缓存队列中，若队列满，则阻塞至一个 signal 请求被取出
func (session *BasicSession) PutSignalMsg(msg *gosshd.SignalMsg) {
	session.sigCh <- msg
}

// Done 类似于 Context#Done() 方法，返回一个管道，用于取消该 Session 关联的所有的子协程
func (session *BasicSession) Done() <-chan struct{} {
	return session.Context.Done()
}

func (session *BasicSession) Ctx() gosshd.Context {
	return session.Context
}

// NewSessionChannelHandler  创建一个 DefaultSessionChanHandler。
// winMsgBufSize 为 window-change 消息队列最大长度；
// ptyMsgBufSize 为 pty-req 消息队列最大长度；
// sigMsgBufSize 为 signal 消息队列最大长度；
// copyBuf 用于客户端 与 session 数据流的缓存；
// 注意：消息队列最大长度设置的太小，容易导致死锁。
func NewSessionChannelHandler(winMsgBufSize, ptyMsgBufSize, sigMsgBufSize, copyBufSize int) *DefaultSessionChanHandler {
	if winMsgBufSize < 0 {
		winMsgBufSize = 1
	}

	if ptyMsgBufSize < 0 {
		ptyMsgBufSize = 1
	}

	if sigMsgBufSize < 0 {
		sigMsgBufSize = 1
	}

	handler := &DefaultSessionChanHandler{
		Mutex:         sync.Mutex{},
		winMsgBufSize: winMsgBufSize,
		ptyMsgBufSize: ptyMsgBufSize,
		sigMsgBufSize: sigMsgBufSize,
		copyBufSize:   copyBufSize,
		ReqHandlers:   map[string]HandleRequest{},
	}
	return handler
}

// SetDefaults 注册默认的请求处理函数
func (handler *DefaultSessionChanHandler) SetDefaults() {
	handler.SetReqHandler(gosshd.ReqPty, handler.HandlePtyReq)
	handler.SetReqHandler(gosshd.ReqShell, handler.HandleShellReq)
	handler.SetReqHandler(gosshd.ReqExec, handler.HandleExecReq)
	handler.SetReqHandler(gosshd.ReqSignal, handler.HandleSignalReq)
	handler.SetReqHandler(gosshd.ReqEnv, handler.HandleEnvReq)
	handler.SetReqHandler(gosshd.ReqWinCh, handler.HandleWinChangeReq)
	handler.SetReqHandler(gosshd.ReqExit, handler.HandleExit)
}

// HandleRequest 处理单个请求
type HandleRequest func(request gosshd.Request, session gosshd.Session) error

// ReqLogCallback 用于记录接受的请求，处理结果
// err 为处理函数返回的错误；rtype 为请求类型；wantReply 为是否需要回应客户端；payload 为请求附带的数据
type ReqLogCallback func(err error, rtype string, wantReply bool, payload []byte, context gosshd.Context)

type CreateSessionCallback func(gosshd.SSHChannel, gosshd.Context) gosshd.Session

// DefaultSessionChanHandler 一个处理 Session 类型 SSH 通道的 ChannelHandler
type DefaultSessionChanHandler struct {
	sync.Mutex
	winMsgBufSize int
	ptyMsgBufSize int
	sigMsgBufSize int
	copyBufSize   int
	ReqHandlers   map[string]HandleRequest
	ReqLogCallback
}

var InterruptedErr = errors.New("interrupted by Context")

var NotSessionTypeErr = errors.New("not session type channel")

// SetReqHandler 添加一个对应请求类型的处理函数
func (handler *DefaultSessionChanHandler) SetReqHandler(rtype string, f HandleRequest) {
	handler.ReqHandlers[rtype] = f
}

// Start 接受客户端的 session channel 请求建立，并开始开启子协程的方式处理 requests；
// 当所有请求处理完毕后或接收到一个 nil Request，将关闭该会话
func (handler *DefaultSessionChanHandler) Start(c gosshd.SSHNewChannel, ctx gosshd.Context) error {
	if c.ChannelType() != gosshd.SessionTypeChannel {
		return NotSessionTypeErr
	}
	channel, requests, err := c.Accept()
	if err != nil {
		return err
	}
	session := &BasicSession{
		Context:    ctx,
		SSHChannel: channel,
		Mutex:      sync.Mutex{},
		winchCh:    make(chan *gosshd.PtyWindowChangeMsg, handler.winMsgBufSize),
		ptyCh:      make(chan *gosshd.PtyRequestMsg, handler.ptyMsgBufSize),
		sigCh:      make(chan *gosshd.SignalMsg, handler.sigMsgBufSize),
		env:        make([]string, 0),
	}

	for {
		select {
		case <-ctx.Done():
			//fmt.Println("session close by shutdown")
			channel.Close()
			return InterruptedErr
		case request := <-requests:
			if request == nil {
				goto ret
			}
			go handler.ServeRequest(gosshd.Request{Request: request}, session, ctx)
		}
	}
ret:
	//fmt.Println("session close")
	return channel.Close()
}

// ServeRequest 从注册的请求处理函数中找到对应请求类型的函数，并调用；
// 处理函数返回的错误将被用于 handler 的 ReqLogCallback
func (handler *DefaultSessionChanHandler) ServeRequest(request gosshd.Request, session gosshd.Session, ctx gosshd.Context) {
	if reqHandler, ok := handler.ReqHandlers[request.Type]; ok {
		go func() {
			err := reqHandler(request, session)
			if handler.ReqLogCallback != nil {
				handler.ReqLogCallback(err, request.Type, request.WantReply, request.Payload, ctx)
			}
		}()
	} else {
		request.Reply(false, nil)
		if handler.ReqLogCallback != nil {
			handler.ReqLogCallback(fmt.Errorf("no handler for '%s' type", request.Type), request.Type, request.WantReply, request.Payload, ctx)
		}
	}
}

// HandleExit 接受退出请求，并关闭 Session
func (handler *DefaultSessionChanHandler) HandleExit(request gosshd.Request, session gosshd.Session) error {
	return handler.SendExitStatus(0, true, session)
}

func (handler *DefaultSessionChanHandler) HandleEnvReq(request gosshd.Request, session gosshd.Session) error {
	var payload *gosshd.SetenvRequest
	err := ssh.Unmarshal(request.Payload, &payload)
	if err != nil {
		return err
	}
	env := session.Env()
	session.SetEnv(append(env, fmt.Sprintf("%s=%s", payload.Name, payload.Value)))
	return request.Reply(true, nil)
}

// HandleSignalReq 解析客户端发送的窗口变换消息队列，并将其传入 session 窗口消息队列中
// 根据 RFC 4254 6.9. signal 类型请求不需要回复
func (handler *DefaultSessionChanHandler) HandleSignalReq(request gosshd.Request, session gosshd.Session) error {
	sigMsg := &gosshd.SignalMsg{}
	if err := ssh.Unmarshal(request.Payload, sigMsg); err != nil {
		return err
	}
	session.PutSignalMsg(sigMsg)
	return request.Reply(true, nil)
}

// HandleWinChangeReq 解析客户端发送的窗口变换消息队列，并将其传入 session 窗口消息队列中
// 根据 RFC 4254 6.7. window-change 类型请求不需要回复
func (handler *DefaultSessionChanHandler) HandleWinChangeReq(request gosshd.Request, session gosshd.Session) error {
	winMsg := &gosshd.PtyWindowChangeMsg{}
	if err := ssh.Unmarshal(request.Payload, winMsg); err != nil {
		return err
	}
	session.PutWinchMsg(winMsg)
	request.Reply(true, nil)
	return nil
}

// HandlePtyReq 解析 pty-req 请求，将信息存入 session 缓存队列中
func (handler *DefaultSessionChanHandler) HandlePtyReq(request gosshd.Request, session gosshd.Session) error {
	ptyMsg := &gosshd.PtyRequestMsg{}
	if err := ssh.Unmarshal(request.Payload, ptyMsg); err != nil {

		return err
	}
	err := request.Reply(true, nil)
	if err != nil {
		return err
	}
	session.PutPtyMsg(ptyMsg)
	return nil
}

// HandleShellReq login -f 登陆用户，子进程打开错误或者处理完毕后 session 将被关闭；
// todo 没有对 RFC 4254 8. 规定的 Encoding of Terminal Modes 进行处理
func (handler *DefaultSessionChanHandler) HandleShellReq(request gosshd.Request, session gosshd.Session) error {
	request.Reply(true, nil)
	user := session.User()
	ptyMsg := <-session.PtyMsg()
	cmd := exec.Command("login", "-f", user.UserName) // fixme 会不会有 RCE 取决于 LookupUser 回调函数生成的 User
	// 当接收到 context 的 cancelFunc 时，取消子进程的执行
	var wbuf []byte = nil
	var rbuf []byte = nil
	if handler.copyBufSize > 0 {
		wbuf = make([]byte, handler.copyBufSize)
		rbuf = make([]byte, handler.copyBufSize)
	}

	// 应用 term 环境变量
	//cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyMsg.Term))
	//shell, err := pty.StartWithSize(cmd, &pty.Winsize{
	//	Cols: uint16(ptyMsg.Columns),
	//	Rows: uint16(ptyMsg.Rows),
	//	X:    uint16(ptyMsg.Width),
	//	Y:    uint16(ptyMsg.Height),
	//})
	//if err != nil {
	//	return err
	//}

	pty, tty, err := StartPtyWithSize(cmd, &Winsize{
		Cols: uint16(ptyMsg.Columns),
		Rows: uint16(ptyMsg.Rows),
		X:    uint16(ptyMsg.Width),
		Y:    uint16(ptyMsg.Height),
	})
	if pty != nil {
		defer pty.Close()
	}
	if tty != nil {
		defer tty.Close()
	}
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		session.Close()
		return err
	}
	exitCtx, cancel := context.WithCancel(session.Ctx())
	go CopyBufferWithContext(session, pty, wbuf, exitCtx.Done())
	go CopyBufferWithContext(pty, session, rbuf, exitCtx.Done())
	// 接受窗口改变消息，并应用于 pty
	go func() {
		win := &Winsize{}
		for {
			select {
			case winChange := <-session.WinchMsg():
				win.Rows = uint16(winChange.Rows)
				win.Cols = uint16(winChange.Columns)
				win.X = uint16(winChange.Width)
				win.Y = uint16(winChange.Height)
				Setsize(pty, win)
			case <-exitCtx.Done():
				return
			}
		}
	}()

	// fixme 当 session 取消信号来临时，是否要关闭子进程
	go func() {
		select {
		case <-exitCtx.Done():
			return
		case <-session.Done():
			cmd.Process.Kill()
		}
	}()

	// 接受 Signal 消息，并应用于 Process
	go func() {
		for {
			select {
			case signal := <-session.SignalMsg():
				cmd.Process.Signal(signal.Signal)
			case <-exitCtx.Done():
				return
			}
		}
	}()
	err = cmd.Wait()
	cancel()
	return handler.SendExitStatus(cmd.ProcessState.ExitCode(), true, session)
}

// HandleExecReq 处理 exec 请求，处理完毕后 session 将被关闭
func (handler *DefaultSessionChanHandler) HandleExecReq(request gosshd.Request, session gosshd.Session) error {
	cmdMsg := &gosshd.ExecMsg{}
	if err := ssh.Unmarshal(request.Payload, cmdMsg); err != nil {
		request.Reply(false, nil)
		return err
	}
	return handler.execCmd(request, cmdMsg.Command, session)
}

// SendExitStatus 发送 exit-status 请求，但 close 为 true 时，会关闭 BasicSession，
// 当 close 为 false 时，返回请求发送时出现的错误；否则返回关闭 session 时的发送的错误
func (handler *DefaultSessionChanHandler) SendExitStatus(code int, close bool, session gosshd.Session) error {
	status := struct{ Status uint32 }{uint32(code)}
	_, err := session.SendRequest(gosshd.ExitStatus, false, ssh.Marshal(&status))
	if err != nil && !close {
		return err
	}
	return session.Close()
}

func (handler *DefaultSessionChanHandler) execCmd(request gosshd.Request, cmdline string, session gosshd.Session) error {
	// Fixme golang 运行命令需要将每个参数都要分割，无法判断空白字符是分隔符还是作为字符串参数中的内容，故使用 `sh -c cmd` 运行命令
	words, err := shlex.Split(cmdline, true)
	if err != nil {
		request.Reply(false, nil)
		return err
	}
	cmd, err := CreateCmdWithUser(session.User(), words[0], words[1:]...)
	if err != nil {
		request.Reply(false, nil)
		return err
	}
	request.Reply(true, nil)
	cmd.Env = session.Env()
	cmd.Dir = session.User().HomeDir
	// 如果客户端之前请求了伪终端
	if len(session.PtyMsg()) != 0 {
		select {
		case ptyMsg := <-session.PtyMsg():
			return handler.execCmdWithPty(request, cmd, ptyMsg, session)
		case <-session.Done(): // 如果分配到 pty 之前就已经关闭
			return nil
		}
	} else {
		stdOut, err := cmd.StdoutPipe()
		stdErr, err := cmd.StderrPipe()
		stdIn, err := cmd.StdinPipe()
		if err != nil {
			request.Reply(false, nil)
			return err
		}
		var wbuf []byte = nil
		var rbuf []byte = nil
		var wbuf2 []byte = nil
		if handler.copyBufSize > 0 {
			rbuf = make([]byte, handler.copyBufSize)
			wbuf = make([]byte, handler.copyBufSize)
			wbuf2 = make([]byte, handler.copyBufSize)
		}
		exitCtx, cancel := context.WithCancel(session.Ctx())
		go CopyBufferWithContext(stdIn, session, rbuf, exitCtx.Done())
		go CopyBufferWithContext(session.Stderr(), stdErr, wbuf, exitCtx.Done())
		go CopyBufferWithContext(session, stdOut, wbuf2, exitCtx.Done())
		if err = cmd.Start(); err != nil {
			cancel()
			session.Close()
			return err
		}
		// 接受 Signal 消息，并应用于 Process
		go func() {
			for {
				select {
				case signal := <-session.SignalMsg():
					sig := gosshd.Signals[signal.Signal]
					cmd.Process.Signal(syscall.Signal(sig))
				case <-exitCtx.Done():
					return
				}
			}
		}()
		cmd.Wait()
		cancel()
		return handler.SendExitStatus(cmd.ProcessState.ExitCode(), true, session)
	}
}

// 分配一个 Pty 至 cmd ，并将输入输出绑定到 session 中，最终 session 将被关闭
func (handler *DefaultSessionChanHandler) execCmdWithPty(request gosshd.Request, cmd *exec.Cmd, msg *gosshd.PtyRequestMsg, session gosshd.Session) error {
	var wbuf []byte = nil
	var rbuf []byte = nil
	if handler.copyBufSize > 0 {
		wbuf = make([]byte, handler.copyBufSize)
		rbuf = make([]byte, handler.copyBufSize)
	}
	// 应用 term 环境变量
	cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", msg.Term))
	pty, tty, err := StartPtyWithSize(cmd, &Winsize{
		Cols: uint16(msg.Columns),
		Rows: uint16(msg.Rows),
		X:    uint16(msg.Width),
		Y:    uint16(msg.Height),
	})
	if pty != nil {
		defer pty.Close()
	}
	if tty != nil {
		defer tty.Close()
	}
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		session.Close()
		return err
	}
	exitCtx, cancel := context.WithCancel(session.Ctx())
	go CopyBufferWithContext(session, pty, wbuf, exitCtx.Done())
	go CopyBufferWithContext(pty, session, rbuf, exitCtx.Done())
	// 接受窗口改变消息，并应用于 pty
	go func() {
		win := &Winsize{}
		for {
			select {
			case winChange := <-session.WinchMsg():
				win.Rows = uint16(winChange.Rows)
				win.Cols = uint16(winChange.Columns)
				win.X = uint16(winChange.Width)
				win.Y = uint16(winChange.Height)
				Setsize(pty, win)
			case <-exitCtx.Done():
				return
			}
		}
	}()

	// fixme 当 session 取消信号来临时，是否要关闭子进程
	go func() {
		select {
		case <-session.Done():
			cmd.Process.Kill()
		}
	}()

	// 接受 Signal 消息，并应用于 Process
	go func() {
		for {
			select {
			case signal := <-session.SignalMsg():
				cmd.Process.Signal(signal.Signal)
			case <-exitCtx.Done():
				//fmt.Println("break sig")
				return
			}
		}
	}()
	err = cmd.Wait()
	cancel()
	handler.SendExitStatus(cmd.ProcessState.ExitCode(), true, session)
	return err
}
