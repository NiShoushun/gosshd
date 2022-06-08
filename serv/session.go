package serv

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

// Env 获取设置的环境变量
func (handler *DefaultSessionChanHandler) Env() []string {
	return handler.env
}

// SetEnv 设置环境变量，单个的形式应该为 %s=%s
func (handler *DefaultSessionChanHandler) SetEnv(env []string) {
	handler.env = env
}

// PtyMsg 从缓存队列中取出最新的 pty-req 请求信息，若无，则阻塞至一个客户端发送一个新的 pty-req 请求
func (handler *DefaultSessionChanHandler) PtyMsg() <-chan *gosshd.PtyRequestMsg {
	return handler.ptyCh
}

// WinchMsg 从缓存队列中取出最新的 window-change 请求信息，若无，则阻塞至一个客户端发送一个新的 window-change 请求
func (handler *DefaultSessionChanHandler) WinchMsg() <-chan *gosshd.PtyWindowChangeMsg {
	return handler.winchCh
}

// SignalMsg 从缓存队列中取出最新的 signal 请求信息，若无，则阻塞至一个客户端发送一个新的 signal 请求
func (handler *DefaultSessionChanHandler) SignalMsg() <-chan *gosshd.SignalMsg {
	return handler.sigCh
}

// PutPtyMsg 放入 pty-req 请求信息至缓存队列中，若队列满，则阻塞至一个 pty-req 请求被取出
func (handler *DefaultSessionChanHandler) PutPtyMsg(msg *gosshd.PtyRequestMsg) {
	handler.ptyCh <- msg
}

// PutWinchMsg 放入 window-change 请求信息至缓存队列中，若队列满，则阻塞至一个 window-change 请求被取出
func (handler *DefaultSessionChanHandler) PutWinchMsg(msg *gosshd.PtyWindowChangeMsg) {
	handler.winchCh <- msg
}

// PutSignalMsg 放入 signal 请求信息至缓存队列中，若队列满，则阻塞至一个 signal 请求被取出
func (handler *DefaultSessionChanHandler) PutSignalMsg(msg *gosshd.SignalMsg) {
	handler.sigCh <- msg
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
		Mutex:       sync.Mutex{},
		winchCh:     make(chan *gosshd.PtyWindowChangeMsg, winMsgBufSize),
		ptyCh:       make(chan *gosshd.PtyRequestMsg, ptyMsgBufSize),
		sigCh:       make(chan *gosshd.SignalMsg, sigMsgBufSize),
		env:         make([]string, 0),
		copyBufSize: copyBufSize,
		ReqHandlers: map[string]RequestHandlerFunc{},
	}
	return handler
}

// SetDefaults 注册默认的请求处理函数
func (handler *DefaultSessionChanHandler) SetDefaults() {
	handler.SetReqHandlerFunc(gosshd.ReqPty, handler.HandlePtyReq)
	handler.SetReqHandlerFunc(gosshd.ReqShell, handler.HandleShellReq)
	handler.SetReqHandlerFunc(gosshd.ReqExec, handler.HandleExecReq)
	handler.SetReqHandlerFunc(gosshd.ReqSignal, handler.HandleSignalReq)
	handler.SetReqHandlerFunc(gosshd.ReqEnv, handler.HandleEnvReq)
	handler.SetReqHandlerFunc(gosshd.ReqWinCh, handler.HandleWinChangeReq)
	handler.SetReqHandlerFunc(gosshd.ReqExit, handler.HandleExit)
}

// RequestHandlerFunc 处理单个请求
type RequestHandlerFunc func(ctx gosshd.Context, request gosshd.Request, session gosshd.Channel) error

// ReqLogCallback 用于记录接受的请求，处理结果
// err 为处理函数返回的错误；rtype 为请求类型；wantReply 为是否需要回应客户端；payload 为请求附带的数据
type ReqLogCallback func(err error, rtype string, wantReply bool, payload []byte, context gosshd.Context)

type CreateSessionCallback func(gosshd.Context, gosshd.Channel) gosshd.Channel

// DefaultSessionChanHandler 一个处理 Channel 类型 SSH 通道的 ChannelHandler
type DefaultSessionChanHandler struct {
	sync.Mutex
	winMsgBufSize int
	ptyMsgBufSize int
	sigMsgBufSize int

	winchCh chan *gosshd.PtyWindowChangeMsg // window-change 请求队列
	sigCh   chan *gosshd.SignalMsg          // signal 请求队列
	ptyCh   chan *gosshd.PtyRequestMsg      // pty-req 请求队列
	env     []string                        // 该 session 环境变量

	copyBufSize int
	ReqHandlers map[string]RequestHandlerFunc
	ReqLogCallback
}

var InterruptedErr = errors.New("interrupted by Context")

var NotSessionTypeErr = errors.New("not session type channel")

// SetReqHandlerFunc 添加一个对应请求类型的处理函数
func (handler *DefaultSessionChanHandler) SetReqHandlerFunc(reqtype string, f RequestHandlerFunc) {
	handler.ReqHandlers[reqtype] = f
}

// Start 接受客户端的 session channel 请求建立，并开始开启子协程的方式处理 requests；
// 当所有请求处理完毕后或接收到一个 nil Request，将关闭该会话
func (handler *DefaultSessionChanHandler) Start(ctx gosshd.Context, c gosshd.NewChannel) error {
	if c.ChannelType() != gosshd.SessionTypeChannel {
		return NotSessionTypeErr
	}
	channel, requests, err := c.Accept()
	if err != nil {
		return err
	}
	//session := &BasicSession{
	//	Context: ctx,
	//	Channel: channel,
	//	Mutex:   sync.Mutex{},
	//}

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
			go handler.ServeRequest(ctx, gosshd.Request{Request: request}, channel)
		}
	}
ret:
	//fmt.Println("session close")
	return channel.Close()
}

// ServeRequest 从注册的请求处理函数中找到对应请求类型的函数，并调用；
// 处理函数返回的错误将被用于 handler 的 ReqLogCallback
func (handler *DefaultSessionChanHandler) ServeRequest(ctx gosshd.Context, request gosshd.Request, session gosshd.Channel) {
	if reqHandler, ok := handler.ReqHandlers[request.Type]; ok {
		go func() {
			err := reqHandler(ctx, request, session)
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

// HandleExit 接受退出请求，并关闭 Channel
func (handler *DefaultSessionChanHandler) HandleExit(ctx gosshd.Context, request gosshd.Request, session gosshd.Channel) error {
	return handler.SendExitStatus(0, true, session)
}

func (handler *DefaultSessionChanHandler) HandleEnvReq(ctx gosshd.Context, request gosshd.Request, session gosshd.Channel) error {
	var payload *gosshd.SetenvRequest
	err := ssh.Unmarshal(request.Payload, &payload)
	if err != nil {
		return err
	}
	env := handler.Env()
	handler.SetEnv(append(env, fmt.Sprintf("%s=%s", payload.Name, payload.Value)))
	return request.Reply(true, nil)
}

// HandleSignalReq 解析客户端发送的窗口变换消息队列，并将其传入 session 窗口消息队列中
// 根据 RFC 4254 6.9. signal 类型请求不需要回复
func (handler *DefaultSessionChanHandler) HandleSignalReq(ctx gosshd.Context, request gosshd.Request, session gosshd.Channel) error {
	sigMsg := &gosshd.SignalMsg{}
	if err := ssh.Unmarshal(request.Payload, sigMsg); err != nil {
		return err
	}
	handler.PutSignalMsg(sigMsg)
	return request.Reply(true, nil)
}

// HandleWinChangeReq 解析客户端发送的窗口变换消息队列，并将其传入 session 窗口消息队列中
// 根据 RFC 4254 6.7. window-change 类型请求不需要回复
func (handler *DefaultSessionChanHandler) HandleWinChangeReq(ctx gosshd.Context, request gosshd.Request, session gosshd.Channel) error {
	winMsg := &gosshd.PtyWindowChangeMsg{}
	if err := ssh.Unmarshal(request.Payload, winMsg); err != nil {
		return err
	}
	handler.PutWinchMsg(winMsg)
	request.Reply(true, nil)
	return nil
}

// HandlePtyReq 解析 pty-req 请求，将信息存入 session 缓存队列中
func (handler *DefaultSessionChanHandler) HandlePtyReq(ctx gosshd.Context, request gosshd.Request, session gosshd.Channel) error {
	ptyMsg := &gosshd.PtyRequestMsg{}
	if err := ssh.Unmarshal(request.Payload, ptyMsg); err != nil {

		return err
	}
	err := request.Reply(true, nil)
	if err != nil {
		return err
	}
	handler.PutPtyMsg(ptyMsg)
	return nil
}

// HandleShellReq login -f 登陆用户，子进程打开错误或者处理完毕后 session 将被关闭；
// todo 没有对 RFC 4254 8. 规定的 Encoding of Terminal Modes 进行处理
func (handler *DefaultSessionChanHandler) HandleShellReq(ctx gosshd.Context, request gosshd.Request, session gosshd.Channel) error {
	request.Reply(true, nil)
	user := ctx.User()
	ptyMsg := <-handler.PtyMsg()
	cmd := exec.Command("login", "-f", user.UserName) // fixme 会不会有 RCE 取决于 LookupUser 回调函数生成的 UserName
	// 当接收到 context 的 cancelFunc 时，取消子进程的执行
	var wbuf []byte = nil
	var rbuf []byte = nil
	if handler.copyBufSize > 0 {
		wbuf = make([]byte, handler.copyBufSize)
		rbuf = make([]byte, handler.copyBufSize)
	}

	// 应用 term 环境变量
	//cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyMsg.Term))

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
	exitCtx, cancel := context.WithCancel(ctx)
	go CopyBufferWithContext(session, pty, wbuf, exitCtx)
	go CopyBufferWithContext(pty, session, rbuf, exitCtx)
	// 接受窗口改变消息，并应用于 pty
	go func() {
		win := &Winsize{}
		for {
			select {
			case winChange := <-handler.WinchMsg():
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
			cmd.Process.Kill()
		}
	}()

	// 接受 Signal 消息，并应用于 Process
	go func() {
		for {
			select {
			case signal := <-handler.SignalMsg():
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
func (handler *DefaultSessionChanHandler) HandleExecReq(ctx gosshd.Context, request gosshd.Request, session gosshd.Channel) error {
	cmdMsg := &gosshd.ExecMsg{}
	if err := ssh.Unmarshal(request.Payload, cmdMsg); err != nil {
		request.Reply(false, nil)
		return err
	}
	return handler.execCmd(ctx, request, cmdMsg.Command, session)
}

// SendExitStatus 发送 exit-status 请求，但 close 为 true 时，会关闭 BasicSession，
// 当 close 为 false 时，返回请求发送时出现的错误；否则返回关闭 session 时的发送的错误
func (handler *DefaultSessionChanHandler) SendExitStatus(code int, close bool, session gosshd.Channel) error {
	status := struct{ Status uint32 }{uint32(code)}
	_, err := session.SendRequest(gosshd.ExitStatus, false, ssh.Marshal(&status))
	if err != nil && !close {
		return err
	}
	return session.Close()
}

func (handler *DefaultSessionChanHandler) execCmd(ctx gosshd.Context, request gosshd.Request, cmdline string, session gosshd.Channel) error {
	words, err := shlex.Split(cmdline, true)
	if err != nil {
		request.Reply(false, nil)
		return err
	}
	var cmd *exec.Cmd

	if len(words) == 1 {
		cmd, err = CreateCmdWithUser(ctx.User(), words[0])
	} else if len(words) >= 2 {
		cmd, err = CreateCmdWithUser(ctx.User(), words[0], words[1:]...)
	} else {
		request.Reply(false, nil)
		return err
	}

	if err != nil {
		request.Reply(false, nil)
		return err
	}

	request.Reply(true, nil)
	cmd.Env = handler.Env()
	cmd.Dir = ctx.User().HomeDir

	// 如果客户端之前请求了伪终端
	if len(handler.PtyMsg()) != 0 {
		select {
		case ptyMsg := <-handler.PtyMsg():
			return handler.execCmdWithPty(ctx, request, cmd, ptyMsg, session)
		case <-ctx.Done(): // 如果分配到 pty 之前就已经关闭
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
		var stdOutWBuf []byte = nil
		var stdInRBuf []byte = nil
		var errWBuf []byte = nil

		if handler.copyBufSize > 0 {
			stdInRBuf = make([]byte, handler.copyBufSize)
			stdOutWBuf = make([]byte, handler.copyBufSize)
			errWBuf = make([]byte, handler.copyBufSize)
		}
		exitCtx, cancel := context.WithCancel(ctx)
		go CopyBufferWithContext(stdIn, session, stdInRBuf, exitCtx)
		go CopyBufferWithContext(session.Stderr(), stdErr, stdOutWBuf, exitCtx)
		go CopyBufferWithContext(session, stdOut, errWBuf, exitCtx)
		if err = cmd.Start(); err != nil {
			cancel()
			session.Close()
			return err
		}
		// 接受 Signal 消息，并应用于 Process
		go func() {
			for {
				select {
				case signal := <-handler.SignalMsg():
					sig := gosshd.Signals[signal.Signal]
					cmd.Process.Signal(syscall.Signal(sig))
				case <-exitCtx.Done():
					return
				}
			}
		}()
		_ = cmd.Wait()
		cancel()
		return handler.SendExitStatus(cmd.ProcessState.ExitCode(), true, session)
	}
}

// 分配一个 Pty 至 cmd ，并将输入输出绑定到 session 中，最终 session 将被关闭
func (handler *DefaultSessionChanHandler) execCmdWithPty(ctx gosshd.Context, request gosshd.Request, cmd *exec.Cmd, msg *gosshd.PtyRequestMsg, session gosshd.Channel) error {
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
	exitCtx, cancel := context.WithCancel(ctx)
	go CopyBufferWithContext(session, pty, wbuf, exitCtx)
	go CopyBufferWithContext(pty, session, rbuf, exitCtx)
	// 接受窗口改变消息，并应用于 pty
	go func() {
		win := &Winsize{}
		for {
			select {
			case winChange := <-handler.WinchMsg():
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
		case <-ctx.Done():
			cmd.Process.Kill()
		}
	}()

	// 接受 Signal 消息，并应用于 Process
	go func() {
		for {
			select {
			case signal := <-handler.SignalMsg():
				cmd.Process.Signal(signal.Signal)
			case <-exitCtx.Done():
				//fmt.Println("break sig")
				return
			}
		}
	}()

	if err := cmd.Start(); err != nil {
		session.Close()
		cancel()
		return err
	}

	err = cmd.Wait()
	cancel()
	handler.SendExitStatus(cmd.ProcessState.ExitCode(), true, session)
	return err
}
