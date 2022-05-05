# Go-SSHD

`gosshd` 是对 `golang.org/x/crypto/ssh` 的进一步封装，旨在快速搭建一个高度自定义的 SSH 服务器，应用于不同场景。

共分为两个包：`gosshd` 以及 `utils`，前者是对 `ssh` 包的进一步封装以及类型的定义；后者包含了一系列的默认实现、工具函数。 

**例**：使用 `utils` 包的 `SimpleServerOnUnix` 函数创建一个 `SSHServer` 实例，并监听 `2222` 端口 

```go
package main

import (
	"github.com/nishoushun/gosshd/utils"
	"log"
)

func main() {
	server, _ := utils.SimpleServerOnUnix()
	log.Fatalln(server.ListenAndServe(":2222"))
}
```

编译并运行，使用 Open-SSH 作为客户端进行连接：

![image-20220505002235784](https://ni187note-pics.oss-cn-hangzhou.aliyuncs.com/notes-img/202205050022881.png)

### 安装

```
go get github.com/nishoushun/gosshd
go get github.com/nishoushun/gosshd/utils
```

### 配置 SSHServer

#### 身份认证

GoSSHD 提供了 3 种类型的身份验证方式，通过设置回调函数来规定验证过程。

在 `utils` 包中额外准备了一些身份验证回调函数类型的实现，以及一些其他的身份校验相关的工具函数。

如果希望使用 ssh 包提供的身份验证回调函数，则需要通过 `SSHServer` 的 `ServerConfig` 字段去设置相应的回调函数；否则应该通过 `SSHServer` 的 `SetXXX` 方法设置相应的身份验证回调函数。

对于 `KeyboardInteractiveChallengeCallback` 类型身份认证方式实际上并不常用，该类型用于交互式问答，通过向客户端提供多个问题，然后检查客户端的回答，来决定是否通过认证。

**例**：为 `SSHServer` 设置 `KeyboardInteractiveChallengeCallback`

```go
import (
	"github.com/nishoushun/gosshd"
	"github.com/nishoushun/gosshd/utils"
	"log"
)

func main() {
	server, _ := utils.SimpleServerOnUnix()
	server.SetKeyboardInteractiveChallengeCallback(
		func(conn gosshd.ConnMetadata,
			client gosshd.KeyboardInteractiveChallenge) (*gosshd.Permissions, error) {
			questions := []string{
				"Hey buddy, What about the melon price? \r\n>>",
				"Is the peel made by gold or the pith made by gold? \n>>",
				"pick one for me. \n>>"}
			echo := []bool{true, true, true}
			answers, err := client(
				"HuaQiang mai gua",
				"answer the following questions",
				questions, echo)
			if err != nil {
				return nil, err
			}
			if answers[0] == "2" && answers[2] == "sure" {
				return nil, nil
			}
			return nil, fmt.Errorf("wrong answer")
		})
	log.Fatalln(server.ListenAndServe(":2222"))
}
```

效果如下：

![image-20220504164439048](https://ni187note-pics.oss-cn-hangzhou.aliyuncs.com/notes-img/202205041644091.png)

> 另外对于身份认证，如果验证失败建议延迟几秒再返回 err，防止爆破。

#### 关于 Context

这是一个作用域为单个客户端与服务器的整个连接过程的上下文，包含了网络信息、用户身份信息、以及其他信息。其中用户信息由 `SSHServer` 的 `LookupUser` 回调函数来获取；`Permission` 身份认证信息由设计的身份认证的回调函数决定；其余的信息将会在建立连接时被填写；

另外用户自定义的请求处理回调函数总是应该正确的处理 `Context.Done()` 消息，以接受服务器的关闭消息从而正确地取消子协程任务。

#### 添加 channel 处理回调函数

按照 RFC 4254，总共有四种类型的 ssh `channel` 请求，分别是 `session`、`direct-tcpip`、`forwarded-tcpip` 以及 `x11`。当然一些客户端与服务端还会定义自己的请求类型。可通过 `SSHServer` 提供的 `SetNewChanHandleFunc` 为特定类型注册一个处理函数；

另外在 `utils` 包中，对 `session`、`direct-tcpip`、`forwarded-tcpip` 有一个基本功能的实现；

##### DefaultSessionChanHandler

该类型用于处理 `session` 类型的 channel 请求，目前除了 `subsystem` ，其余的 RFC 4254 中定义的请求均已实现。

使用者可以通过该类型提供的 `SetReqHandler` 中定义的 `SetReqHandler` 来注册特定类型请求的处理函数，以监听、记录、过滤的用户的请求等。

通过 `Start` 方法对客户端通道建立的请求进行处理；

> 总是应该使用 `NewSessionChannelHandler` 函数创建一个 `DefaultSessionChanHandler` 实例；

**例**：添加 `session` 类型的 channel 请求处理函数，使用 `gosshd` 提供的 `NewSessionChannelHandler` 去创建一个处理器，并为其设置一个 `exec` 类型的处理的回调函数，记录客户端想要执行的命令：

```go
package main

import (
	"github.com/nishoushun/gosshd"
	"github.com/nishoushun/gosshd/utils"
	"log"
)

func main() {
	server, _ := utils.SimpleServerOnUnix()
	server.SetNewChanHandleFunc(gosshd.SessionTypeChannel, func(c gosshd.SSHNewChannel, ctx gosshd.Context) {
		handler := utils.NewSessionChannelHandler(1, 1, 1, 0)
		handler.SetReqHandler(gosshd.ReqExec,
			func(request gosshd.Request, session gosshd.Session) error {
				log.Printf("%s want exec cmd: %s \r\n", session.User().UserName, string(request.Payload))
				request.Reply(true, nil)
				handler.SendExitStatus(0, true, session)
				return nil
			})
		handler.Start(c, ctx)
	})
	log.Fatalln(server.ListenAndServe(":2222"))
}
```

运行效果如下：

![image-20220504221259668](https://ni187note-pics.oss-cn-hangzhou.aliyuncs.com/notes-img/202205042212736.png)

##### TcpIpDirector

该类型用于处理 `direct-tcpip` 类型的 `channel`，即打开客户端指定的远程连接，并将通道内容转发至远程目标；

> 一个最经典的例子就是 `ssh -L local-addr:local-port:remote-addr:remote-port`  选项，客户端会监听 `local-addr:local-port`，并将内容通过 SSH 连接转发至服务器，服务器再将其转发至 `remote-addr:remote-port`，其底层就是通过 `direct-tcpip` 类型的 `channel` 传输数据。

**例**：为新创建的 server 注册一个由 `TcpIpDirector` 实现的 `NewChanHandleFunc`

```go
package main

import (
	"github.com/nishoushun/gosshd"
	"github.com/nishoushun/gosshd/utils"
	"log"
)

func main() {
	server, _ := utils.SimpleServerOnUnix()
	server.SetNewChanHandleFunc(gosshd.DirectTcpIpChannel, utils.NewTcpIpDirector(0).HandleDirectTcpIP)
	log.Fatalln(server.ListenAndServe(":2222"))
}
```

开启 docker 容器进行测试：

![image-20220504221816307](https://ni187note-pics.oss-cn-hangzhou.aliyuncs.com/notes-img/202205042218340.png)

未开启端口映射的情况下，只能通过 docker 的虚拟网卡地址访问web服务：

![image-20220504221841279](https://ni187note-pics.oss-cn-hangzhou.aliyuncs.com/notes-img/202205042218335.png)

开服务端并转发：

![image-20220504222643254](https://ni187note-pics.oss-cn-hangzhou.aliyuncs.com/notes-img/202205042226957.png)

#### 添加全局请求处理回调函数

在 `RFC 4254 4.` 中定义了全局请求处理，通过 `SSHServer` 的 `SetGlobalRequestHandleFunc` 方法可注册一个全局请求类型的处理函数。

**例**：为服务器添加 `tcpip-forward` 与 `cancel-tcpip-forward` 全局请求的处理器

```go
package main

import (
	"github.com/nishoushun/gosshd"
	"github.com/nishoushun/gosshd/utils"
	"log"
)

func main() {
	server, _ := utils.SimpleServerOnUnix()
	fhandler := NewForwardedTcpIpHandler(0)
	server.SetGlobalRequestHandleFunc(gosshd.GlobalReqTcpIpForward, fhandler.ServeForward)
	server.SetGlobalRequestHandleFunc(gosshd.GlobalReqCancelTcpIpForward, fhandler.CancelForward)
	log.Fatalln(server.ListenAndServe(":2222"))
}
```



