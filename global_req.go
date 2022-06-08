package gosshd

// 全局请求消息定义

const (
	GlobalReqTcpIpForward       = "tcpip-forward"
	GlobalReqCancelTcpIpForward = "cancel-tcpip-forward"

	ForwardedTcpIpChannelType = "forwarded-tcpip"
)

type RemoteForwardRequestMsg struct {
	BindAddr string
	BindPort uint32
}

type RemoteForwardSuccessMsg struct {
	BindPort uint32
}

type RemoteForwardCancelRequestMsg struct {
	BindAddr string
	BindPort uint32
}

type RemoteForwardChannelDataMsg struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}
