package gosshd

// ChannelOpenDirectMsg 客户端发送的 channel 建立请求中附带的额外数据，用于指明转发地址与端口
// RFC 4254 7.2.
type ChannelOpenDirectMsg struct {
	Dest  string // host to connect
	DPort uint32 // port to connect
	Src   string // originator IP address
	SPort uint32 // originator port
}
