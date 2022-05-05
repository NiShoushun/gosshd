package utils

import (
	"fmt"
	"github.com/nishoushun/gosshd"
	"golang.org/x/crypto/ssh"
)

// RejectChannel 拒绝 channel 的建立
func RejectChannel(channel gosshd.SSHNewChannel, requests <-chan *ssh.Request, ctx gosshd.Context) error {
	return channel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", channel.ChannelType()))
}

func OnlyAcceptSession(chType string) (reason gosshd.RejectionReason, msg string, reject bool) {
	if chType != gosshd.SessionTypeChannel {
		return gosshd.Prohibited, "not a session channel", true
	}
	return 0, "", false
}
