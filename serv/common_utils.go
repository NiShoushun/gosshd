package serv

import (
	"fmt"
	"github.com/nishoushun/gosshd"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
)

//var DefaultSSHDOptions = &gosshd.SSHServOptions{
//	Version:                 gosshd.Version2 + gosshd.Version,
//	NoClientAuth:            true,
//	AllowUsers:              nil,
//	AllowGroups:             nil,
//	Banner:                  "Niss-GoSSHD",
//	MaxAuthTries:            6,
//	PermitRootLogin:         true,
//	ReadRequestTimeout:      15 * time.Minute,
//	PasswordAuthentication:  true,
//	AcceptEnv:               false,
//	PublicKeyAuthentication: true,
//	Ciphers:                 nil,
//	KeyExchange:             nil,
//	MACs:                    nil,
//}

func LookupUserInfo(user string) (*gosshd.User, error) {
	switch runtime.GOOS {
	case "linux":
		return UnixUserInfo(user)
	default:
		return nil, gosshd.PlatformNotSupportError{Function: "user info"}
	}
}

// CreateCmdWithUser 指定用户身份创建子进程
func CreateCmdWithUser(user *gosshd.User, cmdline string, args ...string) (*exec.Cmd, error) {
	if user == nil || cmdline == "" {
		return nil, fmt.Errorf("illegal args")
	}
	cmd := exec.Command(cmdline, args...)
	uid, err := strconv.Atoi(user.Uid)
	if err != nil {
		return nil, fmt.Errorf("wrong uid: '%s'", user.Uid)
	}
	gid, err := strconv.Atoi(user.Gid)
	if err != nil {
		return nil, fmt.Errorf("wrong gid: '%s'", user.Gid)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
	return cmd, nil
}
