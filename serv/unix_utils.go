package serv

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/nishoushun/gosshd"
	"os"
	"os/exec"
	"strings"
)

// unix 系统下处理用户文件、认证、终端的工具类

const (
	Passwd = "/etc/passwd"
	Shadow = "/etc/shadow"
)

// OpenSSH 在 unix 系统下的密钥路径
const (
	RSAHostKeyPath     = "/etc/ssh/ssh_host_rsa_key"
	ECDSAHostKeyPath   = "/etc/ssh/ssh_host_ecdsa_key"
	ED25519HostKeyPath = "/etc/ssh/ssh_host_ed25519_key"
	DSAHostKeyPath     = "/etc/ssh/ssh_host_dsa_key"

	RSAHostPublicKeyPath     = "/etc/ssh/ssh_host_rsa_key.pub"
	ECDSAHostPublicKeyPath   = "/etc/ssh/ssh_host_ecdsa_key.pub"
	ED25519HostPublicKeyPath = "/etc/ssh/ssh_host_ed25519_key.pub"
	DSAHostPublicKeyPath     = "/etc/ssh/ssh_host_dsa_key.pub"
)

// UnixUserInfo 从 CrossPlatformPasswordCallback 文件中解析用户信息
func UnixUserInfo(user string) (*gosshd.User, error) {
	line, err := FindUserLog(Passwd, user)
	if err != nil {
		return nil, err
	}
	fields := strings.Split(line, ":")
	if len(fields) != 7 {
		return nil, fmt.Errorf("wrong CrossPlatformPasswordCallback log format")
	}

	return &gosshd.User{
		UserName:     fields[0],
		PasswordFlag: fields[1],
		Uid:          fields[2],
		Gid:          fields[3],
		GECOS:        fields[4],
		HomeDir:      fields[5],
		Shell:        fields[6],
	}, nil
}

// WrongPassword 错误的密码
var WrongPassword = errors.New("wrong password")

// WrongFormat 错误的用户记录格式
var WrongFormat = errors.New("wrong format")

// VerifyUnixPassword Unix 系统的密码认证回调函数的实现，
// 通过 /etc/shadow 的密码哈希来进行认证
func VerifyUnixPassword(password []byte, user string) error {
	line, err := FindUserLog(Shadow, user)
	if err != nil {
		return err
	}
	ok, err := VerifyUserByShadowLog(user, string(password), line)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	return WrongPassword
}

// VerifyUserByShadowLog 通过 openssl passwd 模块验证 用户提供的密码是否符合 shadow 文件中对应的记录
// fixme 不应该借助外部程序来进行验证
func VerifyUserByShadowLog(user, passwd, userLog string) (bool, error) {
	fields := strings.Split(userLog, ":")
	if len(fields) < 2 {
		return false, WrongFormat
	}
	username, passwdHash := fields[0], fields[1]
	if username != user {
		return false, gosshd.UserNotExistError{User: user}
	}

	passwdHashFields := strings.Split(passwdHash, "$")
	if len(passwdHashFields) < 4 {
		return false, WrongFormat
	}

	process := exec.Command("openssl", "passwd",
		fmt.Sprintf("-%s", passwdHashFields[1]),
		"-salt", passwdHashFields[2], passwd)
	output, err := process.Output()
	if err != nil {
		return false, err
	}
	out := strings.TrimSpace(string(output))
	if out == passwdHash {
		return true, nil
	}
	return false, nil
}

// FindUserLog 从 passwd 或 shadow 文件中找到对应的用户记录
func FindUserLog(path string, user string) (string, error) {
	file, err := os.OpenFile(path, os.O_RDONLY, 0600)
	defer file.Close()
	if err != nil {
		return "", gosshd.PermitNotAllowedError{Msg: err.Error()}
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := string(scanner.Bytes())
		fields := strings.Split(line, ":")
		if len(fields) == 0 {
			continue
		}
		if fields[0] == user {
			return line, nil
		}
	}
	return "", gosshd.UserNotExistError{User: user}
}
