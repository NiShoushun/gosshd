package serv

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"github.com/nishoushun/gosshd"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"os/user"
	"path"
	"runtime"
)

// 本文件包含一些认证相关接口的具体实现

const (
	PassedPasswdKey = "passed-password"
	PassedPublicKey = "passed-public-key"
)

const (
	AuthorizedKeysPath = ".ssh/authorized_keys"
)

// CheckUnixPasswd 通过 Unix 系统下的 passwd 与 shadow 文件，校验用户密码；返回的 Permissions.Extensions 中包含 ‘passed-password’ 以及密码信息
func CheckUnixPasswd(conn gosshd.ConnMetadata, password []byte) (*gosshd.Permissions, error) {
	if err := VerifyUnixPassword(password, conn.User()); err != nil {
		return nil, err
	}
	return &gosshd.Permissions{CriticalOptions: map[string]string{}, Extensions: map[string]string{PassedPasswdKey: string(password)}}, nil
}

// CheckPublicKeyByAuthorizedKeys 检查客户端发送的公钥是否在 `authorized_keys` 中
func CheckPublicKeyByAuthorizedKeys(conn gosshd.ConnMetadata, key gosshd.PublicKey) (*gosshd.Permissions, error) {
	userInfo, err := user.Lookup(conn.User())
	if err != nil {
		return nil, gosshd.UserNotExistError{User: conn.User()}
	}
	return LoadAndCheck(path.Join(userInfo.HomeDir, AuthorizedKeysPath), key)
}

// LoadAndCheck 加载并解析文件，并检查 key 是否被包含。
// 如果被包含，则在返回的 Permission 的 Extension 字段中添加 "passed-public-key" 以及对应的公钥内容
func LoadAndCheck(path string, key gosshd.PublicKey) (*gosshd.Permissions, error) {
	authorizedKeysBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	keys := map[string]struct{}{}
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			continue
		}
		keys[string(pubKey.Marshal())] = struct{}{}
		authorizedKeysBytes = rest
	}
	if _, ok := keys[string(key.Marshal())]; ok {
		return &gosshd.Permissions{CriticalOptions: map[string]string{}, Extensions: map[string]string{PassedPublicKey: string(key.Marshal())}}, nil
	}
	return nil, gosshd.PermitNotAllowedError{Msg: "no authorized key found"}
}

// FixedPasswdCallback 固定服务器密码验证回调函数
func FixedPasswdCallback(passwd []byte) gosshd.PasswdCallback {
	return func(conn gosshd.ConnMetadata, password []byte) (*gosshd.Permissions, error) {
		if bytes.Compare(password, passwd) != 0 {
			return nil, &gosshd.PermitNotAllowedError{Msg: "wrong password"}
		}
		return &gosshd.Permissions{CriticalOptions: map[string]string{}, Extensions: map[string]string{PassedPasswdKey: string(password)}}, nil
	}
}

// CrossPlatformPasswordCallback 跨平台密码验证回调函数
// todo 只实现了 linux 平台下的验证
func CrossPlatformPasswordCallback(conn gosshd.ConnMetadata, password []byte) (*gosshd.Permissions, error) {
	switch runtime.GOOS {
	case "linux":
		return CheckUnixPasswd(conn, password)
	default:
		return nil, gosshd.PlatformNotSupportError{Function: "password authentication"}
	}
}

// FindInAuthorizedKeys 在给定的 authorized_keys 中寻找公钥
func FindInAuthorizedKeys(path string, key ssh.PublicKey) (bool, error) {
	authorizedKeysBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return false, err
	}

	authorizedKeysMap := map[string]bool{}

	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			return false, err
		}
		authorizedKeysMap[string(pubKey.Marshal())] = true
		authorizedKeysBytes = rest
	}
	return authorizedKeysMap[string(key.Marshal())], nil
}

// GenerateSigner 生成指定位数的 Signer
func GenerateSigner(bits int) (gosshd.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(key)
}
