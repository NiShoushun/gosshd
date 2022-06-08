package gosshd

import (
	"golang.org/x/crypto/ssh"
)

// 该文件包含处理身份认证过程相关的各种身份认证的回调函数以及其他类型定义

// ConnMetadata 身份认证时，客户端提供的信息
type ConnMetadata interface {
	ssh.ConnMetadata
}

// Permissions 用于保存身份认证信息，最终会被存到 Context 中
type Permissions struct {
	CriticalOptions map[string]string
	Extensions      map[string]string
}

type PublicKey interface {
	ssh.PublicKey
}

type Signer interface {
	ssh.Signer
}

// KeyboardInteractiveChallenge ssh 定义的轮询问答认证回调函数
type KeyboardInteractiveChallenge func(name, instruction string, questions []string, echos []bool) (answers []string, err error)

// PublicKeyCallback ssh 包下定义的公钥认证回调函数类型的包装
type PublicKeyCallback func(conn ConnMetadata, key PublicKey) (*Permissions, error)

// PasswdCallback ssh 包下定义的密码认证回调函数类型的包装
type PasswdCallback func(conn ConnMetadata, password []byte) (*Permissions, error)

// KeyboardInteractiveChallengeCallback ssh 包下定义的公钥认证回调函数类型的包装
type KeyboardInteractiveChallengeCallback func(conn ConnMetadata, client KeyboardInteractiveChallenge) (*Permissions, error)

// AuthLogCallback ssh 包下定义的身份认证回调函数被调用时的回调函数的包装
type AuthLogCallback func(conn ConnMetadata, method string, err error)

// BannerCallback 当建立 SSH 连接时，在身份认证之前向客户端发送的字符串信息
// 注意：并不是所有的客户端都会对该信息进行处理
type BannerCallback func(metadata ConnMetadata) string

// WrapPasswdCallback  生成 ssh.ServerConfig 可接受的函数参数：PasswordCallback
func WrapPasswdCallback(callback PasswdCallback) func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	if callback == nil {
		return nil
	}
	return func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		perms, err := callback(meta, password)
		if err != nil {
			return nil, err
		}
		if perms != nil {
			permissions := &ssh.Permissions{}
			permissions.Extensions = perms.Extensions
			permissions.CriticalOptions = perms.CriticalOptions
			return permissions, nil
		}
		return nil, err
	}
}

// WrapKeyboardInteractiveChallenger 生成 ssh.ServerConfig 可接受的参数：KeyboardInteractiveChallengeCallback
func WrapKeyboardInteractiveChallenger(callback KeyboardInteractiveChallengeCallback) func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	if callback == nil {
		return nil
	}
	return func(meta ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		perms, err := callback(meta, KeyboardInteractiveChallenge(client))
		if err != nil {
			return nil, err
		}
		if perms != nil {
			permissions := &ssh.Permissions{}
			permissions.Extensions = perms.Extensions
			permissions.CriticalOptions = perms.CriticalOptions
			return permissions, nil
		}
		return nil, err
	}
}

// WrapPublicKeyCallback  生成 ssh.ServerConfig 可接受的参数：PublicKeyCallback
func WrapPublicKeyCallback(callback PublicKeyCallback) func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	if callback == nil {
		return nil
	}
	return func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		perms, err := callback(meta, key)
		if err != nil {
			return nil, err
		}
		if perms != nil {
			permissions := &ssh.Permissions{}
			permissions.Extensions = perms.Extensions
			permissions.CriticalOptions = perms.CriticalOptions
			return permissions, nil
		}
		return nil, err
	}
}

// WrapAuthLogCallback 生成 ssh.ServerConfig 可接受的参数函数：AuthLogCallback
func WrapAuthLogCallback(callback AuthLogCallback) func(conn ssh.ConnMetadata, method string, err error) {
	if callback == nil {
		return nil
	}
	return func(conn ssh.ConnMetadata, method string, err error) {
		callback(conn, method, err)
	}
}

// WrapBannerCallback 生成 ssh.ServerConfig 可接受的参数函数：BannerCallback
func WrapBannerCallback(callback BannerCallback) func(conn ssh.ConnMetadata) string {
	if callback == nil {
		return nil
	}
	return func(conn ssh.ConnMetadata) string {
		return callback(conn)
	}
}
