package gosshd

// User 根据 Unix 系统的 passwd 文件设置的用户字段结构体
type User struct {
	UserName     string            // 用户名
	PasswordFlag string            // 密码标志位
	Uid          string            // 用户id
	Gid          string            // 用户组id
	GECOS        string            // 用户描述
	HomeDir      string            // 用户的主目录
	Shell        string            // 用户的默认shell
	Extensions   map[string]string // 可能会用到的额外信息
}
