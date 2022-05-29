package utils

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"
)

// github.com/creack/pty 的修改

type Winsize struct {
	Rows uint16 // ws_row: Number of rows (in cells)
	Cols uint16 // ws_col: Number of columns (in cells)
	X    uint16 // ws_xpixel: Width in pixels
	Y    uint16 // ws_ypixel: Height in pixels
}

// StartPtyWithSize 类似于 StartPtyWithAttrs，设置初始大小
func StartPtyWithSize(cmd *exec.Cmd, ws *Winsize) (*os.File, *os.File, error) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setsid = true
	cmd.SysProcAttr.Setctty = true
	return StartPtyWithAttrs(cmd, ws, cmd.SysProcAttr)
}

// StartPtyWithAttrs 返回创建 pty、tty，将 cmd 的输入输出绑定到 tty，然后返回对应的 pty,tty
func StartPtyWithAttrs(c *exec.Cmd, sz *Winsize, attrs *syscall.SysProcAttr) (*os.File, *os.File, error) {
	ptyF, tty, err := Open()
	if err != nil {
		return nil, nil, err
	}
	//defer func() { _ = tty.Close() }() // Best effort.
	if sz != nil {
		if err := Setsize(ptyF, sz); err != nil {
			_ = ptyF.Close() // Best effort.
			return nil, nil, err
		}
	}
	if c.Stdout == nil {
		c.Stdout = tty
	}
	if c.Stderr == nil {
		c.Stderr = tty
	}
	if c.Stdin == nil {
		c.Stdin = tty
	}
	c.SysProcAttr = attrs
	return ptyF, tty, err
}

func Open() (pty, tty *os.File, err error) {
	p, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}
	// In case of error after this point, make sure we close the ptmx fd.
	defer func() {
		if err != nil {
			_ = p.Close() // Best effort.
		}
	}()

	sname, err := ptsname(p)
	if err != nil {
		return nil, nil, err
	}

	if err := unlockpt(p); err != nil {
		return nil, nil, err
	}

	t, err := os.OpenFile(sname, os.O_RDWR|syscall.O_NOCTTY, 0) //nolint:gosec // Expected Open from a variable.
	if err != nil {
		return nil, nil, err
	}
	return p, t, nil
}

func ptsname(f *os.File) (string, error) {
	var n uint32
	err := ioctl(f.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))) //nolint:gosec // Expected unsafe pointer for Syscall call.
	if err != nil {
		return "", err
	}
	return "/dev/pts/" + strconv.Itoa(int(n)), nil
}

func unlockpt(f *os.File) error {
	var u int32
	// use TIOCSPTLCK with a pointer to zero to clear the lock
	return ioctl(f.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&u))) //nolint:gosec // Expected unsafe pointer for Syscall call.
}

func ioctl(fd, cmd, ptr uintptr) error {
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, cmd, ptr)
	if e != 0 {
		return e
	}
	return nil
}

func Setsize(t *os.File, ws *Winsize) error {
	//nolint:gosec // Expected unsafe pointer for Syscall call.
	return ioctl(t.Fd(), syscall.TIOCSWINSZ, uintptr(unsafe.Pointer(ws)))
}
