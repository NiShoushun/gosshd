package gosshd

import (
	"fmt"
	"runtime"
)

type PlatformNotSupportError struct {
	Function string
}

func (e PlatformNotSupportError) Error() string {
	return fmt.Sprintf("'%s' not supported on '%s'", e.Function, runtime.GOOS)
}

type PermitNotAllowedError struct {
	Msg string
}

func (e PermitNotAllowedError) Error() string {
	return fmt.Sprintf("permit not allowd: %s", e.Msg)
}

type UserNotExistError struct {
	User string
}

func (e UserNotExistError) Error() string {
	return fmt.Sprintf("%s not exists", e.User)
}
