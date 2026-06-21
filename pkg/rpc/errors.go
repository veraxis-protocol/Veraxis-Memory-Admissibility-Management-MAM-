package rpc

import "fmt"

type Code uint8

const (
	CodeOK Code = iota
	CodeInvalidArgument
	CodeInternal
)

type Error struct {
	Code    Code
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code.String(), e.Message)
}

func (c Code) String() string {
	switch c {
	case CodeInvalidArgument:
		return "InvalidArgument"
	case CodeInternal:
		return "Internal"
	default:
		return "OK"
	}
}

func InvalidArgument(message string) error {
	return &Error{Code: CodeInvalidArgument, Message: message}
}

func Internal(message string) error {
	return &Error{Code: CodeInternal, Message: message}
}

func ErrorCode(err error) Code {
	if err == nil {
		return CodeOK
	}
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return CodeInternal
}
