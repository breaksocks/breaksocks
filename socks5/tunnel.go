package socks5

import (
	"io"
)

type SocksTunnel interface {
	DoDomainProxy(domain string, port int, rw io.ReadWriteCloser)
	DoIPProxy(addr []byte, port int, rw io.ReadWriteCloser)
}
