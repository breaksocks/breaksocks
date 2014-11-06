package socks5

import (
	"github.com/golang/glog"
	"io"
	"net"
)

const SocksVersion = 5
const SocksUPCheckVersion = 1

var (
	SocksAuthNotRequired         = []byte{SocksVersion, 0}
	SocksAuthUserPasswd          = []byte{SocksVersion, 2}
	SocksAuthMethodNotMatch      = []byte{SocksVersion, 0xFF}
	SocksUPAuthSuccess           = []byte{SocksUPCheckVersion, 0}
	SocksUPAuthFail              = []byte{SocksUPCheckVersion, 1}
	SocksReplySuccess            = []byte{SocksVersion, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	SocksReplyServerFail         = []byte{SocksVersion, 1, 0, 1, 0, 0, 0, 0, 0, 0}
	SocksReplyNotAllowed         = []byte{SocksVersion, 2, 0, 1, 0, 0, 0, 0, 0, 0}
	SocksReplyNetworkUnreachable = []byte{SocksVersion, 3, 0, 1, 0, 0, 0, 0, 0, 0}
	SocksReplyHostUnreachable    = []byte{SocksVersion, 4, 0, 1, 0, 0, 0, 0, 0, 0}
	SocksReplyRefused            = []byte{SocksVersion, 5, 0, 1, 0, 0, 0, 0, 0, 0}
	SocksReplyTTLExpired         = []byte{SocksVersion, 6, 0, 1, 0, 0, 0, 0, 0, 0}
	SocksReplyInvalidCommand     = []byte{SocksVersion, 7, 0, 1, 0, 0, 0, 0, 0, 0}
	SocksReplyInvalidAddrType    = []byte{SocksVersion, 8, 0, 1, 0, 0, 0, 0, 0, 0}
)

type Socks5Server struct {
	tunnel   SocksTunnel
	auth     SocksAuth
	listener *net.TCPListener
}

func NewSocks5Server(addr string, t SocksTunnel, auth SocksAuth) (*Socks5Server, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Socks5Server{tunnel: t, auth: auth,
		listener: l.(*net.TCPListener)}, nil
}

func (ss *Socks5Server) Run() {
	for {
		if conn, err := ss.listener.AcceptTCP(); err == nil {
			go ss.handleRequest(conn)
		} else {
			glog.Fatalf("accept fail: %v", err)
		}
	}
}

func (ss *Socks5Server) handleRequest(conn *net.TCPConn) {
	defer conn.Close()
	if !ss.authenticate(conn) {
		return
	}

	/*Request:
	  +----+-----+-------+------+----------+----------+
	  |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	  +----+-----+-------+------+----------+----------+
	  | 1  |  1  | X'00' |  1   | Variable |    2     |
	  +----+-----+-------+------+----------+----------+
	*/
	var buf [262]byte
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	} else if buf[0] != 5 {
		return
	} else if buf[1] != 1 {
		conn.Write(SocksReplyInvalidCommand)
		return
	}

	switch buf[3] {
	case 1:
		if _, err := io.ReadFull(conn, buf[4:10]); err == nil {
			port := int(buf[8])*256 + int(buf[9])
			conn.Write(SocksReplySuccess)
			ss.tunnel.DoIPProxy(buf[4:8], port, conn)
		}
	case 3:
		if _, err := io.ReadFull(conn, buf[4:5]); err != nil {
			return
		} else if buf[4] == 0 {
			conn.Write(SocksReplyHostUnreachable)
			return
		} else if _, err = io.ReadFull(conn, buf[5:7+buf[4]]); err != nil {
			return
		}
		conn.Write(SocksReplySuccess)
		port := int(buf[5+buf[4]])*256 + int(buf[6+buf[4]])
		ss.tunnel.DoDomainProxy(string(buf[5:5+buf[4]]), port, conn)
	case 4:
		if _, err := io.ReadFull(conn, buf[4:22]); err == nil {
			port := int(buf[20])*256 + int(buf[21])
			conn.Write(SocksReplySuccess)
			ss.tunnel.DoIPProxy(buf[4:20], port, conn)
		}
	default:
		conn.Write(SocksReplyInvalidAddrType)
	}
}

func (ss *Socks5Server) authenticate(conn *net.TCPConn) bool {
	/*
		+----+----------+----------+
		|VER | NMETHODS | METHODS  |
		+----+----------+----------+
		| 1  |    1     | 1 to 255 |
		+----+----------+----------+
	*/
	var buf [257]byte
	if _, err := io.ReadFull(conn, buf[:2]); err != nil || buf[0] != 5 {
		return false
	} else if buf[1] > 0 {
		if _, err := io.ReadFull(conn, buf[2:2+buf[1]]); err != nil {
			return false
		}
	}

	/*
	   +----+--------+
	   |VER | METHOD |
	   +----+--------+
	   | 1  |   1    |
	   +----+--------+
	*/
	var method byte = 0
	auth_rep := SocksAuthNotRequired
	if ss.auth != nil {
		method = 2
		auth_rep = SocksAuthUserPasswd
	}

	support_method := false
	for i := 2; i < 2+int(buf[1]); i++ {
		if buf[i] == method {
			support_method = true
			if _, err := conn.Write(auth_rep); err != nil {
				return false
			}
			break
		}
	}
	if !support_method {
		conn.Write(SocksAuthMethodNotMatch)
		return false
	}

	return ss.checkUserPasswd(conn)
}

func (ss *Socks5Server) checkUserPasswd(conn *net.TCPConn) bool {
	if ss.auth == nil {
		return true
	}
	/*
	   +----+------+----------+------+----------+
	   |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
	   +----+------+----------+------+----------+
	   | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
	   +----+------+----------+------+----------+
	*/
	var buf [513]byte

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return false
	} else if buf[0] != 1 || buf[1] == 0 {
		return false
	}
	idx := 2 + buf[1]
	if _, err := io.ReadFull(conn, buf[2:idx+1]); err != nil || buf[idx] == 0 {
		return false
	}
	user := string(buf[2:idx])
	if _, err := io.ReadFull(conn, buf[idx+1:idx+1+buf[idx]]); err != nil {
		return false
	}
	passwd := string(buf[idx+1 : idx+1+buf[idx]])

	auth_ok := ss.auth.Check(user, passwd)
	if auth_ok {
		conn.Write(SocksUPAuthSuccess)
	} else {
		conn.Write(SocksUPAuthFail)
	}

	return auth_ok
}
