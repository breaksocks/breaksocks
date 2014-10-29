package server

import (
	"fmt"
	"github.com/breaksocks/breaksocks/cipher"
	"github.com/breaksocks/breaksocks/protocol"
	"github.com/breaksocks/breaksocks/session"
	"github.com/breaksocks/breaksocks/utils"
	"io"
	"log"
	"net"
)

type Server struct {
	sessions  *session.SessionManager
	config    *utils.ServerConfig
	user_cfgs *UserConfigs
	listenser *net.TCPListener
	g_cipher  struct {
		config *cipher.CipherConfig
		key    []byte
		iv     []iv
	}
}

func NewServer(config *utils.ServerConfig) (*Server, error) {
	addr := net.TCPAddr{IP: config.IP, Port: config.Port}
	server := new(Server)
	var err error

	if config.GlobalEncryptMethod != "" {
		if config.GlobalEncryptPassword == "" {
			return nil, fmt.Errorf("global cipher password can't be empty")
		}

		cipher_cfg := cipher.GetCipherConfig(config.GlobalEncryptMethod)
		if cipher_cfg == nil {
			return nil, fmt.Errorf("no such cipher: %s", config.GlobalEncryptMethod)
		}

		key, iv := cipher.MakeCryptoKeyIV(config.GlobalEncryptPassword,
			cipher_cfg.KeySize, cipher_cfg.IVSize)
		server.g_cipher.config = cipher_cfg
		server.g_cipher.key = key
		server.g_cipher.iv = iv
	}

	if server.user_cfgs, err = GetUserConfigs(config.UserConfigPath); err != nil {
		return nil, err
	}

	if server.listenser, err = net.ListenTCP("tcp", &addr); err != nil {
		return nil, err
	}

	server.sessions = session.NewSessionManager()
	server.config = config
	return server, nil

}

func (ser *Server) Run() {
	for {
		if conn, err := ser.listenser.AcceptTCP(); err != nil {
			log.Fatal("accept fail", err)
		} else {
			go ser.processClient(conn)
		}
	}
}

func (ser *Server) processClient(conn *net.TCPConn) {
	defer conn.Close()

	pipe := cipher.NewEncStreamPipe(conn)
	enc, dec, err := ser.g_cipher.config.NewCipher(ser.g_cipher.key, ser.g_cipher.iv)
	if err != nil {
		log.Fatal("make global enc/dec fail", err)
	}
	if err = conn.SetNoDelay(true); err != nil {
		log.Fatal("set client NoDelay fail", err)
	}
	pipe.SwitchCipher(enc, dec)

	user := ser.clientStartup(pipe)
	if session == nil {
		return
	}
	ser.clientLoop(user, pipe)
}

func (ser *Server) clientStartup(pipe *cipher.StreamPipe) *session.Session {
	// cipher exchange && session cipher switch
}

func (ser *Server) clientLoop(user *session.Session, pipe *cipher.StreamPipe) {
	// socks proxy
}
