package server

import (
	"fmt"
	"github.com/breaksocks/breaksocks/crypto"
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
		config *crypto.CipherConfig
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

		cipher_cfg := crypto.GetCipherConfig(config.GlobalEncryptMethod)
		if cipher_cfg == nil {
			return nil, fmt.Errorf("no such cipher: %s", config.GlobalEncryptMethod)
		}

		key, iv := crypto.MakeCryptoKeyIV(config.GlobalEncryptPassword,
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
			log.Fatalf("accept fail: %s", err.Error())
		} else {
			go ser.processClient(conn)
		}
	}
}

func (ser *Server) processClient(conn *net.TCPConn) {
	defer conn.Close()

	pipe := crypto.NewStreamPipe(conn)
	if ser.g_cipher != nil {
		enc, dec, err := ser.g_cipher.config.NewCipher(ser.g_cipher.key, ser.g_cipher.iv)
		if err != nil {
			log.Fatalf("make global enc/dec fail: %s", err.Error())
		}
		pipe.SwitchCipher(enc, dec)
	}
	if err = conn.SetNoDelay(true); err != nil {
		log.Fatalf("set client NoDelay fail: %s", err.Error())
	}

	user := ser.clientStartup(pipe)
	if session == nil {
		return
	}
	ser.clientLoop(user, pipe)
}

func (ser *Server) clientStartup(pipe *crypto.StreamPipe) *session.Session {
	// cipher exchange && session cipher switch
	header := make([]byte, 4)
	if _, err := io.ReadFull(pipe, header); err != nil {
		log.Printf("receive startup header fail: %s", err.Error())
		return nil
	}

	if header[0] != protocol.PROTO_MAGIC {
		log.Printf("reveiced a invalid magic: %d", header[0])
		return nil
	}

	if header[1] == 0 {
		return ser.newSession(pipe)
	}
	if header[2] == 0 || header[3] == 0 {
		log.Printf("reuse session, 0 random/hmac")
		return nil
	}

	body_size := header[1] + header[2] + header[3]
	body := make([]byte, body_size)
	if _, err := io.ReadFull(pipe, body); err != nil {
		log.Printf("receive startup body fail")
		return nil
	}
	return ser.reuseSession(pipe, body[:header[1]],
		body[header[1]:header[1]+header[2]],
		body[header[1]+header[2]:])
}

func (ser *Server) newSession(pipe *crypto.StreamPipe) *session.Session {
	ctx, err := crypto.NewCipherContext(5)
	if err != nil {
		log.Printf("create cipher context fail: %s", err.Error())
		return nil
	}

	f, err := ctx.MakeF()
	if err != nil {
		log.Printf("make f fail: %s", err.Error())
	}

	//buf := make([]byte)
}

func (ser *Server) reuseSession(pipe *crypto.StreamPipe, s_bs, rand_bs, hmac_bs []byte) *session.Session {

}

func (ser *Server) clientLoop(user *session.Session, pipe *crypto.StreamPipe) {
	// socks proxy
}
