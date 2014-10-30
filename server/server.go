package server

import (
	gocrypto "crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"github.com/breaksocks/breaksocks/crypto"
	"github.com/breaksocks/breaksocks/protocol"
	"github.com/breaksocks/breaksocks/session"
	"github.com/breaksocks/breaksocks/utils"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
)

type Server struct {
	sessions  *session.SessionManager
	config    *utils.ServerConfig
	user_cfgs *UserConfigs

	priv_key *rsa.PrivateKey
	pub_der  []byte
	g_cipher struct {
		config *crypto.CipherConfig
		key    []byte
		iv     []byte
	}
	enc_methods []byte

	listenser *net.TCPListener
}

func NewServer(config *utils.ServerConfig) (*Server, error) {
	server := new(Server)
	var err error

	if len(config.LinkEncryptMethods) == 0 {
		return nil, fmt.Errorf("encrypt methods can't be empty")
	}
	server.enc_methods = []byte(strings.Join(config.LinkEncryptMethods, ","))

	if server.priv_key, err = crypto.LoadRSAPrivateKey(config.KeyPath); err != nil {
		if os.IsNotExist(err) {
			log.Printf("generating new private key(RSA 2048bits) ...")
			if server.priv_key, err = crypto.GenerateRSAKey(2048, config.KeyPath); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	if server.pub_der, err = x509.MarshalPKIXPublicKey(&server.priv_key.PublicKey); err != nil {
		return nil, err
	}

	if config.GlobalEncryptMethod != "" {
		if config.GlobalEncryptPassword == "" {
			return nil, fmt.Errorf("global cipher password can't be empty")
		}

		cipher_cfg := crypto.GetCipherConfig(config.GlobalEncryptMethod)
		if cipher_cfg == nil {
			return nil, fmt.Errorf("no such cipher: %s", config.GlobalEncryptMethod)
		}

		key, iv := crypto.MakeCryptoKeyIV([]byte(config.GlobalEncryptPassword),
			cipher_cfg.KeySize, cipher_cfg.IVSize)
		server.g_cipher.config = cipher_cfg
		server.g_cipher.key = key
		server.g_cipher.iv = iv
	}

	if server.user_cfgs, err = GetUserConfigs(config.UserConfigPath); err != nil {
		return nil, err
	}

	addr := net.TCPAddr{IP: net.ParseIP(config.IP), Port: int(config.Port)}
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
	if ser.g_cipher.config != nil {
		enc, dec, err := ser.g_cipher.config.NewCipher(ser.g_cipher.key, ser.g_cipher.iv)
		if err != nil {
			log.Printf("kl: %d, ivl: %d, %#v", len(ser.g_cipher.key), len(ser.g_cipher.iv),
				ser.g_cipher.config)
			log.Fatalf("make global enc/dec fail: %s", err.Error())
		}
		pipe.SwitchCipher(enc, dec)
	}
	if err := conn.SetNoDelay(true); err != nil {
		log.Fatalf("set client NoDelay fail: %s", err.Error())
	}

	user := ser.clientStartup(pipe)
	if user == nil {
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
	p_bs, f_bs := ctx.P.Bytes(), f.Bytes()

	buf := make([]byte, len(ser.pub_der)+len(p_bs)+len(f_bs)+len(ser.enc_methods)+2048)
	utils.WriteN2(buf, uint16(len(ser.pub_der)))
	utils.WriteN2(buf[2:], uint16(len(p_bs)))
	utils.WriteN2(buf[4:], uint16(len(f_bs)))
	utils.WriteN2(buf[8:], uint16(len(ser.enc_methods)))
	cur := 10
	cur += copy(buf[cur:], ser.pub_der)
	cur += copy(buf[cur:], p_bs)
	buf[cur] = byte(ctx.G)
	cur += 1
	cur += copy(buf[cur:], f_bs)

	hash_bs := sha256.Sum256(buf[:cur])
	if sig, err := rsa.SignPKCS1v15(rand.Reader, ser.priv_key, gocrypto.SHA256,
		hash_bs[:]); err != nil {
		log.Printf("sign p/g/f fail: %s", err.Error())
		return nil
	} else {
		utils.WriteN2(buf[6:], uint16(len(sig)))
		cur += copy(buf[cur:], sig)
	}
	cur += copy(buf[cur:], ser.enc_methods)

	if _, err := pipe.Write(buf[:cur]); err != nil {
		log.Printf("write pipe fail: %s", err.Error())
		return nil
	}

	// finihs cipher exchange
	if _, err := io.ReadFull(pipe, buf[:4]); err != nil {
		log.Printf("read cipher exchange finish fail: %s", err.Error())
		return nil
	}
	e_size := utils.ReadN2(buf)
	md_size := utils.ReadN2(buf[2:])
	if e_size == 0 || md_size < 0 || e_size+md_size > uint16(len(buf)) {
		log.Printf("invalid e/md size:%d %d", e_size, md_size)
		return nil
	}
	if _, err := io.ReadFull(pipe, buf[:e_size+md_size]); err != nil {
		log.Printf("read cipher exchange finish body fail: %s", err.Error())
		return nil
	}
	method := string(buf[e_size : e_size+md_size])
	var cipher_cfg *crypto.CipherConfig
	for _, md := range ser.config.LinkEncryptMethods {
		if md == method {
			cipher_cfg = crypto.GetCipherConfig(method)
			break
		}
	}
	if cipher_cfg == nil {
		log.Printf("invalid method: %s", method)
		return nil
	}
	ctx.CalcKey(new(big.Int).SetBytes(buf[:e_size]))
	key, iv := ctx.MakeCryptoKeyIV(cipher_cfg.KeySize, cipher_cfg.IVSize)
	if enc, dec, err := cipher_cfg.NewCipher(key, iv); err != nil {
		log.Printf("new stream cipher fail: %s", err.Error())
		return nil
	} else {
		pipe.SwitchCipher(enc, dec)
	}

	s := ser.clientLogin(pipe)
	if s != nil {
		s.CipherCtx = ctx
		s.CipherConfig = cipher_cfg
	}
	return s
}

func (ser *Server) clientLogin(pipe *crypto.StreamPipe) *session.Session {
	buf := make([]byte, 4+32+32)
	if _, err := io.ReadFull(pipe, buf[:4]); err != nil {
		log.Printf("receive login req fail: %s", err.Error())
		return nil
	}

	// rep
	login_ok := protocol.B_FALSE
	var msg []byte
	var s *session.Session

	user_size, passwd_size := buf[2], buf[3]
	if user_size > 0 && user_size <= 32 && passwd_size > 0 && passwd_size <= 32 {
		if _, err := io.ReadFull(pipe, buf[:user_size+passwd_size]); err != nil {
			log.Printf("read login body fail: %s", err.Error())
			return nil
		}
		user, passwd := string(buf[:user_size]), buf[user_size:user_size+passwd_size]
		user_cfg := ser.user_cfgs.Get(user)
		if user_cfg == nil || user_cfg.Password != string(passwd) {
			msg = []byte("invalid username/password")
		} else {
			login_ok = protocol.B_TRUE
			var err error
			if s, err = ser.sessions.NewSession(); err != nil {
				log.Printf("new session fail: %s", err.Error())
				return nil
			}
			s.Username = string(user)
		}
	} else {
		msg = []byte("user/passwd size invalid")
	}

	utils.WriteN2(buf, protocol.PROTO_VERSION)
	buf[2] = login_ok
	buf[3] = byte(len(msg))
	copy(buf[4:], msg)
	if _, err := pipe.Write(buf[:4+buf[3]]); err != nil {
		log.Printf("write err rep fail: %s", err.Error())
		return nil
	}
	return s
}

func CheckMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}

func (ser *Server) reuseSession(pipe *crypto.StreamPipe, s_bs, rand_bs, hmac_bs []byte) *session.Session {
	sessionId := session.SessionIdFromBytes(s_bs)
	s := ser.sessions.GetSession(sessionId)
	if s == nil {
		return nil
	}

	do_init := false
	rep := []byte{protocol.B_TRUE, protocol.REUSE_SUCCESS}
	if !CheckMAC(rand_bs, hmac_bs, s.CipherCtx.CryptoKey) {
		rep[0] = protocol.B_FALSE
		rep[1] = protocol.REUSE_FAIL_START_CIPHER_EXCHANGE | protocol.REUSE_FAIL_HMAC_FAIL
		do_init = true
	}

	if _, err := pipe.Write(rep); err != nil {
		log.Printf("write init rep fail: %s", err.Error())
		return nil
	}
	if do_init {
		return ser.newSession(pipe)
	}
	return s
}

func (ser *Server) clientLoop(user *session.Session, pipe *crypto.StreamPipe) {
	// socks proxy
}
