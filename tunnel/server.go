package tunnel

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"github.com/golang/glog"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
)

type Server struct {
	sessions  *SessionManager
	config    *ServerConfig
	user_cfgs *UserConfigs

	priv_key    *rsa.PrivateKey
	pub_der     []byte
	g_cipher    *GlobalCipherConfig
	enc_methods []byte

	listenser *net.TCPListener
}

func NewServer(config *ServerConfig) (*Server, error) {
	server := new(Server)
	var err error

	if len(config.LinkEncryptMethods) == 0 {
		return nil, fmt.Errorf("encrypt methods can't be empty")
	}
	server.enc_methods = []byte(strings.Join(config.LinkEncryptMethods, ","))

	if server.priv_key, err = LoadRSAPrivateKey(config.KeyPath); err != nil {
		if os.IsNotExist(err) {
			glog.Info("generating new private key(RSA 2048bits) ...")
			if server.priv_key, err = GenerateRSAKey(2048, config.KeyPath); err != nil {
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
		if server.g_cipher, err = LoadGlobalCipherConfig(
			config.GlobalEncryptMethod, []byte(config.GlobalEncryptPassword)); err != nil {
			return nil, err
		}
	}

	if server.user_cfgs, err = GetUserConfigs(config.UserConfigPath); err != nil {
		return nil, err
	}

	if l, err := net.Listen("tcp", config.ListenAddr); err == nil {
		server.listenser = l.(*net.TCPListener)
		glog.Infof("listen on: %s", config.ListenAddr)
	} else {
		return nil, err
	}

	server.sessions = NewSessionManager()
	server.config = config
	return server, nil
}

func (ser *Server) Run() {
	for {
		if conn, err := ser.listenser.AcceptTCP(); err != nil {
			glog.Fatalf("accept fail: %s", err.Error())
		} else {
			go ser.processClient(conn)
		}
	}
}

func (ser *Server) processClient(conn *net.TCPConn) {
	defer conn.Close()

	pipe := NewStreamPipe(conn)
	if ser.g_cipher != nil {
		enc, dec, err := ser.g_cipher.NewCipher()
		if err != nil {
			glog.Fatalf("make global enc/dec fail: %s", err.Error())
		}
		pipe.SwitchCipher(enc, dec)
	}
	if err := conn.SetNoDelay(true); err != nil {
		glog.Fatalf("set client NoDelay fail: %s", err.Error())
	}

	user := ser.clientStartup(pipe)
	if user == nil {
		return
	}
	cli := NewClientProxy(user, pipe)
	cli.DoProxy()
}

func (ser *Server) clientStartup(pipe *StreamPipe) *Session {
	// cipher exchange && session cipher switch
	header := make([]byte, 4)
	if _, err := io.ReadFull(pipe, header); err != nil {
		glog.V(1).Infof("receive startup header fail: %s", err.Error())
		return nil
	}

	if header[0] != PROTO_MAGIC {
		glog.V(1).Infof("reveiced a invalid magic: %d", header[0])
		return nil
	}

	if header[1] == 0 {
		return ser.newSession(pipe)
	}
	if header[2] == 0 || header[3] == 0 {
		glog.V(1).Info("reuse session, 0 random/hmac")
		return nil
	}

	body_size := header[1] + header[2] + header[3]
	body := make([]byte, body_size)
	if _, err := io.ReadFull(pipe, body); err != nil {
		glog.V(1).Info("receive startup body fail")
		return nil
	}
	return ser.reuseSession(pipe, body[:header[1]],
		body[header[1]:header[1]+header[2]],
		body[header[1]+header[2]:])
}

func (ser *Server) newSession(pipe *StreamPipe) *Session {
	ctx, err := NewCipherContext(5)
	if err != nil {
		glog.Errorf("create cipher context fail: %s", err.Error())
		return nil
	}

	f, err := ctx.MakeF()
	if err != nil {
		glog.Errorf("make f fail: %s", err.Error())
	}
	p_bs, f_bs := ctx.P.Bytes(), f.Bytes()

	buf := make([]byte, len(ser.pub_der)+len(p_bs)+len(f_bs)+len(ser.enc_methods)+2048)
	WriteN2(buf, uint16(len(ser.pub_der)))
	WriteN2(buf[2:], uint16(len(p_bs)))
	WriteN2(buf[4:], uint16(len(f_bs)))
	WriteN2(buf[8:], uint16(len(ser.enc_methods)))
	cur := 10
	cur += copy(buf[cur:], ser.pub_der)
	cur += copy(buf[cur:], p_bs)
	buf[cur] = byte(ctx.G)
	cur += 1
	cur += copy(buf[cur:], f_bs)

	hash_bs := sha256.Sum256(buf[10+len(ser.pub_der) : cur])
	if sig, err := rsa.SignPKCS1v15(rand.Reader, ser.priv_key, crypto.SHA256,
		hash_bs[:]); err != nil {
		glog.Errorf("sign p/g/f fail: %s", err.Error())
		return nil
	} else {
		WriteN2(buf[6:], uint16(len(sig)))
		cur += copy(buf[cur:], sig)
	}
	cur += copy(buf[cur:], ser.enc_methods)

	if _, err := pipe.Write(buf[:cur]); err != nil {
		glog.V(1).Infof("write pipe fail: %s", err.Error())
		return nil
	}

	// finihs cipher exchange
	if _, err := io.ReadFull(pipe, buf[:4]); err != nil {
		glog.V(1).Infof("read cipher exchange finish fail: %s", err.Error())
		return nil
	}
	e_size := ReadN2(buf)
	md_size := ReadN2(buf[2:])
	if e_size == 0 || md_size < 0 || e_size+md_size > uint16(len(buf)) {
		glog.V(1).Infof("invalid e/md size:%d %d", e_size, md_size)
		return nil
	}
	if _, err := io.ReadFull(pipe, buf[:e_size+md_size]); err != nil {
		glog.V(1).Infof("read cipher exchange finish body fail: %s", err.Error())
		return nil
	}
	method := string(buf[e_size : e_size+md_size])
	var cipher_cfg *CipherConfig
	for _, md := range ser.config.LinkEncryptMethods {
		if md == method {
			cipher_cfg = GetCipherConfig(method)
			break
		}
	}
	if cipher_cfg == nil {
		glog.V(1).Infof("invalid method: %s", method)
		return nil
	}
	ctx.CalcKey(new(big.Int).SetBytes(buf[:e_size]))
	key, iv := ctx.MakeCryptoKeyIV(cipher_cfg.KeySize, cipher_cfg.IVSize)
	if enc, dec, err := cipher_cfg.NewCipher(key, iv); err != nil {
		glog.Errorf("new stream cipher fail: %s", err.Error())
		return nil
	} else {
		pipe.SwitchCipher(enc, dec)
	}

	s := ser.clientLogin(ctx, pipe)
	if s != nil {
		s.CipherCtx = ctx
		s.CipherConfig = cipher_cfg
	}
	return s
}

func (ser *Server) clientLogin(ctx *CipherContext, pipe *StreamPipe) *Session {
	buf := make([]byte, 4+32+32)
	if _, err := io.ReadFull(pipe, buf[:4]); err != nil {
		glog.V(1).Infof("receive login req fail: %s", err.Error())
		return nil
	}

	// rep
	login_ok := B_FALSE
	var msg []byte
	var s *Session

	user_size, passwd_size := buf[2], buf[3]
	if user_size > 0 && user_size <= 32 && passwd_size > 0 && passwd_size <= 32 {
		if _, err := io.ReadFull(pipe, buf[:user_size+passwd_size]); err != nil {
			glog.V(1).Infof("read login body fail: %s", err.Error())
			return nil
		}
		user, passwd := string(buf[:user_size]), buf[user_size:user_size+passwd_size]
		user_cfg := ser.user_cfgs.Get(user)
		if user_cfg == nil || user_cfg.Password != string(passwd) {
			msg = []byte("invalid username/password")
		} else {
			login_ok = B_TRUE
			var err error
			if s, err = ser.sessions.NewSession(ctx); err != nil {
				glog.Errorf("new session fail: %s", err.Error())
				return nil
			}
			s.Username = string(user)
			if msg, err = s.Id.Bytes(); err != nil {
				glog.Errorf("sessionId toBytes fail: %s", err.Error())
				return nil
			}
		}
	} else {
		msg = []byte("user/passwd size invalid")
	}

	WriteN2(buf, PROTO_VERSION)
	buf[2] = login_ok
	buf[3] = byte(len(msg))
	copy(buf[4:], msg)
	if _, err := pipe.Write(buf[:4+buf[3]]); err != nil {
		glog.V(1).Infof("write err rep fail: %s", err.Error())
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

func (ser *Server) reuseSession(pipe *StreamPipe, s_bs, rand_bs, hmac_bs []byte) *Session {
	sessionId := SessionIdFromBytes(s_bs)
	s := ser.sessions.GetSession(sessionId)
	if s == nil {
		return nil
	}

	do_init := false
	rep := []byte{B_TRUE, REUSE_SUCCESS}
	if !CheckMAC(rand_bs, hmac_bs, s.CipherCtx.CryptoKey) {
		rep[0] = B_FALSE
		rep[1] = REUSE_FAIL_START_CIPHER_EXCHANGE | REUSE_FAIL_HMAC_FAIL
		do_init = true
	}

	if _, err := pipe.Write(rep); err != nil {
		glog.V(1).Infof("write init rep fail: %s", err.Error())
		return nil
	}
	if do_init {
		return ser.newSession(pipe)
	}
	return s
}
