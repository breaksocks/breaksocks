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
	"sync"
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
	ser.clientLoop(user, pipe)
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

func (ser *Server) clientLoop(user *Session, pipe *StreamPipe) {
	glog.V(1).Infof("start proxy: %s(%s)", user.Username, user.Id)
	write_ch := make(chan []byte, 4096)
	write_pool := NewBytesPool(4096, 1500)

	go func() {
		for {
			if data, ok := <-write_ch; ok {
				pkt_size := ReadN2(data[2:])
				if _, err := pipe.Write(data[:4+pkt_size]); err != nil {
					glog.V(1).Infof("write to client fail: %s", err.Error())
					// TODO shutdown link
				}
				write_pool.Put(data)
			} else {
				break
			}
		}
	}()
	defer close(write_ch)

	conns := make(map[uint32]chan []byte)
	var lock sync.RWMutex
	read_pool := NewBytesPool(1024, 1500)
	for {
		buf := read_pool.Get()
		if _, err := io.ReadFull(pipe, buf[:4]); err != nil {
			glog.V(1).Infof("recv packet fail: %s", err.Error())
			return
		} else {
			if buf[0] != PROTO_MAGIC {
				glog.V(1).Infof("invalid magic: %d", buf[0])
				return
			}
			pkt_size := ReadN2(buf[2:])
			if pkt_size > 1500-4 {
				glog.V(1).Infof("recved an invalid packet, size: %d", pkt_size)
				return
			}
			if _, err := io.ReadFull(pipe, buf[4:pkt_size+4]); err != nil {
				glog.V(1).Infof("recv packet fail: %s", err.Error())
				return
			}

			switch buf[1] {
			case PACKET_PROXY:
				conn_id := ReadN4(buf[4:])
				lock.RLock()
				ch := conns[conn_id]
				lock.RUnlock()
				if ch != nil {
					ch <- buf
				} else {
					glog.V(1).Infof("no such conn: %d", conn_id)
				}
			case PACKET_NEW_CONN:
				port := ReadN2(buf[6:])
				conn_id := ReadN4(buf[8:])
				conn_type := buf[4]
				addr := make([]byte, int(buf[5]))
				copy(addr, buf[12:12+int(buf[5])])
				read := make(chan []byte, 32)
				lock.Lock()
				conns[conn_id] = read
				lock.Unlock()
				go func() {
					if conn, err := ser.connectRemote(conn_type, addr, port); err == nil {
						ser.copyRemote(read, write_ch, read_pool, write_pool, conn_id, conn)
					}
					lock.Lock()
					delete(conns, conn_id)
					lock.Unlock()
				}()
				read_pool.Put(buf)
			case PACKET_CLOSE_CONN:
				conn_id := ReadN4(buf[4:])
				lock.Lock()
				ch := conns[conn_id]
				if ch != nil {
					close(ch)
					delete(conns, conn_id)
				}
				lock.Unlock()
				read_pool.Put(buf)
			}
		}
	}
}

func (ser *Server) connectRemote(conn_type byte, addr []byte, port uint16) (*net.TCPConn, error) {
	var rconn *net.TCPConn

	if conn_type == PROTO_ADDR_IP {
		var remote_addr net.TCPAddr
		remote_addr.IP = net.IP(addr)
		remote_addr.Port = int(port)
		if conn, err := net.DialTCP("tcp", nil, &remote_addr); err == nil {
			rconn = conn
		} else {
			glog.V(1).Infof("conn %#v fail: %s", remote_addr, err.Error())
			return nil, err
		}
	} else {
		raddr := net.JoinHostPort(string(addr), fmt.Sprintf("%d", port))
		if conn, err := net.Dial("tcp", raddr); err == nil {
			rconn = conn.(*net.TCPConn)
		} else {
			glog.V(1).Infof("conn %#v fail: %s", raddr, err.Error())
			return nil, err
		}
	}

	return rconn, nil
}

func (ser *Server) copyRemote(read, write chan []byte, read_p, write_p *BytesPool,
	conn_id uint32, conn *net.TCPConn) {
	defer conn.Close()

	exit_ch := make(chan bool)

	go func() {
		for {
			buf := write_p.Get()
			if n, err := conn.Read(buf[8:]); err == nil {
				buf[0] = PROTO_MAGIC
				buf[1] = PACKET_PROXY
				WriteN2(buf[2:], uint16(n+4))
				WriteN4(buf[4:], conn_id)
				write <- buf
			} else {
				write_p.Put(buf)
				exit_ch <- true
				return
			}
		}
	}()

for_loop:
	for {
		select {
		case data, ok := <-read:
			if !ok {
				return
			}
			pkt_size := ReadN2(data[2:])
			_, err := conn.Write(data[:4+pkt_size])
			read_p.Put(data)
			if err != nil {
				break for_loop
			}
		case <-exit_ch:
			break for_loop
		}
	}

	buf := write_p.Get()
	buf[0] = PROTO_MAGIC
	buf[1] = PACKET_CLOSE_CONN
	WriteN2(buf[2:], 4)
	WriteN4(buf[4:], conn_id)
	write <- buf
}
