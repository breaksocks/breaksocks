package tunnel

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"github.com/golang/glog"
	"io"
	"math/big"
	"net"
	"strings"
)

type Client struct {
	user   *Session
	config *ClientConfig

	g_cipher  *GlobalCipherConfig
	pipe_conn *net.TCPConn
	pipe      *StreamPipe

	cipher_cfg *CipherConfig
	cipher_ctx *CipherContext
	session_id SessionId
	conn_mgr   *ConnManager
	write_ch   chan []byte
}

func NewClient(config *ClientConfig) (*Client, error) {
	glog.V(1).Infof("%#v", config)
	cli := new(Client)
	var err error
	if config.GlobalEncryptMethod != "" {
		if cli.g_cipher, err = LoadGlobalCipherConfig(
			config.GlobalEncryptMethod, []byte(config.GlobalEncryptPassword)); err != nil {
			return nil, err
		}
	}

	cli.config = config
	cli.write_ch = make(chan []byte, 1024)
	cli.conn_mgr = NewConnManager(cli.write_ch)
	return cli, nil
}

func (cli *Client) Init() error {
	if conn, err := net.Dial("tcp", cli.config.ServerAddr); err == nil {
		if tcp_conn, ok := conn.(*net.TCPConn); ok {
			cli.pipe_conn = tcp_conn
		} else {
			return fmt.Errorf("invalid tcp conn: %#v", conn)
		}
	} else {
		return err
	}
	cli.pipe_conn.SetNoDelay(true)

	cli.pipe = NewStreamPipe(cli.pipe_conn)
	if cli.g_cipher != nil {
		enc, dec, err := cli.g_cipher.NewCipher()
		if err != nil {
			glog.Fatalf("make global enc/dec fail: %s", err.Error())
		}
		cli.pipe.SwitchCipher(enc, dec)
	}

	if err := cli.startup(); err != nil {
		return err
	}

	if err := cli.login(); err != nil {
		return err
	}

	go func() {
		for {
			if data, ok := <-cli.write_ch; ok {
				if n, err := cli.pipe.Write(data); err != nil {
					break
				} else {
					glog.V(3).Infof("remote written %d", n)
				}
			} else {
				break
			}
		}
	}()

	go func() {
		for {
			buf := make([]byte, 2048)
			if _, err := io.ReadFull(cli.pipe, buf[:4]); err != nil {
				glog.Errorf("read from server fail: %s", err.Error())
				break
			} else {
				pkt_size := ReadN2(buf[2:])
				if _, err := io.ReadFull(cli.pipe, buf[4:pkt_size+4]); err != nil {
					glog.Errorf("recv from server fail: %s", err.Error())
					break
				}
				if pkt_size > 2048-4 {
					glog.Errorf("invalid packet size: %s", pkt_size)
					break
				}
				conn_id := ReadN4(buf[4:])
				switch buf[1] {
				case PACKET_PROXY:
					glog.V(3).Infof("proxy(%d) %d", conn_id, pkt_size-4)
					cli.conn_mgr.WriteToLocalConn(conn_id, buf[8:4+pkt_size])
				case PACKET_CLOSE_CONN:
					glog.V(2).Infof("remote close %d", conn_id)
					cli.conn_mgr.CloseConn(conn_id)
				}
			}
		}
	}()

	return nil
}

func (cli *Client) startup() error {
	req_header := []byte{PROTO_MAGIC, 0, 0, 0}
	if _, err := cli.pipe.Write(req_header[:]); err != nil {
		glog.Errorf("send startup req fail: %s", err.Error())
		return err
	}

	var header [10]byte
	if _, err := io.ReadFull(cli.pipe, header[:]); err != nil {
		glog.Errorf("recv startup rep header fail: %s", err.Error())
		return err
	}

	pub_size, p_size := ReadN2(header[:]), ReadN2(header[2:])
	f_size, sig_size := ReadN2(header[4:]), ReadN2(header[6:])
	mds_size := ReadN2(header[8:])
	if pub_size == 0 || p_size == 0 || f_size == 0 || sig_size == 0 || mds_size == 0 {
		return fmt.Errorf("invalid size pub:%d p:%d f:%d sig:%d mds:%d",
			pub_size, p_size, f_size, sig_size, mds_size)
	}
	body_size := pub_size + p_size + f_size + sig_size + mds_size + 1
	body := make([]byte, body_size)
	if _, err := io.ReadFull(cli.pipe, body); err != nil {
		glog.Errorf("recv startup rep body fail: %s", err.Error())
		return err
	}

	var pub_key *rsa.PublicKey
	if pubk, err := x509.ParsePKIXPublicKey(body[:pub_size]); err == nil {
		if rsa_pub, ok := pubk.(*rsa.PublicKey); ok {
			pub_key = rsa_pub
		} else {
			glog.Errorf("invalid pubkey: %#v", pubk)
			return fmt.Errorf("invalid server pubkey")
		}
	} else {
		glog.Errorf("parse pubkey fail: %s", err.Error())
		return err
	}

	dgst := sha256.Sum256(body[pub_size : pub_size+p_size+1+f_size])
	sig := body[body_size-mds_size-sig_size : body_size-mds_size]
	if err := rsa.VerifyPKCS1v15(pub_key, crypto.SHA256, dgst[:], sig); err != nil {
		glog.Errorf("verify sig fail: %s", err.Error())
		return err
	}
	p, g := body[pub_size:pub_size+p_size], body[pub_size+p_size]
	f := body[pub_size+p_size+1 : pub_size+p_size+1+f_size]
	cli.cipher_ctx = MakeCipherContext(new(big.Int).SetBytes(p), int(g))
	if _, err := cli.cipher_ctx.MakeE(); err != nil {
		glog.Errorf("make e fail: %s", err.Error())
		return err
	}
	cli.cipher_ctx.CalcKey(new(big.Int).SetBytes(f))

	mds := strings.Split(string(body[body_size-mds_size:]), ",")
	var method string
	for _, md_opt := range mds {
		for _, md := range cli.config.LinkEncryptMethods {
			if md == md_opt {
				method = md
				break
			}
		}
		if method != "" {
			break
		}
	}
	if method == "" {
		glog.Errorf("enc method not match, server(%s) local(%s)",
			strings.Join(mds, ", "), strings.Join(cli.config.LinkEncryptMethods, ", "))
		return fmt.Errorf("enc method not match")
	}
	cli.cipher_cfg = GetCipherConfig(method)
	if cli.cipher_cfg == nil {
		glog.Errorf("invalid cipher cfg: %s", method)
		return fmt.Errorf("get cipher fail")
	}

	e_bs := cli.cipher_ctx.EF.Bytes()
	rep := make([]byte, 4+len(e_bs)+len(method))
	WriteN2(rep, uint16(len(e_bs)))
	WriteN2(rep[2:], uint16(len(method)))
	copy(rep[4:], e_bs)
	copy(rep[4+len(e_bs):], []byte(method))
	if _, err := cli.pipe.Write(rep); err != nil {
		glog.Errorf("write cipher exchange rep fail: %s", err.Error())
		return err
	}

	key, iv := cli.cipher_ctx.MakeCryptoKeyIV(cli.cipher_cfg.KeySize, cli.cipher_cfg.IVSize)
	if enc, dec, err := cli.cipher_cfg.NewCipher(key, iv); err != nil {
		glog.Errorf("new stream cipher fail: %s", err.Error())
		return err
	} else {
		cli.pipe.SwitchCipher(enc, dec)
	}

	return nil
}

func (cli *Client) login() error {
	u, p := []byte(cli.config.Username), []byte(cli.config.Password)
	buf := make([]byte, 4+len(u)+len(p))
	WriteN2(buf, PROTO_VERSION)
	buf[2] = byte(len(u))
	buf[3] = byte(len(p))
	copy(buf[4:], u)
	copy(buf[4+len(u):], p)
	if _, err := cli.pipe.Write(buf); err != nil {
		glog.Errorf("send login req fail: %s", err.Error())
		return err
	}

	if _, err := io.ReadFull(cli.pipe, buf[:4]); err != nil {
		glog.Errorf("read login rep fail: %s", err.Error())
		return err
	}
	if buf[3] == 0 {
		glog.Errorf("login rep with 0 body")
		return fmt.Errorf("invalid login rep")
	}
	body := make([]byte, buf[3])
	if _, err := io.ReadFull(cli.pipe, body); err != nil {
		glog.Errorf("recv login rep body fail: %s", err.Error())
		return err
	}

	if buf[2] == B_TRUE {
		cli.session_id = SessionIdFromBytes(body)
		glog.Infof("login ok, sessionId: %s", cli.session_id)
	} else {
		glog.Errorf("login fail: %s", string(body))
		return fmt.Errorf("login fail")
	}

	return nil
}

func (cli *Client) Close() {
}

func (cli *Client) DoDomainProxy(domain string, port int, rw io.ReadWriteCloser) {
	cli.conn_mgr.DoProxy(PROTO_ADDR_DOMAIN, []byte(domain), port, rw)
}

func (cli *Client) DoIPProxy(addr []byte, port int, rw io.ReadWriteCloser) {
	cli.conn_mgr.DoProxy(PROTO_ADDR_IP, addr, port, rw)
}
