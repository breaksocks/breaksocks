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

type ClientTunnel struct {
	cli        *Client
	session_id SessionId
	session    *Session
	cipher_cfg *CipherConfig
	cipher_ctx *CipherContext

	conn *net.TCPConn
	pipe *StreamPipe

	conn_mgr *ConnManager
	write_ch chan []byte
}

func NewClientTunnel(cli *Client) *ClientTunnel {
	ct := new(ClientTunnel)
	ct.cli = cli
	ct.write_ch = make(chan []byte, 1024)
	ct.conn_mgr = NewConnManager(ct.write_ch)
	return ct
}

func (ct *ClientTunnel) Init() error {
	if conn, err := net.Dial("tcp", ct.cli.config.ServerAddr); err == nil {
		ct.conn = conn.(*net.TCPConn)
	} else {
		return err
	}
	ct.conn.SetNoDelay(true)

	ct.pipe = NewStreamPipe(ct.conn)
	if ct.cli.g_cipher != nil {
		enc, dec, err := ct.cli.g_cipher.NewCipher()
		if err != nil {
			glog.Fatalf("make global enc/dec fail: %s", err.Error())
		}
		ct.pipe.SwitchCipher(enc, dec)
	}

	if err := ct.startup(); err != nil {
		return err
	}

	if err := ct.login(); err != nil {
		return err
	}

	go func() {
		for {
			if data, ok := <-ct.write_ch; ok {
				conn_id := ReadN4(data, 4)
				if n, err := ct.pipe.Write(data); err != nil {
					glog.Fatalf("pipe write fail: %v", err)
				} else {
					glog.V(3).Infof("remote(%d) written %d", conn_id, n-8)
				}
			} else {
				break
			}
		}
	}()

	go func() {
		for {
			buf := make([]byte, 2048)
			if _, err := io.ReadFull(ct.pipe, buf[:8]); err != nil {
				glog.Errorf("read from server fail: %s", err.Error())
				break
			} else {
				if buf[0] != PROTO_MAGIC {
					glog.Errorf("invalid packet magic")
					break
				}
				pkt_size := ReadN2(buf, 2)
				if pkt_size > 2048-8 {
					glog.Errorf("invalid packet size: %s", pkt_size)
					break
				}
				conn_id := ReadN4(buf, 4)
				pkt_data := buf[8 : pkt_size+8]
				if pkt_size > 0 {
					if _, err := io.ReadFull(ct.pipe, pkt_data); err != nil {
						glog.Errorf("recv from server fail: %s", err.Error())
						break
					}
				}
				switch buf[1] {
				case PACKET_PROXY:
					glog.V(3).Infof("proxy(%d) %d", conn_id, pkt_size)
					ct.conn_mgr.WriteToLocalConn(conn_id, pkt_data)
				case PACKET_CLOSE_CONN:
					glog.V(2).Infof("remote close %d", conn_id)
					ct.conn_mgr.CloseConn(conn_id)
				}
			}
		}
	}()

	return nil
}

func (ct *ClientTunnel) startup() error {
	req_header := []byte{PROTO_MAGIC, 0, 0, 0}
	if _, err := ct.pipe.Write(req_header[:]); err != nil {
		glog.Errorf("send startup req fail: %s", err.Error())
		return err
	}

	header := make([]byte, 10)
	if _, err := io.ReadFull(ct.pipe, header[:]); err != nil {
		glog.Errorf("recv startup rep header fail: %s", err.Error())
		return err
	}

	pub_size, p_size := ReadN2(header, 0), ReadN2(header, 2)
	f_size, sig_size := ReadN2(header, 4), ReadN2(header, 6)
	mds_size := ReadN2(header, 8)
	if pub_size == 0 || p_size == 0 || f_size == 0 || sig_size == 0 || mds_size == 0 {
		return fmt.Errorf("invalid size pub:%d p:%d f:%d sig:%d mds:%d",
			pub_size, p_size, f_size, sig_size, mds_size)
	}
	body_size := pub_size + p_size + f_size + sig_size + mds_size + 1
	body := make([]byte, body_size)
	if _, err := io.ReadFull(ct.pipe, body); err != nil {
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
	ct.cipher_ctx = MakeCipherContext(new(big.Int).SetBytes(p), int(g))
	if _, err := ct.cipher_ctx.MakeE(); err != nil {
		glog.Errorf("make e fail: %s", err.Error())
		return err
	}
	ct.cipher_ctx.CalcKey(new(big.Int).SetBytes(f))

	mds := strings.Split(string(body[body_size-mds_size:]), ",")
	var method string
	for _, md_opt := range mds {
		for _, md := range ct.cli.config.LinkEncryptMethods {
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
			strings.Join(mds, ", "), strings.Join(ct.cli.config.LinkEncryptMethods, ", "))
		return fmt.Errorf("enc method not match")
	}
	ct.cipher_cfg = GetCipherConfig(method)
	if ct.cipher_cfg == nil {
		glog.Errorf("invalid cipher cfg: %s", method)
		return fmt.Errorf("get cipher fail")
	}

	e_bs := ct.cipher_ctx.EF.Bytes()
	rep := make([]byte, 4+len(e_bs)+len(method))
	WriteN2(rep, 0, uint16(len(e_bs)))
	WriteN2(rep, 2, uint16(len(method)))
	copy(rep[4:], e_bs)
	copy(rep[4+len(e_bs):], []byte(method))
	if _, err := ct.pipe.Write(rep); err != nil {
		glog.Errorf("write cipher exchange rep fail: %s", err.Error())
		return err
	}

	key, iv := ct.cipher_ctx.MakeCryptoKeyIV(ct.cipher_cfg.KeySize, ct.cipher_cfg.IVSize)
	if enc, dec, err := ct.cipher_cfg.NewCipher(key, iv); err != nil {
		glog.Errorf("new stream cipher fail: %s", err.Error())
		return err
	} else {
		ct.pipe.SwitchCipher(enc, dec)
	}

	return nil
}

func (ct *ClientTunnel) login() error {
	u, p := []byte(ct.cli.config.Username), []byte(ct.cli.config.Password)
	buf := make([]byte, 4+len(u)+len(p))
	WriteN2(buf, 0, PROTO_VERSION)
	buf[2] = byte(len(u))
	buf[3] = byte(len(p))
	copy(buf[4:], u)
	copy(buf[4+len(u):], p)
	if _, err := ct.pipe.Write(buf); err != nil {
		glog.Errorf("send login req fail: %s", err.Error())
		return err
	}

	if _, err := io.ReadFull(ct.pipe, buf[:4]); err != nil {
		glog.Errorf("read login rep fail: %s", err.Error())
		return err
	}
	if buf[3] == 0 {
		glog.Errorf("login rep with 0 body")
		return fmt.Errorf("invalid login rep")
	}
	body := make([]byte, buf[3])
	if _, err := io.ReadFull(ct.pipe, body); err != nil {
		glog.Errorf("recv login rep body fail: %s", err.Error())
		return err
	}

	if buf[2] == B_TRUE {
		ct.session_id = SessionIdFromBytes(body)
		glog.Infof("login ok, sessionId: %s", ct.session_id)
	} else {
		glog.Errorf("login fail: %s", string(body))
		return fmt.Errorf("login fail")
	}

	return nil
}
