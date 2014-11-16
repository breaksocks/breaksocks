package tunnel

import (
	"github.com/golang/glog"
	"io"
)

type Client struct {
	user   *Session
	config *ClientConfig

	g_cipher   *GlobalCipherConfig
	cipher_cfg *CipherConfig
	cipher_ctx *CipherContext
	session_id SessionId

	//tunnels []*ClientTunnel
	tun *ClientTunnel
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
	return cli, nil
}

func (cli *Client) Init() error {
	tun := NewClientTunnel(cli)
	if err := tun.Init(); err != nil {
		return err
	}
	cli.tun = tun

	cli.session_id = tun.session_id
	cli.cipher_cfg = tun.cipher_cfg
	cli.cipher_ctx = tun.cipher_ctx

	return nil
}

func (cli *Client) Close() {
}

func (cli *Client) DoDomainProxy(domain string, port int, rw io.ReadWriteCloser) {
	cli.tun.conn_mgr.DoProxy(PROTO_ADDR_DOMAIN, []byte(domain), port, rw)
}

func (cli *Client) DoIPProxy(addr []byte, port int, rw io.ReadWriteCloser) {
	cli.tun.conn_mgr.DoProxy(PROTO_ADDR_IP, addr, port, rw)
}
