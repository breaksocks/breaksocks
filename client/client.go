package client

import (
	"flag"
	"github.com/breaksocks/breaksocks/crypto"
	"github.com/breaksocks/breaksocks/protocol"
	"github.com/breaksocks/breaksocks/session"
	"github.com/breaksocks/breaksocks/utils"
	"log"
)

type Client struct {
	user   *session.Session
	config *utils.ClientConfig

	g_cipher *crypto.GlobalCipherConfig
}

func NewClient(config *utils.ClientConfig) (*Client, error) {
	cli := new(Client)
	if config.GlobalEncryptMethod != "" {
		if server.g_cipher, err = crypto.LoadGlobalCipherConfig(
			config.GlobalEncryptMethod, []byte(config.GlobalEncryptPassword)); err != nil {
			return nil, err
		}
	}

	cli.config = config
	return cli, nil
}

func (cli *Client) Init() error {

}

func (cli *Client) Close() {

}

func (cli *Client) NewPipeSock() *PipeSock {

}
