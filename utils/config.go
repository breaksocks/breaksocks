package utils

import (
	"gopkg.in/yaml.v2"
	"io"
	"os"
)

const defaultKeyPath = "rsa_key"
const defaultUserConfigPath = "users"

type ServerConfig struct {
	ListenAddr            string
	GlobalEncryptMethod   string
	GlobalEncryptPassword string
	LinkEncryptMethods    []string

	UserConfigPath string
	KeyPath        string
}

type ClientConfig struct {
	ServerAddr      string
	SocksListenAddr string
	RedirListenAddr string

	GlobalEncryptMethod   string
	GlobalEncryptPassword string
	LinkEncryptMethods    []string
	ServerPublicKeyPath   string

	Username string
	Password string
}

func LoadYamlConfig(path string, obj interface{}) error {
	if f, err := os.Open(path); err != nil {
		return err
	} else {
		fstat, err := f.Stat()
		if err != nil {
			return err
		}

		data := make([]byte, fstat.Size())
		if _, err := io.ReadFull(f, data); err != nil {
			return err
		}
		return yaml.Unmarshal(data, obj)
	}
}

func LoadServerConfig(path string) (*ServerConfig, error) {
	cfg := new(ServerConfig)
	cfg.ListenAddr = "0.0.0.0:8989"
	cfg.GlobalEncryptMethod = "3des-192"
	cfg.GlobalEncryptPassword = "passwd"
	cfg.LinkEncryptMethods = []string{"aes-256", "aes-192", "aes-128",
		"3des-192", "rc4"}
	cfg.KeyPath = defaultKeyPath
	cfg.UserConfigPath = defaultUserConfigPath
	if err := LoadYamlConfig(path, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func LoadClientConfig(path string) (*ClientConfig, error) {
	cfg := new(ClientConfig)
	cfg.SocksListenAddr = "127.0.0.1:1080"
	cfg.GlobalEncryptMethod = "3des-192"
	cfg.GlobalEncryptPassword = "passwd"
	cfg.LinkEncryptMethods = []string{"aes-256", "aes-192", "aes-128",
		"3des-192", "rc4"}
	if err := LoadYamlConfig(path, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
