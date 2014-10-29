package utils

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"io"
	"os"
)

type ServerConfig struct {
	IP   string
	Port uint16

	GlobalEncryptMethod   string
	GlobalEncryptPassword string
	LinkEncryptMethods    []string

	UserConfigPath string
}

type ClientConfig struct {
	ServerIP   string
	ServerPort string
	LocalPort  string

	GlobalEncryptMethod   string
	GlobalEncryptPassword string
	LinkEncryptMethods    []string

	Username string
	Password string
}

func loadYamlConfig(path string, obj interface{}) error {
	if f, err := os.Open(path); err != nil {
		return err
	} else {
		fstat, err := f.Stat()
		if err != nil {
			return err
		}

		data := make([]byte, fstat.Size())
		return yaml.Unmarshal(data, obj)
	}
}

func LoadServerConfig(path string) (*ServerConfig, error) {
	cfg := new(ServerConfig)
	cfg.GlobalEncryptMethod = "3des-128"
	cfg.GlobalEncryptPassword = "passwd"
	cfg.LinkEncryptMethods = []string{"rc4", "des", "3des-128", "3des-192",
		"aes-128", "aes-192", "aes-256"}
	if err := LoadYamlConfig(path, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func LoadClientConfig(path string) (*ClientConfig, error) {
	cfg := new(ClientConfig)
	cfg.GlobalEncryptMethod = "3des-128"
	cfg.GlobalEncryptPassword = "passwd"
	cfg.LinkEncryptMethods = []string{"aes-256", "aes-192", "aes-128",
		"3des-192", "3des-128", "rc4"}
	if err := LoadYamlConfig(path, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
