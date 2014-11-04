package tunnel

import (
	"gopkg.in/yaml.v2"
	"io"
	"os"
)

type BytesChan struct {
	Chan  chan []byte
	bytes [][]byte
	cur   int
	n     int
}

func NewBytesChan(n, size int, init_func func([]byte)) *BytesChan {
	bs := make([][]byte, n+1)
	for i := 0; i < n+1; i += 1 {
		bs[i] = make([]byte, size)
		if init_func != nil {
			init_func(bs[i])
		}
	}

	return &BytesChan{
		Chan:  make(chan []byte, n),
		bytes: bs,
		cur:   n,
		n:     n,
	}
}

func (bc *BytesChan) CurBytes() []byte {
	return bc.bytes[bc.cur]
}

func (bc *BytesChan) Send(size int) {
	bc.Chan <- bc.bytes[bc.cur][:size]
	bc.cur += 1
	if bc.cur == bc.n+1 {
		bc.cur = 0
	}
}

func (bc *BytesChan) Close() {
	close(bc.Chan)
}

func WriteN2(bs []byte, n uint16) {
	bs[0] = byte(n >> 8)
	bs[1] = byte(n & 0xFF)
}

func ReadN2(bs []byte) uint16 {
	return (uint16(bs[0]) << 8) | uint16(bs[1])
}

func WriteN4(bs []byte, n uint32) {
	bs[0] = byte(n >> 24)
	bs[1] = byte(n >> 16)
	bs[2] = byte(n >> 8)
	bs[3] = byte(n)
}

func ReadN4(bs []byte) uint32 {
	var n uint32
	n |= uint32(bs[0]) << 24
	n |= uint32(bs[1]) << 16
	n |= uint32(bs[2]) << 8
	n |= uint32(bs[3])
	return n
}

func Dump(bs []byte) []byte {
	ret := make([]byte, len(bs))
	copy(ret, bs)
	return ret
}

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
