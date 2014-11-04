package tunnel

import (
	"crypto/cipher"
	"fmt"
)

type GlobalCipherConfig struct {
	Config *CipherConfig
	Key    []byte
	IV     []byte
}

func LoadGlobalCipherConfig(name string, passwd []byte) (*GlobalCipherConfig, error) {
	if name == "" || passwd == nil || len(passwd) == 0 {
		return nil, fmt.Errorf("name/password can't be empty")
	}

	cfg := GetCipherConfig(name)
	if cfg == nil {
		return nil, fmt.Errorf("no such cipher: %s", name)
	}

	key, iv := MakeCryptoKeyIV(passwd, cfg.KeySize, cfg.IVSize)
	return &GlobalCipherConfig{
		Config: cfg,
		Key:    key,
		IV:     iv,
	}, nil
}

func (cfg *GlobalCipherConfig) NewCipher() (cipher.Stream, cipher.Stream, error) {
	return cfg.Config.NewCipher(cfg.Key, cfg.IV)
}
