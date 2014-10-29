package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rc4"
)

type cipherMaker interface {
	// return encrypter/ decrypter
	NewStreamCipher(key, iv []byte) (cipher.Stream, cipher.Stream, error)
}

type CipherConfig struct {
	Name    string
	KeySize int
	IVSize  int
	maker   cipherMaker
}

func (ctx *CipherConfig) NewCipher(key, iv []byte) (cipher.Stream, cipher.Stream, error) {
	return ctx.maker.NewStreamCipher(key, iv)
}

type RC4CipherMaker struct{}

func (m *RC4CipherMaker) NewStreamCipher(key, iv []byte) (cipher.Stream, cipher.Stream, error) {
	var c1, c2 cipher.Stream
	var err error

	if c1, err = rc4.NewCipher(key); err != nil {
		return nil, nil, err
	}

	if c2, err = rc4.NewCipher(key); err != nil {
		return nil, nil, err
	}

	return c1, c2, nil
}

type DESCipherMaker struct {
	is3des bool
}

func (m *DESCipherMaker) NewStreamCipher(key, iv []byte) (cipher.Stream, cipher.Stream, error) {
	var block cipher.Block
	var err error

	if m.is3des {
		if block, err = des.NewTripleDESCipher(key); err != nil {
			return nil, nil, err
		}
	} else {
		if block, err = des.NewCipher(key); err != nil {
			return nil, nil, err
		}
	}

	return cipher.NewCFBEncrypter(block, iv), cipher.NewCFBDecrypter(block, iv), nil
}

type AESCipherMaker struct{}

func (m *AESCipherMaker) NewStreamCipher(key, iv []byte) (cipher.Stream, cipher.Stream, error) {
	if block, err := aes.NewCipher(key); err != nil {
		return nil, nil, err
	} else {
		return cipher.NewCFBEncrypter(block, iv), cipher.NewCFBDecrypter(block, iv), nil
	}
}

var ciphers map[string]*CipherConfig

func init() {
	ciphers = make(map[string]*CipherConfig)
	ciphers["rc4"] = &CipherConfig{Name: "rc4", maker: new(RC4CipherMaker)}
	ciphers["des"] = &CipherConfig{
		Name:    "des",
		KeySize: 8,
		IVSize:  des.BlockSize,
		maker:   &DESCipherMaker{is3des: false}}
	ciphers["3des-128"] = &CipherConfig{
		Name:    "3des-128",
		KeySize: 16,
		IVSize:  des.BlockSize,
		maker:   &DESCipherMaker{is3des: true}}
	ciphers["3des-192"] = &CipherConfig{
		Name:    "3des-192",
		KeySize: 24,
		IVSize:  des.BlockSize,
		maker:   &DESCipherMaker{is3des: true}}
	ciphers["aes-128"] = &CipherConfig{
		Name:    "aes-128",
		KeySize: 16,
		IVSize:  aes.BlockSize,
		maker:   new(AESCipherMaker)}
	ciphers["aes-192"] = &CipherConfig{
		Name:    "aes-192",
		KeySize: 24,
		IVSize:  aes.BlockSize,
		maker:   new(AESCipherMaker)}
	ciphers["aes-256"] = &CipherConfig{
		Name:    "aes-256",
		KeySize: 32,
		IVSize:  aes.BlockSize,
		maker:   new(AESCipherMaker)}
}

func GetCipherConfig(name string) *CipherConfig {
	return ciphers[name]
}
