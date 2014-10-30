package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

func writePEMData(block_type string, der []byte, path string, mode os.FileMode) error {
	var block pem.Block
	block.Type = block_type
	block.Bytes = der
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, mode)
	if err != nil {
		return err
	}
	defer f.Close()

	return pem.Encode(f, &block)
}

func GenerateRSAKey(bits int, path string) (*rsa.PrivateKey, error) {
	pri, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	if err := writePEMData("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(pri),
		path, 0600); err != nil {
		return nil, err
	}

	if bs, err := x509.MarshalPKIXPublicKey(&pri.PublicKey); err == nil {
		if err := writePEMData("RSA PUBLIC KEY", bs, path+".pub", 0644); err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}

	return pri, nil
}

func readPEMData(path string) (*pem.Block, error) {
	if f, err := os.Open(path); err == nil {
		defer f.Close()
		stat, err := f.Stat()
		if err != nil {
			return nil, err
		}

		if stat.IsDir() {
			return nil, fmt.Errorf("%s is a directory", path)
		}

		pem_data := make([]byte, stat.Size())
		if _, err := io.ReadFull(f, pem_data); err != nil {
			return nil, err
		}

		block, _ := pem.Decode(pem_data)
		if block == nil {
			return nil, fmt.Errorf("pem decode fail")
		}
		return block, nil
	} else {
		return nil, err
	}
}

func LoadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	block, err := readPEMData(path)
	if err != nil {
		return nil, err
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func LoadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	block, err := readPEMData(path)
	if err != nil {
		return nil, err
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pub.(*rsa.PublicKey), nil
}
