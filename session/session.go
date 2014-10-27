package session

import (
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"github.com/freesocks/freesocks/cipher"
	"math/big"
	"time"
)

type SessionId string

func SessionIdFromBytes(bs []byte) SessionId {
	return base64.StdEncoding.EncodeToString(bs)
}

func (sid SessionId) toBytes() ([]byte, error) {
	return base64.StdEncoding.DecodeString(sid)
}

func (sid SessionId) size() int {
	return len(sid)
}

func NewSessionId() (SessionId, error) {
	buf := make([]byte, 16)

	now := time.Now()
	if tbin, err := now.MarshalBinary(); err != nil {
		return nil, err
	} else {
		copy(buf[:12], tbin[1:13])
	}

	if _, err := rand.Read(buf[12:]); err != nil {
		return nil, err
	}

	session_bin := md5.Sum(buf)
	return SessionIdFromBytes(session_bin), nil
}

type Session struct {
	Id        SessionId
	Username  string
	CipherCtx CipherContext
}
