package tunnel

import (
	"encoding/base64"
)

type SessionId string

func SessionIdFromBytes(bs []byte) SessionId {
	return SessionId(base64.StdEncoding.EncodeToString(bs))
}

func (sid SessionId) Bytes() ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(sid))
}

func (sid SessionId) size() int {
	return len(sid)
}

type Session struct {
	Id           SessionId
	Username     string
	CipherCtx    *CipherContext
	CipherConfig *CipherConfig
}
