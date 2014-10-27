package protocol

const (
	B_TRUE  = 1
	B_FALSE = 0

	PROTO_MAGIC   = 'P'
	PROTO_VERSION = 1

	PACKET_NEW_CONN   = 1
	PACKET_PROXY      = 2
	PACKET_CLOSE_CONN = 3
)

type ReuseSession struct {
	SessionId string
	RandMsg   []byte
	HMACData  []byte
}

type CipherExchangeInit struct {
	PublickKey []byte
	P          []byte
	G          uint8
	F          []byte
	Signature  []byte
}

type LoginRequest struct {
	Magic         uint8
	ClientVersion uint8
	Username      string
	Password      string
}

type LoginResponse struct {
	Magic         uint8
	ServerVersion uint8
	LoginOk       bool
	SessionId     string
}
