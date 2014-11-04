package tunnel

const (
	B_TRUE  byte = 1
	B_FALSE byte = 0

	PROTO_MAGIC   = 'P'
	PROTO_VERSION = 1

	PACKET_NEW_CONN   = 1
	PACKET_PROXY      = 2
	PACKET_CLOSE_CONN = 3

	PROTO_ADDR_IP     byte = 1
	PROTO_ADDR_DOMAIN byte = 2

	REUSE_SUCCESS                    = 0
	REUSE_FAIL_HMAC_FAIL             = 1
	REUSE_FAIL_SYS_ERR               = 2
	REUSE_FAIL_START_CIPHER_EXCHANGE = 0x10
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
