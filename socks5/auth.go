package socks5

type SocksAuth interface {
	Check(user, passwd string) bool
}

type SimpleAuth map[string]string

func NewSimpleAuth() SimpleAuth {
	return make(SimpleAuth)
}

func (s SimpleAuth) Check(user, passwd string) bool {
	if real_pwd, ok := s[user]; ok {
		return real_pwd == passwd
	}
	return false
}
