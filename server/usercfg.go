package server

import (
	"github.com/breaksocks/breaksocks/session"
	"github.com/breaksocks/breaksocks/utils"
	"gopkg.in/yaml.v2"
)

type UserConfig struct {
	Password string
}

type UserConfigs struct {
	path  string
	users map[string]*UserConfig
}

func GetUserConfigs(path string) (*UserConfigs, error) {
	cfgs := new(UserConfigs)
	cfgs.path = path
	if err := cfgs.Reload(); err != nil {
		return nil, err
	}
	return cfgs, nil
}

func (cfgs *UserConfigs) Reload() error {
	new_pass := make(map[string]*UserPasswd)
	if err := utils.LoadYamlConfig(cfgs.path, &new_pass); err != nil {
		return err
	}

	cfgs.users = new_pass
}

func (cfgs *UserConfigs) Get(user string) *UserConfigs {
	return cfgs.users[user]
}
