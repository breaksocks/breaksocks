package server

import (
	"github.com/breaksocks/breaksocks/utils"
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
	new_pass := make(map[string]*UserConfig)
	if err := utils.LoadYamlConfig(cfgs.path, &new_pass); err != nil {
		return err
	}

	cfgs.users = new_pass
	return nil
}

func (cfgs *UserConfigs) Get(user string) *UserConfig {
	return cfgs.users[user]
}
