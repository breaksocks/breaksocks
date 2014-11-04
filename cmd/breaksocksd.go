package main

import (
	"flag"
	"github.com/breaksocks/breaksocks/tunnel"
	"github.com/golang/glog"
)

var cfg_file = flag.String("conf", "config.yaml", "config file path")

func main() {
	flag.Parse()

	if cfg, err := tunnel.LoadServerConfig(*cfg_file); err != nil {
		glog.Fatal(err)
	} else if ser, err := tunnel.NewServer(cfg); err != nil {
		glog.Fatal(err)
	} else {
		ser.Run()
	}
}
