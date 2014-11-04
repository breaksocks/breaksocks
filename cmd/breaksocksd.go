package main

import (
	"flag"
	"github.com/breaksocks/breaksocks/tunnel"
	"log"
)

var cfg_file = flag.String("conf", "config.yaml", "config file path")

func main() {
	flag.Parse()
	if cfg, err := tunnel.LoadServerConfig(*cfg_file); err != nil {
		log.Fatal(err)
	} else if ser, err := tunnel.NewServer(cfg); err != nil {
		log.Fatal(err)
	} else {
		ser.Run()
	}
}
