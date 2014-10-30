package main

import (
	"flag"
	"github.com/breaksocks/breaksocks/server"
	"github.com/breaksocks/breaksocks/utils"
	"log"
)

var cfg_file = flag.String("conf", "config.yaml", "config file path")

func main() {
	flag.Parse()
	if cfg, err := utils.LoadServerConfig(*cfg_file); err != nil {
		log.Fatal(err)
	} else if ser, err := server.NewServer(cfg); err != nil {
		log.Fatal(err)
	} else {
		ser.Run()
	}
}
