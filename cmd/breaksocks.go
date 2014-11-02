package main

import (
	"flag"
	"github.com/breaksocks/breaksocks/client"
	"github.com/breaksocks/breaksocks/utils"
	"log"
	"net"
)

var cfg_file = flag.String("conf", "config.yaml", "config file path")

func main() {
	flag.Parse()
	if cfg, err := utils.LoadClientConfig(*cfg_file); err != nil {
		log.Printf("%#v", err)
		log.Fatal(err)
	} else if cli, err := client.NewClient(cfg); err != nil {
		log.Fatal(err)
	} else if err := cli.Init(); err != nil {
		log.Fatal(err)
	} else {
		l, err := net.Listen("tcp", cfg.RedirListenAddr)
		if err != nil {
			log.Fatal(err)
		}

		addr := []byte{173, 194, 127, 41}
		for {
			conn, err := l.Accept()
			if err != nil {
				log.Fatal(err)
			}
			go cli.DoIPProxy(addr, 80, conn)
		}
	}
}
