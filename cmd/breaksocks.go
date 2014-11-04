package main

import (
	"flag"
	"github.com/breaksocks/breaksocks/tunnel"
	"log"
	"net"
	"unsafe"
)

/*
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/netfilter_ipv4.h>

int getdestaddr(int fd, struct sockaddr_in *destaddr) {
    socklen_t socklen = sizeof(*destaddr);
    int error;

    error = getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, destaddr, &socklen);
    if (error) {
        return -1;
    }
    return 0;
}
*/
import "C"

var cfg_file = flag.String("conf", "config.yaml", "config file path")

func main() {
	flag.Parse()
	if cfg, err := tunnel.LoadClientConfig(*cfg_file); err != nil {
		log.Printf("%#v", err)
		log.Fatal(err)
	} else if cli, err := tunnel.NewClient(cfg); err != nil {
		log.Fatal(err)
	} else if err := cli.Init(); err != nil {
		log.Fatal(err)
	} else {
		l, err := net.Listen("tcp", cfg.RedirListenAddr)
		if err != nil {
			log.Fatal(err)
		}

		//addr := []byte{115, 239, 210, 27}
		for {
			conn, err := l.(*net.TCPListener).AcceptTCP()
			if err != nil {
				log.Fatal(err)
				return
			}

			var addr []byte = []byte{0, 0, 0, 0}
			var port int
			if f, err := conn.File(); err == nil {
				defer f.Close()

				var addr_in C.struct_sockaddr_in
				if C.getdestaddr(C.int(f.Fd()), (*C.struct_sockaddr_in)(unsafe.Pointer(&addr_in))) == 0 {
					port = int(C.ntohs(C.uint16_t(addr_in.sin_port)))
					tunnel.WriteN4(addr, uint32(C.ntohl(C.uint32_t(addr_in.sin_addr.s_addr))))
				} else {
					log.Fatal("get dest addr fail")
				}
			} else {
				log.Fatal("get conn file fail: %s", err)
			}
			log.Printf("got cli: %v (%v, %d)", conn.LocalAddr(), addr, port)
			go cli.DoIPProxy(addr, port, conn)
		}
	}
}
