package main

import (
	"flag"
	"github.com/breaksocks/breaksocks/socks5"
	"github.com/breaksocks/breaksocks/tunnel"
	"github.com/golang/glog"
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

func runRedirServer(cfg *tunnel.ClientConfig, cli *tunnel.Client, exit_ch chan bool) {
	defer func() {
		exit_ch <- true
	}()

	l, err := net.Listen("tcp", cfg.RedirListenAddr)
	if err != nil {
		glog.Fatal(err)
	}

	for {
		conn, err := l.(*net.TCPListener).AcceptTCP()
		if err != nil {
			glog.Fatal(err)
			return
		}

		var addr []byte = []byte{0, 0, 0, 0}
		var port int
		if f, err := conn.File(); err == nil {
			var addr_in C.struct_sockaddr_in
			if C.getdestaddr(C.int(f.Fd()), (*C.struct_sockaddr_in)(unsafe.Pointer(&addr_in))) == 0 {
				port = int(C.ntohs(C.uint16_t(addr_in.sin_port)))
				tunnel.WriteN4(addr, 0, uint32(C.ntohl(C.uint32_t(addr_in.sin_addr.s_addr))))
			} else {
				glog.Fatal("get dest addr fail")
			}
			f.Close()
		} else {
			glog.Fatal("get conn file fail: %s", err)
		}
		glog.V(1).Infof("got cli: %v (%v, %d)", conn.LocalAddr(), addr, port)
		go cli.DoIPProxy(addr, port, conn)
	}
}

func runSocks5Server(cfg *tunnel.ClientConfig, cli *tunnel.Client, exit_ch chan bool) {
	defer func() {
		exit_ch <- true
	}()

	if ser, err := socks5.NewSocks5Server(cfg.SocksListenAddr, cli, nil); err == nil {
		ser.Run()
	} else {
		glog.Fatal("create socks5server fail: %v", err)
	}
}

func main() {
	flag.Parse()

	if cfg, err := tunnel.LoadClientConfig(*cfg_file); err != nil {
		glog.Fatal(err)
	} else if cli, err := tunnel.NewClient(cfg); err != nil {
		glog.Fatal(err)
	} else if err := cli.Init(); err != nil {
		glog.Fatal(err)
	} else {
		ch := make(chan bool)
		go runRedirServer(cfg, cli, ch)
		go runSocks5Server(cfg, cli, ch)
		<-ch
		<-ch
	}
}
