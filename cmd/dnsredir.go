package main

import (
	"flag"
	"github.com/breaksocks/breaksocks/tunnel"
	"github.com/golang/glog"
	"github.com/miekg/dns"
	"net"
	"strconv"
)

func runDNSServer(cfg *tunnel.ClientConfig, cli *tunnel.Client, exit_ch chan bool) {
	if cfg.DNSListenAddr == "" {
		return
	}

	var host, port_s string
	var port int
	var err error
	if host, port_s, err = net.SplitHostPort(cfg.DNSRemoteAddr); err != nil {
		glog.Fatalf("invalid dns remote addr: %s", cfg.DNSRemoteAddr)
	}
	if port_n, err := strconv.ParseInt(port_s, 10, 16); err != nil {
		glog.Fatalf("invalid dns remote addr: %s", cfg.DNSRemoteAddr)
	} else {
		port = int(port_n)
	}

	var dnsLocalAddr net.Addr
	if listener, err := net.Listen("tcp", "127.0.0.1:0"); err != nil {
		glog.Fatalf("listen dns redirecter fail: %v", err)
	} else {
		dnsLocalAddr = listener.Addr()
		go func() {
			for {
				if conn, err := listener.Accept(); err == nil {
					go cli.DoDomainProxy(host, port, conn)
				} else {
					glog.Fatalf("dns redir accept fail: %v", err)
				}
			}
		}()
	}

	var lnet string = "udp"
	if cfg.DNSListenOnTCP {
		lnet = "tcp"
	}

	err = dns.ListenAndServe(cfg.DNSListenAddr, lnet, dns.HandlerFunc(
		func(w dns.ResponseWriter, msg *dns.Msg) {
			cli := new(dns.Client)
			cli.Net = "tcp"
			if retmsg, _, err := cli.Exchange(msg, dnsLocalAddr.String()); err == nil {
				w.WriteMsg(retmsg)
			} else {
				dns.HandleFailed(w, retmsg)
			}
		}))
	if err != nil {
		glog.Fatalf("serve DNS fail: %v", err)
	}
}

var cfg_file = flag.String("conf", "config.yaml", "config file path")

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
		go runDNSServer(cfg, cli, ch)
		<-ch
	}
}
