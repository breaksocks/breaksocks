package tunnel

import (
	"fmt"
	"github.com/golang/glog"
	"io"
	"net"
	"sync"
)

type proxyConn struct {
	read chan []byte
}

type ClientProxy struct {
	session *Session
	pipe    *StreamPipe
	closed  bool
	write   chan []byte

	lock  sync.RWMutex
	conns map[uint32]*proxyConn
}

func NewClientProxy(session *Session, pipe *StreamPipe) *ClientProxy {
	return &ClientProxy{
		session: session,
		pipe:    pipe,
		closed:  false,
		write:   make(chan []byte),
		conns:   make(map[uint32]*proxyConn)}
}

func (cp *ClientProxy) newConn(conn_id uint32) *proxyConn {
	pconn := &proxyConn{read: make(chan []byte, 64)}
	cp.lock.Lock()
	cp.conns[conn_id] = pconn
	cp.lock.Unlock()
	return pconn
}

func (cp *ClientProxy) closeConn(conn_id uint32, pconn *proxyConn) {
	cp.lock.Lock()
	pconn, ok := cp.conns[conn_id]
	if ok {
		close(pconn.read)
		delete(cp.conns, conn_id)
	}
	cp.lock.Unlock()
}

func (cp *ClientProxy) sendToConn(conn_id uint32, data []byte) {
	defer func() {
		if err := recover(); err != nil {
			glog.V(1).Infof("sendToConn panic: %v", err)
		}
	}()

	cp.lock.RLock()
	pconn, ok := cp.conns[conn_id]
	cp.lock.RUnlock()
	if ok {
		pconn.read <- data
	} else {
		glog.V(1).Infof("no such conn: %d", conn_id)
	}
}

func (cp *ClientProxy) closeAllConns() {
	cp.lock.Lock()
	for _, pconn := range cp.conns {
		close(pconn.read)
	}
	cp.conns = make(map[uint32]*proxyConn)
	cp.lock.Unlock()
}

func (cp *ClientProxy) DoProxy() {
	send_to_client_exit := make(chan bool)
	go func() {
		for {
			select {
			case data := <-cp.write:
				if !cp.closed {
					conn_id := ReadN4(data, 4)
					if n, err := cp.pipe.Write(data); err != nil {
						glog.V(1).Infof("write to client fail: %s", err.Error())
					} else {
						glog.V(3).Infof("pipe(%d) writted %d", conn_id, n-8)
					}
				}
			case <-send_to_client_exit:
				// clear write queue
				for {
					select {
					case <-cp.write:
					default:
						return
					}
				}
			}
		}
	}()

	defer func() {
		cp.closed = true
		cp.closeAllConns()
		send_to_client_exit <- true
	}()

	pipe := cp.pipe
	for {
		buf := make([]byte, 2048)
		if _, err := io.ReadFull(pipe, buf[:8]); err != nil {
			glog.V(1).Infof("recv packet fail: %s", err.Error())
			return
		} else {
			if buf[0] != PROTO_MAGIC {
				glog.V(1).Infof("invalid magic: %d", buf[0])
				return
			}
			pkt_size := ReadN2(buf, 2)
			if pkt_size > 2048-8 {
				glog.V(1).Infof("recved an invalid packet, size: %d", pkt_size)
				return
			}
			conn_id := ReadN4(buf, 4)
			pkt_data := buf[8 : pkt_size+8]
			if pkt_size > 0 {
				if _, err := io.ReadFull(pipe, pkt_data); err != nil {
					glog.V(1).Infof("recv packet fail: %s", err.Error())
					return
				}
			}

			switch buf[1] {
			case PACKET_PROXY:
				cp.sendToConn(conn_id, pkt_data)
			case PACKET_NEW_CONN:
				conn_type := pkt_data[0]
				//addr_size := int(pkt_data[1])
				port := ReadN2(pkt_data, 2)
				addr := pkt_data[4:]
				pconn := cp.newConn(conn_id)
				go func() {
					if conn, err := cp.connectRemote(conn_type, addr, port); err == nil {
						cp.copyRemote(pconn.read, conn_id, conn)
					}
					cp.closeConn(conn_id, pconn)
				}()
			case PACKET_CLOSE_CONN:
				cp.closeConn(conn_id, nil)
			}
		}
	}
}

func (cp *ClientProxy) connectRemote(conn_type byte, addr []byte, port uint16) (*net.TCPConn, error) {
	var rconn *net.TCPConn

	if conn_type == PROTO_ADDR_IP {
		var remote_addr net.TCPAddr
		remote_addr.IP = net.IP(addr)
		remote_addr.Port = int(port)
		if conn, err := net.DialTCP("tcp", nil, &remote_addr); err == nil {
			rconn = conn
		} else {
			glog.V(1).Infof("conn %#v fail: %s", remote_addr, err.Error())
			return nil, err
		}
	} else {
		raddr := net.JoinHostPort(string(addr), fmt.Sprintf("%d", port))
		if conn, err := net.Dial("tcp", raddr); err == nil {
			rconn = conn.(*net.TCPConn)
		} else {
			glog.V(1).Infof("conn %#v fail: %s", raddr, err.Error())
			return nil, err
		}
	}

	return rconn, nil
}

func (cp *ClientProxy) copyRemote(read chan []byte, conn_id uint32, conn *net.TCPConn) {
	remote_read_exit := make(chan bool, 1)
	copy_write := make(chan []byte, 512)
	closed_by_client := false

	// remote chan -> client
	go func() {
		// exit: copy_write is closed or nil == <-copy_write or cp.closed
		for !cp.closed {
			data, ok := <-copy_write
			if !ok || cp.closed {
				break
			}
			cp.write <- data
		}

		if !cp.closed && !closed_by_client {
			buf := make([]byte, 8)
			buf[0] = PROTO_MAGIC
			buf[1] = PACKET_CLOSE_CONN
			WriteN2(buf, 2, 0)
			WriteN4(buf, 4, conn_id)
			cp.write <- buf
		}
	}()

	// remote -> remote chan
	go func() {
		// exit: cp.closed or conn.Read fail
		for {
			buf := make([]byte, 2048)
			if n, err := conn.Read(buf[8:]); err == nil {
				if cp.closed {
					break
				}
				buf[0] = PROTO_MAGIC
				buf[1] = PACKET_PROXY
				WriteN2(buf, 2, uint16(n))
				WriteN4(buf, 4, conn_id)
				copy_write <- buf[:8+n]
			} else {
				glog.V(3).Infof("remote(%d) read fail: %v", conn_id, err)
				break
			}
		}

		close(copy_write)
		remote_read_exit <- true
	}()

	defer conn.Close()
	// client -> remote
	for {
		select {
		case data, ok := <-read:
			if !ok {
				closed_by_client = true
				return
			}
			if n, err := conn.Write(data); err != nil {
				glog.V(3).Infof("remote(%d) write fail: %v", conn_id, err)
				return
			} else {
				glog.V(3).Infof("remote(%d) sent %d", conn_id, n)
			}
		case <-remote_read_exit:
			return
		}
	}
}
