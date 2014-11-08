package tunnel

import (
	"fmt"
	"github.com/golang/glog"
	"io"
	"net"
	"sync"
)

type ClientProxy struct {
	session *Session
	pipe    *StreamPipe
	closed  bool
	write   chan []byte
}

func NewClientProxy(session *Session, pipe *StreamPipe) *ClientProxy {
	return &ClientProxy{
		session: session,
		pipe:    pipe,
		closed:  false,
		write:   make(chan []byte)}
}

func (cp *ClientProxy) DoProxy() {
	exit_ch := make(chan bool)
	go func() {
		for {
			select {
			case data := <-cp.write:
				if n, err := cp.pipe.Write(data); err != nil {
					glog.V(1).Infof("write to client fail: %s", err.Error())
				} else {
					glog.V(2).Infof("pipe writted %d", n-8)
				}
			case <-exit_ch:
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

	conns := make(map[uint32]chan []byte)
	var lock sync.RWMutex
	defer func() {
		cp.closed = true
		lock.Lock()
		for _, ch := range conns {
			close(ch)
		}
		lock.Unlock()
		exit_ch <- true
	}()

	pipe := cp.pipe
	for {
		buf := make([]byte, 2048)
		if _, err := io.ReadFull(pipe, buf[:4]); err != nil {
			glog.V(1).Infof("recv packet fail: %s", err.Error())
			return
		} else {
			if buf[0] != PROTO_MAGIC {
				glog.V(1).Infof("invalid magic: %d", buf[0])
				return
			}
			pkt_size := ReadN2(buf[2:])
			if pkt_size > 2048-4 {
				glog.V(1).Infof("recved an invalid packet, size: %d", pkt_size)
				return
			}
			if _, err := io.ReadFull(pipe, buf[4:pkt_size+4]); err != nil {
				glog.V(1).Infof("recv packet fail: %s", err.Error())
				return
			}

			switch buf[1] {
			case PACKET_PROXY:
				conn_id := ReadN4(buf[4:])
				lock.RLock()
				ch := conns[conn_id]
				lock.RUnlock()
				if ch != nil {
					ch <- buf[8 : 4+pkt_size]
				} else {
					glog.V(1).Infof("no such conn: %d", conn_id)
				}
			case PACKET_NEW_CONN:
				port := ReadN2(buf[6:])
				conn_id := ReadN4(buf[8:])
				conn_type := buf[4]
				addr := buf[12 : 12+int(buf[5])]
				read := make(chan []byte, 32)
				lock.Lock()
				conns[conn_id] = read
				lock.Unlock()
				go func() {
					if conn, err := cp.connectRemote(conn_type, addr, port); err == nil {
						cp.copyRemote(read, conn_id, conn)
					}
					lock.Lock()
					delete(conns, conn_id)
					lock.Unlock()
				}()
			case PACKET_CLOSE_CONN:
				conn_id := ReadN4(buf[4:])
				lock.Lock()
				ch := conns[conn_id]
				if ch != nil {
					close(ch)
					delete(conns, conn_id)
				}
				lock.Unlock()
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
	copy_write_exit := make(chan bool, 1)

	go func() {
		// exit: copy_write is closed or <-copy_write_exit or cp.closed
		var data []byte
		var ok bool

		for !cp.closed {
			select {
			case data, ok = <-copy_write:
				if !ok || cp.closed {
					return
				}
			case <-copy_write_exit:
				return
			}

			select {
			case cp.write <- data:
			case <-copy_write_exit:
				return
			}
		}
	}()

	go func() {
		// exit: cp.closed or conn.Read fail
		defer func() {
			close(copy_write)
			copy_write_exit <- true
			remote_read_exit <- true
		}()

		for {
			buf := make([]byte, 2048)
			if n, err := conn.Read(buf[8:]); err == nil {
				if cp.closed {
					return
				}
				buf[0] = PROTO_MAGIC
				buf[1] = PACKET_PROXY
				WriteN2(buf[2:], uint16(n+4))
				WriteN4(buf[4:], conn_id)
				glog.V(2).Infof("remote got %d", n)
				copy_write <- buf[:8+n]
			} else {
				return
			}
		}
	}()

for_loop:
	for {
		select {
		case data, ok := <-read:
			if !ok {
				conn.Close()
				return
			}
			_, err := conn.Write(data)
			if err != nil {
				break for_loop
			}
		case <-remote_read_exit:
			break for_loop
		}
	}

	conn.Close()
	if !cp.closed {
		buf := make([]byte, 8)
		buf[0] = PROTO_MAGIC
		buf[1] = PACKET_CLOSE_CONN
		WriteN2(buf[2:], 4)
		WriteN4(buf[4:], conn_id)
		cp.write <- buf
	}
}
