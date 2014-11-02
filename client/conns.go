package client

import (
	"github.com/breaksocks/breaksocks/protocol"
	"github.com/breaksocks/breaksocks/utils"
	"io"
	"sync"
)

type SockChan struct {
	id   uint32
	read chan []byte
}

func (sc *SockChan) Copy(rw io.ReadWriteCloser) {
}

type ConnManager struct {
	chans    map[uint32]*SockChan
	write_ch chan []byte
	next_id  uint32
	lock     sync.RWMutex
}

func NewConnManager(write_ch chan []byte) *ConnManager {
	cm := new(ConnManager)
	cm.chans = make(map[uint32]*SockChan)
	return cm
}

func (cm *ConnManager) newSockChan(rw io.ReadWriteCloser) *SockChan {
	sc := new(SockChan)
	sc.read = make(chan []byte)

	cm.lock.Lock()
	defer cm.lock.Unlock()
	id := cm.next_id
	for {
		if _, ok := cm.chans[id]; !ok {
			cm.next_id += 1
			break
		}
		id += 1
	}
	sc.id = id
	cm.chans[id] = sc
	return sc
}

func (cm *ConnManager) delSockChan(conn_id uint32) {
	cm.lock.Lock()
	delete(cm.chans, conn_id)
	cm.lock.Unlock()
}

func (cm *ConnManager) CloseConn(conn_id uint32) {
	cm.lock.RLock()
	sc := cm.chans[conn_id]
	cm.lock.RUnlock()

	if sc != nil {
		close(sc.read)
		cm.delSockChan(conn_id)
	}
}

func (cm *ConnManager) WriteToLocalConn(conn_id uint32, data []byte) {
	cm.lock.RLock()
	sc := cm.chans[conn_id]
	cm.lock.RUnlock()

	if sc != nil {
		sc.read <- data
	}
}

func (cm *ConnManager) DoProxy(conn_type byte, addr []byte, port int, rw io.ReadWriteCloser) {
	sc := cm.newSockChan(rw)
	req := make([]byte, 12+len(addr))
	req[0] = protocol.PROTO_MAGIC
	req[1] = protocol.PACKET_NEW_CONN
	utils.WriteN2(req[2:], uint16(8+len(addr)))
	req[4] = conn_type
	req[5] = byte(len(addr))
	utils.WriteN2(req[6:], uint16(port))
	utils.WriteN4(req[8:], sc.id)
	copy(req[12:], addr)
	cm.write_ch <- req

	cm.copyConn(sc, rw)
}

func (cm *ConnManager) copyConn(sc *SockChan, rw io.ReadWriteCloser) {
	bs := make([]byte, 65535)
	bs[0] = protocol.PROTO_MAGIC
	bs[1] = protocol.PACKET_PROXY
	utils.WriteN4(bs[4:], sc.id)
	ch := make(chan int)

	go func() {
		buf := bs[8:]
		for {
			if n, err := rw.Read(buf); err == nil {
				ch <- n
			} else {
				close(ch)
				return
			}
		}
	}()

	for {
		select {
		case data, ok := <-sc.read:
			if !ok {
				// closed via cm.CloseConn
				rw.Close()
				return
			}
			if _, err := rw.Write(data); err != nil {
				break
			}
		case size, ok := <-ch:
			if !ok {
				break
			}
			utils.WriteN2(bs[2:], uint16(4+size))
			cm.write_ch <- bs[:8+size]
		}
	}

	bs[1] = protocol.PACKET_CLOSE_CONN
	utils.WriteN2(bs[2:], 4)
	cm.write_ch <- bs[:8]
	rw.Close()
	cm.delSockChan(sc.id)
}
