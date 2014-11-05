package tunnel

import (
	"io"
	"sync"
)

type SockChan struct {
	id   uint32
	read chan []byte
}

type ConnManager struct {
	chans      map[uint32]*SockChan
	write_ch   chan []byte
	read_pool  *BytesPool
	write_pool *BytesPool
	next_id    uint32
	lock       sync.RWMutex
}

func NewConnManager(write_ch chan []byte, read_pool, write_pool *BytesPool) *ConnManager {
	cm := new(ConnManager)
	cm.chans = make(map[uint32]*SockChan)
	cm.write_ch = write_ch
	cm.read_pool = read_pool
	cm.write_pool = write_pool
	cm.next_id = 1
	return cm
}

func (cm *ConnManager) newSockChan(rw io.ReadWriteCloser) *SockChan {
	sc := new(SockChan)
	sc.read = make(chan []byte, 64)

	cm.lock.Lock()
	defer cm.lock.Unlock()
	id := cm.next_id
	for {
		if _, ok := cm.chans[id]; !ok {
			cm.next_id += 1
			break
		}
		id += 1
		if id == 0 {
			id = 1
		}
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
	defer rw.Close()

	sc := cm.newSockChan(rw)
	req := make([]byte, 12+len(addr))
	req[0] = PROTO_MAGIC
	req[1] = PACKET_NEW_CONN
	WriteN2(req[2:], uint16(8+len(addr)))
	req[4] = conn_type
	req[5] = byte(len(addr))
	WriteN2(req[6:], uint16(port))
	WriteN4(req[8:], sc.id)
	copy(req[12:], addr)
	cm.write_ch <- req

	cm.copyConn(sc, rw)
}

func (cm *ConnManager) copyConn(sc *SockChan, rw io.ReadWriteCloser) {
	exit_ch := make(chan bool)
	go func() {
		for {
			bs := cm.write_pool.Get()
			if n, err := rw.Read(bs[8:]); err == nil {
				bs[0] = PROTO_MAGIC
				bs[1] = PACKET_PROXY
				WriteN2(bs[2:], uint16(4+n))
				WriteN4(bs[4:], sc.id)
				cm.write_ch <- bs
			} else {
				cm.write_pool.Put(bs)
				exit_ch <- true
				return
			}
		}
	}()

	for {
		exit := false

		select {
		case data, ok := <-sc.read:
			if !ok {
				// closed via cm.CloseConn
				rw.Close()
				return
			}
			pkt_size := ReadN2(data[2:])
			if _, err := rw.Write(data[8 : 8+pkt_size]); err != nil {
				exit = true
			}
			cm.read_pool.Put(data)
		case <-exit_ch:
			exit = true
		}

		if exit {
			break
		}
	}

	bs := cm.write_pool.Get()
	bs[0] = PROTO_MAGIC
	bs[1] = PACKET_CLOSE_CONN
	WriteN2(bs[2:], 4)
	WriteN4(bs[4:], sc.id)
	cm.write_ch <- bs
	cm.delSockChan(sc.id)
}
