package tunnel

import (
	"github.com/golang/glog"
	"io"
	"sync"
)

type SockChan struct {
	id     uint32
	closed bool
	read   chan []byte
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
	cm.write_ch = write_ch
	cm.next_id = 1
	return cm
}

func (cm *ConnManager) newSockChan(rw io.ReadWriteCloser) *SockChan {
	sc := new(SockChan)
	sc.read = make(chan []byte, 128)

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
	sc.closed = false
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
		sc.closed = true
		close(sc.read)
		cm.delSockChan(conn_id)
	}
}

func (cm *ConnManager) CloseAllConns() {
	cm.lock.Lock()
	for _, sc := range cm.chans {
		close(sc.read)
	}
	cm.chans = make(map[uint32]*SockChan)
	cm.lock.Unlock()
}

func (cm *ConnManager) WriteToLocalConn(conn_id uint32, data []byte) {
	defer func() {
		err := recover()
		if err != nil {
			glog.V(1).Infof("write to local panic: %v", err)
		}
	}()

	cm.lock.RLock()
	sc := cm.chans[conn_id]
	cm.lock.RUnlock()

	if sc != nil {
		sc.read <- data
	} else {
		glog.V(2).Infof("write to deled sock: %d", conn_id)
	}
}

func (cm *ConnManager) DoProxy(conn_type byte, addr []byte, port int, rw io.ReadWriteCloser) {
	defer rw.Close()

	sc := cm.newSockChan(rw)
	req := make([]byte, 12+len(addr))
	req[0] = PROTO_MAGIC
	req[1] = PACKET_NEW_CONN
	WriteN2(req, 2, uint16(4+len(addr)))
	WriteN4(req, 4, sc.id)
	req[8] = conn_type
	req[9] = byte(len(addr))
	WriteN2(req, 10, uint16(port))
	copy(req[12:], addr)
	cm.write_ch <- req

	cm.copyConn(sc, rw)
}

func (cm *ConnManager) copyConn(sc *SockChan, rw io.ReadWriteCloser) {
	exit_ch := make(chan bool, 1)
	go func() {
		for {
			bs := make([]byte, 2048)
			if n, err := rw.Read(bs[8:]); err == nil {
				bs[0] = PROTO_MAGIC
				bs[1] = PACKET_PROXY
				WriteN2(bs, 2, uint16(n))
				WriteN4(bs, 4, sc.id)
				cm.write_ch <- bs[:8+n]
			} else {
				glog.V(1).Infof("read local(%d) fail: %v", sc.id, err)
				exit_ch <- true
				return
			}
		}
	}()

for_loop:
	for {
		select {
		case data, ok := <-sc.read:
			if !ok {
				// closed via cm.CloseConn
				return
			}
			if _, err := rw.Write(data); err != nil {
				glog.V(1).Infof("write local(%d) fail: %v", sc.id, err)
				break for_loop
			}
		case <-exit_ch:
			break for_loop
		}
	}

	bs := make([]byte, 8)
	bs[0] = PROTO_MAGIC
	bs[1] = PACKET_CLOSE_CONN
	WriteN2(bs, 2, 0)
	WriteN4(bs, 4, sc.id)
	cm.write_ch <- bs
	cm.CloseConn(sc.id)
	glog.V(1).Infof("local(%d) closed", sc.id)
}
