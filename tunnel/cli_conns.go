package tunnel

import (
	"io"
	"sync"
)

type SockChan struct {
	id   uint32
	read *BytesChan
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
	sc.read = NewBytesChan(8, 65535, nil)

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
		sc.read.Close()
		cm.delSockChan(conn_id)
	}
}

func (cm *ConnManager) WriteToLocalConn(conn_id uint32, data []byte) {
	cm.lock.RLock()
	sc := cm.chans[conn_id]
	cm.lock.RUnlock()

	if sc != nil {
		copy(sc.read.CurBytes(), data)
		sc.read.Send(len(data))
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
	bschan := NewBytesChan(8, 1400, func(bs []byte) {
		bs[0] = PROTO_MAGIC
		bs[1] = PACKET_PROXY
		WriteN4(bs[4:], sc.id)
	})

	go func() {
		for {
			buf := bschan.CurBytes()
			if n, err := rw.Read(buf[8:]); err == nil {
				WriteN2(buf[2:], uint16(4+n))
				bschan.Send(8 + n)
			} else {
				bschan.Close()
				return
			}
		}
	}()

	for {
		exit := false
		select {
		case data, ok := <-sc.read.Chan:
			if !ok {
				// closed via cm.CloseConn
				rw.Close()
				return
			}
			if _, err := rw.Write(data); err != nil {
				exit = true
			}
		case data, ok := <-bschan.Chan:
			if !ok {
				exit = true
			} else {
				cm.write_ch <- Dump(data)
			}
		}
		if exit {
			break
		}
	}

	bs := bschan.CurBytes()
	bs[1] = PACKET_CLOSE_CONN
	WriteN2(bs[2:], 4)
	cm.write_ch <- bschan.CurBytes()[:8]
	cm.delSockChan(sc.id)
}
