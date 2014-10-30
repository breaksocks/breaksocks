package session

import (
	"sync"
)

type SessionManager struct {
	lock     sync.RWMutex
	sessions map[SessionId]*Session
}

func NewSessionManager() *SessionManager {
	mgr := &SessionManager{}
	mgr.sessions = make(map[SessionId]*Session)
	return mgr
}

func (mgr *SessionManager) NewSession() (*Session, error) {
	session_id, err := NewSessionId()
	if err != nil {
		return nil, err
	}

	session := &Session{}
	session.Id = session_id

	mgr.lock.Lock()
	defer mgr.lock.Unlock()
	mgr.sessions[session_id] = session
	return session, nil
}

func (mgr *SessionManager) GetSession(sid SessionId) *Session {
	mgr.lock.RLock()
	defer mgr.lock.RUnlock()

	return mgr.sessions[sid]
}

func (mgr *SessionManager) DelSession(sid SessionId) {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	delete(mgr.sessions, sid)
}
