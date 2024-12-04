package datastore

import (
	"io"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"vitess.io/vitess/go/vt/log"
)

type Session struct {
	uname string

	startTime time.Time

	uuid uuid.UUID

	listener *Listener

	// A connection between a client and a server
	svrConn *Conn

	// A connection between a server and a datastore
	dsConn *Conn

	// mu protects the fields below
	mu sync.Mutex

	closing bool
}

func newSession(listener *Listener, svrConn *Conn, dsConn *Conn) *Session {
	session := &Session{
		listener: listener,
		svrConn:  svrConn,
		dsConn:   dsConn,
	}
	u, _ := uuid.NewUUID()
	session.uuid = u
	return session
}

func (s *Session) handleNextCommand() bool {
	s.svrConn.sequence = 0
	s.dsConn.sequence = 0

	// 1 - read the SQL command sent by mysql client
	data, err := s.svrConn.readEphemeralPacket()

	if err != nil {
		// Don't log EOF errors. They cause too much spam.
		if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Errorf("Error reading packet from %s: %v", s.svrConn, err)
		}
		return false
	}
	if len(data) == 0 {
		return false
	}
	// before continue to process the packet, check if the session should be closed or not.
	if s.IsMarkedForClose() {
		return false
	}

	// 2 - transfert the SQL command to mysql server
	s.dsConn.startWriterBuffering()
	defer s.dsConn.endWriterBuffering()

	buf, pos := s.dsConn.startEphemeralPacketWithHeader(len(data))
	copy(buf[pos:], data)
	if err := s.dsConn.writeEphemeralPacket(); err != nil {
		log.Errorf("Error writing packet from %s to %s: %v", s.svrConn, s.dsConn, err)
		return false
	}
	// reading has ended, so get out of the "epheral read" state and free the ephemeral buffer
	s.svrConn.recycleReadPacket()

	// 3 - read the response from mysql server
	resp, err := s.dsConn.readEphemeralPacket()

	if err != nil {
		// Don't log EOF errors. They cause too much spam.
		if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Errorf("Error reading packet from %s: %v", s.dsConn, err)
		}
		return false
	}
	if len(resp) == 0 {
		return false
	}

	// 4 - send the response to mysql client
	s.svrConn.startWriterBuffering()
	defer s.svrConn.endWriterBuffering()

	buf, pos = s.svrConn.startEphemeralPacketWithHeader(len(resp))
	copy(buf[pos:], resp)
	if err := s.svrConn.writeEphemeralPacket(); err != nil {
		log.Errorf("Error writing packet from %s to %s: %v", s.dsConn, s.svrConn, err)
		return false
	}
	s.dsConn.recycleReadPacket()

	return true
}

func (s *Session) endWriterBuffering() {
	s.svrConn.endWriterBuffering()
	s.dsConn.endWriterBuffering()
}

func (s *Session) returnReader() {
	s.svrConn.returnReader()
	s.dsConn.returnReader()
}

func (s *Session) Close() {
	s.endWriterBuffering()
	if s.listener.connBufferPooling {
		s.returnReader()
	}
	s.svrConn.Close()
	s.dsConn.Close()
}

// MarkForClose marks the session for close.
func (s *Session) MarkForClose() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closing = true
}

// IsMarkedForClose return true if the session should be closed.
func (s *Session) IsMarkedForClose() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closing
}

func (s *Session) IsShuttingDown() bool {
	return s.listener.shutdown.Load()
}
