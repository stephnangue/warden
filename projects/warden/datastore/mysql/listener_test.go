package datastore

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"vitess.io/vitess/go/mysql/collations"
	"vitess.io/vitess/go/mysql/sqlerror"
	"vitess.io/vitess/go/vt/log"
	"vitess.io/vitess/go/vt/proto/vtrpc"
	"vitess.io/vitess/go/vt/vterrors"
)

type fakeClient struct {
	conn *Conn
}

func (s *fakeClient) connect(host string, port int, user string, password string) error {

	address := net.JoinHostPort(host, fmt.Sprintf("%v", port))

	clientConn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		log.Errorf("Could not create a connection to %s: %v", address, err)
		return err
	}
	s.conn = newConn(clientConn, 0, 0)

	// Read the Handshakev10 sent by the server
	data, err := s.conn.readPacket()
	if err != nil {
		log.Errorf("initial packet read failed: %v", err)
		return err
	}

	// Parse the Handshakev10 sent by the server
	capabilities, _, err := s.conn.parseInitialHandshakePacket(data)
	if err != nil {
		log.Errorf("Fail to parse Handshake packet %v", err)
		return err
	}

	params := &ConnParams{
		Uname:            user,
		Host:             host,
		Port:             port,
		Pass:             password,
		ConnectTimeoutMs: uint64(tcpConnectionTimeOut),
	}

	// Write the Handshake Response 41
	err = s.conn.writeHandshakeResponse41(capabilities, []byte(password), uint8(0x6), params)
	if err != nil {
		log.Errorf("Fail to write Handshake response 41 %v", err)
		return err
	}

	// Read the server response.
	if err := s.conn.handleAuthResponse(params); err != nil {
		log.Errorf("Fail to handle Handshake packet %v", err)
		return err
	}

	return nil
}

func (s *fakeClient) sendQuery(query string) error {
	err := s.conn.WriteComQuery(query)
	if err != nil {
		log.Errorf("Fail to write Com Query %v", err)
		return err
	}
	return nil
}

func (s *fakeClient) sendQuit() error {
	err := s.conn.writeComQuit()
	if err != nil {
		log.Errorf("Fail to write Com Quit Command %v", err)
		return err
	}
	return nil
}

func (s *fakeClient) disconnect() {
	s.conn.endWriterBuffering()
	s.conn.Close()
}

type fakeServer struct {
	listener net.Listener
	t        *testing.T
}

func (s *fakeServer) start(t *testing.T, address string) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Errorf("Fail to create mysql server listener %v", err)
		return
	}
	s.listener = listener
	s.t = t

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			log.Errorf("Fail to accept new connection %v", err)
			return
		}
		go func() {
			handle(s.t, conn)
		}()
	}
}

// Addr returns the listener address.
func (s *fakeServer) addr() net.Addr {
	return s.listener.Addr()
}

func (s *fakeServer) stop() {
	s.listener.Close()
}

func handle(t *testing.T, conn net.Conn) {
	c := newConn(conn, 0, 0)

	_, err := c.writeHandshakeV10AskForClearPassword("8.0", uint8(0x6), false)
	if err != nil {
		if err != io.EOF {
			log.Errorf("Cannot send HandshakeV10 packet to %s: %v", c, err)
		}
		return
	}

	// Wait for the client response. This has to be a direct read,
	// so we don't buffer the TLS negotiation packets.
	response, err := c.readEphemeralPacketDirect()
	if err != nil {
		// Don't log EOF errors. They cause too much spam, same as main read loop.
		if err != io.EOF {
			log.Infof("Cannot read client handshake response from %s: %v, it may not be a valid MySQL client", c, err)
		}
		return
	}

	user, _, clientAuthResponse, err := parseClientHandshakePacketWithClearPassword(t, c, true, response)
	if err != nil {
		log.Errorf("Cannot parse client handshake response from %s: %v", c, err)
		return
	}

	c.recycleReadPacket()

	if user == "root" && string(clientAuthResponse) == "password" {
		t.Logf("User %v successfully authenticated", user)
		// Negotiation worked, send OK packet.
		if err := c.writeOKPacket(&PacketOK{}); err != nil {
			log.Errorf("Cannot write OK packet to %s: %v", c, err)
			return
		}

		for {
			c.sequence = 0
			data, err := c.ReadPacket()
			if err != nil {
				// Don't log EOF errors. They cause too much spam.
				if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
					log.Errorf("Error reading packet from %s: %v", c, err)
				}
				return
			}
			if len(data) == 0 {
				return
			}
			t.Logf("The Query is : %s", data)

			switch data[0] {
			case ComQuery:
				if err := c.writeOKPacket(&PacketOK{}); err != nil {
					log.Errorf("Cannot write OK packet to %s: %v", c, err)
					return
				}
			default:
				log.Errorf("Got unhandled packet (default) from %s, returning error: %s", c, data)
				if !c.writeErrorAndLog(sqlerror.ERUnknownComError, sqlerror.SSNetError, "command handling not implemented yet: %v", data[0]) {
					return
				}
			}
		}
	} else {
		if !c.writeErrorAndLog(sqlerror.ERUnknownComError, sqlerror.SSNetError, "could not authenticate the user %s with password %s", user, string(clientAuthResponse)) {
			return
		}
		c.recycleWritePacket()
	}

}

func parseClientHandshakePacketWithClearPassword(t *testing.T, c *Conn, firstTime bool, data []byte) (string, AuthMethodDescription, []byte, error) {
	pos := 0

	// Client flags, 4 bytes.
	clientFlags, pos, ok := readUint32(data, pos)
	if !ok {
		return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read client flags")
	}
	if clientFlags&CapabilityClientProtocol41 == 0 {
		return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: only support protocol 4.1")
	}

	// Remember a subset of the capabilities, so we can use them
	// later in the protocol. If we re-received the handshake packet
	// after SSL negotiation, do not overwrite capabilities.
	if firstTime {
		c.Capabilities = clientFlags & (CapabilityClientDeprecateEOF | CapabilityClientFoundRows)
	}

	// set connection capability for executing multi statements
	if clientFlags&CapabilityClientMultiStatements > 0 {
		c.Capabilities |= CapabilityClientMultiStatements
	}

	// Max packet size. Don't do anything with this now.
	// See doc.go for more information.
	_, pos, ok = readUint32(data, pos)
	if !ok {
		return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read maxPacketSize")
	}

	// Character set. Need to handle it.
	characterSet, pos, ok := readByte(data, pos)
	if !ok {
		return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read characterSet")
	}
	c.CharacterSet = collations.ID(characterSet)

	// 23x reserved zero bytes.
	pos += 23

	// username
	username, pos, ok := readNullString(data, pos)
	if !ok {
		return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read username")
	}

	// auth-response can have three forms.
	var authResponse []byte
	if clientFlags&CapabilityClientPluginAuthLenencClientData != 0 {
		t.Log("Enter First IF")
		var l uint64
		l, pos, ok = readLenEncInt(data, pos)
		t.Logf("Value1 %v",l)
		if !ok {
			return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read auth-response variable length")
		}
		authResponse, pos, ok = readBytesCopy(data, pos, int(l))
		t.Logf("Value2 %v",string(authResponse[:]))
		if !ok {
			return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read auth-response")
		}

	} else if clientFlags&CapabilityClientSecureConnection != 0 {
		t.Log("Enter Second IF")
		var l byte
		l, pos, ok = readByte(data, pos)
		if !ok {
			return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read auth-response length")
		}

		authResponse, pos, ok = readBytesCopy(data, pos, int(l))
		if !ok {
			return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read auth-response")
		}
	} else {
		t.Log("Enter Last IF")
		a := ""
		a, pos, ok = readNullString(data, pos)
		if !ok {
			return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read auth-response")
		}
		authResponse = []byte(a)
	}

	// db name.
	if clientFlags&CapabilityClientConnectWithDB != 0 {
		dbname := ""
		dbname, pos, ok = readNullString(data, pos)
		if !ok {
			return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read dbname")
		}
		c.schemaName = dbname
	}

	authMethod := MysqlClearPassword

	if clientFlags&CapabilityClientPluginAuth != 0 {
		var authMethodStr string
		authMethodStr, pos, ok = readNullString(data, pos)
		if !ok {
			return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read authMethod")
		}
		// The JDBC driver sometimes sends an empty string as the auth method when it wants to use mysql_native_password
		if authMethodStr != "" {
			authMethod = AuthMethodDescription(authMethodStr)
		}
	}

	// Decode connection attributes send by the client
	if clientFlags&CapabilityClientConnAttr != 0 {
		if _, _, err := parseConnAttrs(data, pos); err != nil {
			log.Warningf("Decode connection attributes send by the client: %v", err)
		}
	}

	return username, AuthMethodDescription(authMethod), authResponse, nil

}

func TestBasicSession(t *testing.T) {
	th := &testHandler{}

	l, err := NewListener("tcp", "127.0.0.1:", th, 0, 0, false, false, 0, 0)

	require.NoError(t, err)
	defer l.Close()

	host := l.Addr().(*net.TCPAddr).IP.String()
	port := l.Addr().(*net.TCPAddr).Port

	var wg sync.WaitGroup
	wg.Add(1)
	go func(l *Listener) {
		wg.Done()
		t.Log("Done executed 1")
		l.AcceptV1()
		t.Log("Exited 1")
	}(l)

	wg.Wait()

	time.Sleep(300 * time.Millisecond)

	mysqlServer := &fakeServer{}

	wg.Add(1)
	go func() {
		wg.Done()
		t.Log("Done executed 2")
		mysqlServer.start(t, "127.0.0.1:5000")
		t.Log("Exited 2")
	}()

	wg.Wait()

	time.Sleep(300 * time.Millisecond)

	mysqlClient := &fakeClient{}

	t.Log("mysqlClient connect")
	err = mysqlClient.connect(host, port, "root$127.0.0.1#5000", "password")
	require.NoError(t, err)

	err = mysqlClient.sendQuery("Select * from database")
	require.NoError(t, err)

	err = mysqlClient.sendQuit()
	require.NoError(t, err)

	time.Sleep(1 * time.Second)

	mysqlServer.stop()

	l.Shutdown()

	mysqlClient.disconnect()

}
