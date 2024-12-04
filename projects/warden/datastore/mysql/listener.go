package datastore

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pires/go-proxyproto"
	"vitess.io/vitess/go/mysql/collations"
	"vitess.io/vitess/go/netutil"
	"vitess.io/vitess/go/tb"
	"vitess.io/vitess/go/vt/log"
	"vitess.io/vitess/go/vt/proto/vtrpc"
	"vitess.io/vitess/go/vt/vterrors"
	"vitess.io/vitess/go/vt/vttls"
)

var (
	tcpConnectionTimeOut = 30 * time.Second
)

type TLSParams struct {
	SslMode       vttls.SslMode
	SslCa         string
	SslCaPath     string
	SslCert       string
	SslCrl        string
	SslKey        string
	TLSMinVersion string
}

// Listener is the MySQL server protocol listener.
type Listener struct {
	// Construction parameters, set by NewListener.

	// handler is the data handler.
	handler Handler

	// This is the main listener socket.
	listener net.Listener

	// The following parameters are read by multiple connection go
	// routines.  They are not protected by a mutex, so they
	// should be set after NewListener, and not changed while
	// Accept is running.

	// ServerVersion is the version we will advertise.
	ServerVersion string

	// TLSConfig is the server TLS config. If set, we will advertise
	// that we support SSL.
	// atomic value stores *tls.Config
	TLSConfig atomic.Value

	// TLSParams contains the TLS params that will be injected
	// in each dsConn to establish connection with mysql backend
	TLSParams atomic.Value

	// AllowClearTextWithoutTLS needs to be set for the
	// mysql_clear_password authentication method to be accepted
	// by the server when TLS is not in use.
	AllowClearTextWithoutTLS atomic.Bool

	// SlowConnectWarnThreshold if non-zero specifies an amount of time
	// beyond which a warning is logged to identify the slow connection
	SlowConnectWarnThreshold atomic.Int64

	// The following parameters are changed by the Accept routine.

	// Incrementing ID for connection id.
	connectionID uint32

	// Read timeout on a given connection
	connReadTimeout time.Duration
	// Write timeout on a given connection
	connWriteTimeout time.Duration
	// connReadBufferSize is size of buffer for reads from underlying connection.
	// Reads are unbuffered if it's <=0.
	connReadBufferSize int

	// connBufferPooling configures if vtgate server pools connection buffers
	connBufferPooling bool

	// connKeepAlivePeriod is period between tcp keep-alives.
	connKeepAlivePeriod time.Duration

	// shutdown indicates that Shutdown method was called.
	shutdown atomic.Bool

	// RequireSecureTransport configures the server to reject connections from insecure clients
	RequireSecureTransport bool

	// PreHandleFunc is called for each incoming connection, immediately after
	// accepting a new connection. By default it's no-op. Useful for custom
	// connection inspection or TLS termination. The returned connection is
	// handled further by the MySQL handler. An non-nil error will stop
	// processing the connection by the MySQL handler.
	PreHandleFunc func(context.Context, net.Conn, uint32) (net.Conn, error)

	// flushDelay is the delay after which buffered response will be flushed to the client.
	flushDelay time.Duration

	// charset is the default server side character set to use for the connection
	charset collations.ID
	// parser to use for this listener, configured with the correct version.
	truncateErrLen int
}

// NewFromListener creates a new mysql listener from an existing net.Listener
func NewFromListener(
	l net.Listener,
	handler Handler,
	connReadTimeout time.Duration,
	connWriteTimeout time.Duration,
	connBufferPooling bool,
	keepAlivePeriod time.Duration,
	flushDelay time.Duration,
) (*Listener, error) {
	cfg := ListenerConfig{
		Listener:            l,
		Handler:             handler,
		ConnReadTimeout:     connReadTimeout,
		ConnWriteTimeout:    connWriteTimeout,
		ConnReadBufferSize:  connBufferSize,
		ConnBufferPooling:   connBufferPooling,
		ConnKeepAlivePeriod: keepAlivePeriod,
		FlushDelay:          flushDelay,
	}
	return NewListenerWithConfig(cfg)
}

// NewListener creates a new Listener.
func NewListener(
	protocol, address string,
	handler Handler,
	connReadTimeout time.Duration,
	connWriteTimeout time.Duration,
	proxyProtocol bool,
	connBufferPooling bool,
	keepAlivePeriod time.Duration,
	flushDelay time.Duration,
) (*Listener, error) {
	listener, err := net.Listen(protocol, address)
	if err != nil {
		return nil, err
	}
	if proxyProtocol {
		proxyListener := &proxyproto.Listener{Listener: listener}
		return NewFromListener(proxyListener, handler, connReadTimeout, connWriteTimeout, connBufferPooling, keepAlivePeriod, flushDelay)
	}

	return NewFromListener(listener, handler, connReadTimeout, connWriteTimeout, connBufferPooling, keepAlivePeriod, flushDelay)
}

// ListenerConfig should be used with NewListenerWithConfig to specify listener parameters.
type ListenerConfig struct {
	// Protocol-Address pair and Listener are mutually exclusive parameters
	Protocol            string
	Address             string
	Listener            net.Listener
	Handler             Handler
	ConnReadTimeout     time.Duration
	ConnWriteTimeout    time.Duration
	ConnReadBufferSize  int
	ConnBufferPooling   bool
	ConnKeepAlivePeriod time.Duration
	FlushDelay          time.Duration
}

// NewListenerWithConfig creates new listener using provided config. There are
// no default values for config, so caller should ensure its correctness.
func NewListenerWithConfig(cfg ListenerConfig) (*Listener, error) {
	var l net.Listener
	if cfg.Listener != nil {
		l = cfg.Listener
	} else {
		listener, err := net.Listen(cfg.Protocol, cfg.Address)
		if err != nil {
			return nil, err
		}
		l = listener
	}

	return &Listener{
		handler:             cfg.Handler,
		listener:            l,
		ServerVersion:       cfg.Handler.Env().MySQLVersion(),
		connectionID:        1,
		connReadTimeout:     cfg.ConnReadTimeout,
		connWriteTimeout:    cfg.ConnWriteTimeout,
		connReadBufferSize:  cfg.ConnReadBufferSize,
		connBufferPooling:   cfg.ConnBufferPooling,
		connKeepAlivePeriod: cfg.ConnKeepAlivePeriod,
		flushDelay:          cfg.FlushDelay,
		truncateErrLen:      cfg.Handler.Env().TruncateErrLen(),
		charset:             cfg.Handler.Env().CollationEnv().DefaultConnectionCharset(),
	}, nil
}

// Addr returns the listener address.
func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}

// Close stops the listener, which prevents accept of any new connections. Existing connections won't be closed.
func (l *Listener) Close() {
	l.listener.Close()
}

// Shutdown closes listener and fails any Ping requests from existing connections.
// This can be used for graceful shutdown, to let clients know that they should reconnect to another server.
func (l *Listener) Shutdown() {
	if l.shutdown.CompareAndSwap(false, true) {
		l.Close()
	}
}

// Accept runs an accept loop until the listener is closed.
func (l *Listener) Accept() {
	ctx := context.Background()

	for {
		conn, err := l.listener.Accept()
		if err != nil {
			// Close() was probably called.
			connRefuse.Add(1)
			return
		}

		acceptTime := time.Now()

		connectionID := l.connectionID
		l.connectionID++

		connCount.Add(1)
		connAccept.Add(1)

		go func() {
			if l.PreHandleFunc != nil {
				conn, err = l.PreHandleFunc(ctx, conn, connectionID)
				if err != nil {
					log.Errorf("mysql_server pre hook: %s", err)
					return
				}
			}

			l.handle(conn, connectionID, acceptTime)
		}()
	}
}

// handle is called in a go routine for each client connection.
func (l *Listener) handleV1(conn net.Conn, connectionID uint32, acceptTime time.Time) {
	if l.connReadTimeout != 0 || l.connWriteTimeout != 0 {
		conn = netutil.NewConnWithTimeouts(conn, l.connReadTimeout, l.connWriteTimeout)
	}
	c := newServerConn(conn, l)
	c.ConnectionID = connectionID

	// Adjust the count of open connections
	defer connCount.Add(-1)

	// First build and send the server handshake packet.
	_, err := c.writeHandshakeV10AskForClearPassword(l.ServerVersion, uint8(l.charset), l.TLSConfig.Load() != nil)
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
	user, _, clientAuthResponse, err := l.parseClientHandshakePacketWithClearPassword(c, true, response)
	if err != nil {
		log.Errorf("Cannot parse client handshake response from %s: %v", c, err)
		return
	}

	c.recycleReadPacket()

	if c.TLSEnabled() {
		// SSL was enabled. We need to re-read the auth packet.
		response, err = c.readEphemeralPacket()
		if err != nil {
			log.Errorf("Cannot read post-SSL client handshake response from %s: %v", c, err)
			return
		}

		// Returns copies of the data, so we can recycle the buffer.
		user, _, clientAuthResponse, err = l.parseClientHandshakePacketWithClearPassword(c, false, response)
		if err != nil {
			log.Errorf("Cannot parse post-SSL client handshake response from %s: %v", c, err)
			return
		}
		c.recycleReadPacket()

		if con, ok := c.conn.(*tls.Conn); ok {
			connState := con.ConnectionState()
			tlsVerStr := tlsVersionToString(connState.Version)
			if tlsVerStr != "" {
				connCountByTLSVer.Add(tlsVerStr, 1)
				defer connCountByTLSVer.Add(tlsVerStr, -1)
			}
		}
	} else {
		if l.RequireSecureTransport {
			c.writeErrorPacketFromError(vterrors.Errorf(vtrpc.Code_UNAVAILABLE, "server does not allow insecure connections, client must use SSL/TLS"))
			return
		}
		connCountByTLSVer.Add(versionNoTLS, 1)
		defer connCountByTLSVer.Add(versionNoTLS, -1)
	}

	// We need to send down an additional packet if we either have no negotiated method
	// at all or incomplete authentication data.
	//
	// The latter case happens for example for MySQL 8.0 clients until 8.0.25 who advertise
	// support for caching_sha2_password by default but with no plugin data.

	// TO DO SOON

	userName, targetHost, targetPort, err := getUserHostPort(user)
	if err != nil {
		log.Errorf("Error parsing username sent by mysql client for %s: %v", c, err)
		return
	}

	c.User = userName

	if c.User != "" {
		connCountPerUser.Add(c.User, 1)
		defer connCountPerUser.Add(c.User, -1)
	}

	// Connect with : user, clientAuthResponse over TLS
	params := ConnParams{
		Uname:            userName,
		Host:             targetHost,
		Port:             targetPort,
		Pass:             string(clientAuthResponse[:]),
		ConnectTimeoutMs: uint64(tcpConnectionTimeOut),
	}

	if l.TLSParams.Load() != nil {
		tlsParams := l.TLSParams.Load().(*TLSParams)
		params.SslCa = tlsParams.SslCa
		params.SslCaPath = tlsParams.SslCaPath
		params.SslCert = tlsParams.SslCert
		params.SslCrl = tlsParams.SslCrl
		params.SslKey = tlsParams.SslKey
		params.SslMode = tlsParams.SslMode
		params.TLSMinVersion = tlsParams.TLSMinVersion
	}

	dsConn, err := Connect(context.Background(), &params)
	if err != nil {
		log.Errorf("Could not create a connection mate of %s using params %s: %v", c, params, err)
		c.writeErrorPacketFromError(err)
		return
	}

	session := newSession(l, c, dsConn)
	session.uname = userName
	session.startTime = time.Now()

	// Tell the handler about the session coming and going.
	l.handler.NewSession(session)
	defer l.handler.SessionClosed(session)

	// Catch panics, and close the connection in any case.
	defer func() {
		if x := recover(); x != nil {
			log.Errorf("mysql_server caught panic:\n%v\n%s", x, tb.Stack(4))
		}

		if session == nil {
			// We call endWriterBuffering here in case there's a premature return after
			// startWriterBuffering is called
			c.endWriterBuffering()

			if l.connBufferPooling {
				c.returnReader()
			}

			conn.Close()
		} else {
			session.Close()
		}
	}()

	// Negotiation worked, send OK packet.
	if err := c.writeOKPacket(&PacketOK{}); err != nil {
		log.Errorf("Cannot write OK packet to %s: %v", c, err)
		return
	}

	// Record how long we took to establish the connection
	timings.Record(connectTimingKey, acceptTime)

	// Log a warning if it took too long to connect
	connectTime := time.Since(acceptTime).Nanoseconds()
	if threshold := l.SlowConnectWarnThreshold.Load(); threshold != 0 && connectTime > threshold {
		connSlow.Add(1)
		log.Warningf("Slow connection from %s: %v", c, connectTime)
	}

	// Tell our handler that we're finished handshake and are ready to
	// process commands.
	l.handler.SessionReady(session)

	for {
		kontinue := session.handleNextCommand()
		// before going for next command check if the session should be closed or not.
		if !kontinue || session.IsMarkedForClose() {
			return
		}
	}
}

// Accept runs an accept loop until the listener is closed.
func (l *Listener) AcceptV1() {
	ctx := context.Background()

	for {
		conn, err := l.listener.Accept()
		if err != nil {
			// Close() was probably called.
			connRefuse.Add(1)
			return
		}

		acceptTime := time.Now()

		connectionID := l.connectionID
		l.connectionID++

		connCount.Add(1)
		connAccept.Add(1)

		go func() {
			if l.PreHandleFunc != nil {
				conn, err = l.PreHandleFunc(ctx, conn, connectionID)
				if err != nil {
					log.Errorf("mysql_server pre hook: %s", err)
					return
				}
			}

			l.handleV1(conn, connectionID, acceptTime)
		}()
	}
}

// handle is called in a go routine for each client connection.
func (l *Listener) handle(conn net.Conn, connectionID uint32, acceptTime time.Time) {
	if l.connReadTimeout != 0 || l.connWriteTimeout != 0 {
		conn = netutil.NewConnWithTimeouts(conn, l.connReadTimeout, l.connWriteTimeout)
	}
	c := newServerConn(conn, l)
	c.ConnectionID = connectionID

	// Catch panics, and close the connection in any case.
	defer func() {
		if x := recover(); x != nil {
			log.Errorf("mysql_server caught panic:\n%v\n%s", x, tb.Stack(4))
		}
		// We call endWriterBuffering here in case there's a premature return after
		// startWriterBuffering is called
		c.endWriterBuffering()

		if l.connBufferPooling {
			c.returnReader()
		}

		conn.Close()
	}()

	// Tell the handler about the connection coming and going.
	l.handler.NewConnection(c)
	defer l.handler.ConnectionClosed(c)

	// Adjust the count of open connections
	defer connCount.Add(-1)

	// First build and send the server handshake packet.
	_, err := c.writeHandshakeV10(l.ServerVersion, uint8(l.charset), l.TLSConfig.Load() != nil)
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
	user, _, _, err := l.parseClientHandshakePacket(c, true, response)
	if err != nil {
		log.Errorf("Cannot parse client handshake response from %s: %v", c, err)
		return
	}

	c.recycleReadPacket()

	if c.TLSEnabled() {
		// SSL was enabled. We need to re-read the auth packet.
		response, err = c.readEphemeralPacket()
		if err != nil {
			log.Errorf("Cannot read post-SSL client handshake response from %s: %v", c, err)
			return
		}

		// Returns copies of the data, so we can recycle the buffer.
		user, _, _, err = l.parseClientHandshakePacket(c, false, response)
		if err != nil {
			log.Errorf("Cannot parse post-SSL client handshake response from %s: %v", c, err)
			return
		}
		c.recycleReadPacket()

		if con, ok := c.conn.(*tls.Conn); ok {
			connState := con.ConnectionState()
			tlsVerStr := tlsVersionToString(connState.Version)
			if tlsVerStr != "" {
				connCountByTLSVer.Add(tlsVerStr, 1)
				defer connCountByTLSVer.Add(tlsVerStr, -1)
			}
		}
	} else {
		if l.RequireSecureTransport {
			c.writeErrorPacketFromError(vterrors.Errorf(vtrpc.Code_UNAVAILABLE, "server does not allow insecure connections, client must use SSL/TLS"))
			return
		}
		connCountByTLSVer.Add(versionNoTLS, 1)
		defer connCountByTLSVer.Add(versionNoTLS, -1)
	}

	c.User = user

	if c.User != "" {
		connCountPerUser.Add(c.User, 1)
		defer connCountPerUser.Add(c.User, -1)
	}

	// Negotiation worked, send OK packet.
	if err := c.writeOKPacket(&PacketOK{statusFlags: c.StatusFlags}); err != nil {
		log.Errorf("Cannot write OK packet to %s: %v", c, err)
		return
	}

	// Record how long we took to establish the connection
	timings.Record(connectTimingKey, acceptTime)

	// Log a warning if it took too long to connect
	connectTime := time.Since(acceptTime).Nanoseconds()
	if threshold := l.SlowConnectWarnThreshold.Load(); threshold != 0 && connectTime > threshold {
		connSlow.Add(1)
		log.Warningf("Slow connection from %s: %v", c, connectTime)
	}

	// Tell our handler that we're finished handshake and are ready to
	// process commands.
	l.handler.ConnectionReady(c)

	for {
		kontinue := c.handleNextCommand(l.handler)
		// before going for next command check if the connection should be closed or not.
		if !kontinue || c.IsMarkedForClose() {
			return
		}
	}
}

// parseClientHandshakePacket parses the handshake sent by the client.
// Returns the username, auth method, auth data, error.
// The original data is not pointed at, and can be freed.
func (l *Listener) parseClientHandshakePacket(c *Conn, firstTime bool, data []byte) (string, AuthMethodDescription, []byte, error) {
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

	// Check for SSL.
	if firstTime && l.TLSConfig.Load() != nil && clientFlags&CapabilityClientSSL > 0 {
		// Need to switch to TLS, and then re-read the packet.
		conn := tls.Server(c.conn, l.TLSConfig.Load().(*tls.Config))
		c.conn = conn
		c.bufferedReader.Reset(conn)
		c.Capabilities |= CapabilityClientSSL
		return "", "", nil, nil
	}

	// username
	username, pos, ok := readNullString(data, pos)
	if !ok {
		return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read username")
	}

	// auth-response can have three forms.
	var authResponse []byte
	if clientFlags&CapabilityClientPluginAuthLenencClientData != 0 {
		var l uint64
		l, pos, ok = readLenEncInt(data, pos)
		if !ok {
			return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read auth-response variable length")
		}
		authResponse, pos, ok = readBytesCopy(data, pos, int(l))
		if !ok {
			return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read auth-response")
		}

	} else if clientFlags&CapabilityClientSecureConnection != 0 {
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

	// authMethod (with default)
	authMethod := MysqlNativePassword

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

func parseConnAttrs(data []byte, pos int) (map[string]string, int, error) {
	var attrLen uint64

	attrLen, pos, ok := readLenEncInt(data, pos)
	if !ok {
		return nil, 0, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read connection attributes variable length")
	}

	var attrLenRead uint64

	attrs := make(map[string]string)

	for attrLenRead < attrLen {
		var keyLen byte
		keyLen, pos, ok = readByte(data, pos)
		if !ok {
			return nil, 0, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read connection attribute key length")
		}
		attrLenRead += uint64(keyLen) + 1

		var connAttrKey []byte
		connAttrKey, pos, ok = readBytes(data, pos, int(keyLen))
		if !ok {
			return nil, 0, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read connection attribute key")
		}

		var valLen byte
		valLen, pos, ok = readByte(data, pos)
		if !ok {
			return nil, 0, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read connection attribute value length")
		}
		attrLenRead += uint64(valLen) + 1

		var connAttrVal []byte
		connAttrVal, pos, ok = readBytes(data, pos, int(valLen))
		if !ok {
			return nil, 0, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read connection attribute value")
		}

		attrs[string(connAttrKey[:])] = string(connAttrVal[:])
	}

	return attrs, pos, nil

}

// Whenever we move to a new version of go, we will need add any new supported TLS versions here
func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return versionTLS10
	case tls.VersionTLS11:
		return versionTLS11
	case tls.VersionTLS12:
		return versionTLS12
	case tls.VersionTLS13:
		return versionTLS13
	default:
		return versionTLSUnknown
	}
}

func (c *Conn) writeHandshakeV10AskForClearPassword(serverVersion string, charset uint8, enableTLS bool) ([]byte, error) {
	// Should fetchable from the config file
	capabilities := CapabilityClientLongPassword |
		CapabilityClientFoundRows |
		CapabilityClientLongFlag |
		CapabilityClientConnectWithDB |
		CapabilityClientProtocol41 |
		CapabilityClientTransactions |
		CapabilityClientSecureConnection |
		CapabilityClientMultiStatements |
		CapabilityClientMultiResults |
		CapabilityClientPluginAuth |
		CapabilityClientPluginAuthLenencClientData |
		CapabilityClientDeprecateEOF |
		CapabilityClientConnAttr
	if enableTLS {
		capabilities |= CapabilityClientSSL
	}

	// We need the clear password sent by the client
	// because it will be scrambled later using the
	// salt sent by the mysql server durig the handshake
	authMethod := MysqlClearPassword

	length :=
		1 + // protocol version
			lenNullString(serverVersion) +
			4 + // connection ID
			8 + // first part of plugin auth data
			1 + // filler byte
			2 + // capability flags (lower 2 bytes)
			1 + // character set
			2 + // status flag
			2 + // capability flags (upper 2 bytes)
			1 + // length of auth plugin data
			10 + // reserved (0)
			13 + // auth-plugin-data
			lenNullString(string(authMethod)) // auth-plugin-name

	data, pos := c.startEphemeralPacketWithHeader(length)

	// Protocol version.
	pos = writeByte(data, pos, protocolVersion)

	// Copy server version.
	pos = writeNullString(data, pos, serverVersion)

	// Add connectionID in.
	pos = writeUint32(data, pos, c.ConnectionID)

	// Generate the salt as the plugin data. Will be reused
	// later on if no auth method switch happens and the real
	// auth method is also mysql_native_password or caching_sha2_password.
	pluginData, err := newSalt()
	if err != nil {
		return nil, err
	}
	// Plugin data is always defined as having a trailing NULL
	pluginData = append(pluginData, 0)

	pos += copy(data[pos:], pluginData[:8])

	// One filler byte, always 0.
	pos = writeByte(data, pos, 0)

	// Lower part of the capability flags.
	pos = writeUint16(data, pos, uint16(capabilities))

	// Character set.
	pos = writeByte(data, pos, charset)

	// Status flag.
	pos = writeUint16(data, pos, c.StatusFlags)

	// Upper part of the capability flags.
	pos = writeUint16(data, pos, uint16(capabilities>>16))

	// Length of auth plugin data.
	// Always 21 (8 + 13).
	pos = writeByte(data, pos, 21)

	// Reserved 10 bytes: all 0
	pos = writeZeroes(data, pos, 10)

	// Second part of auth plugin data.
	pos += copy(data[pos:], pluginData[8:])

	// Copy authPluginName. We always start with the first
	// registered auth method name.
	pos = writeNullString(data, pos, string(authMethod))

	// Sanity check.
	if pos != len(data) {
		return nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "error building Handshake packet: got %v bytes expected %v", pos, len(data))
	}

	if err := c.writeEphemeralPacket(); err != nil {
		if strings.HasSuffix(err.Error(), "write: connection reset by peer") {
			return nil, io.EOF
		}
		if strings.HasSuffix(err.Error(), "write: broken pipe") {
			return nil, io.EOF
		}
		return nil, err
	}

	return pluginData, nil
}

func (l *Listener) parseClientHandshakePacketWithClearPassword(c *Conn, firstTime bool, data []byte) (string, AuthMethodDescription, []byte, error) {
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

	// Check for SSL.
	if firstTime && l.TLSConfig.Load() != nil && clientFlags&CapabilityClientSSL > 0 {
		// Need to switch to TLS, and then re-read the packet.
		conn := tls.Server(c.conn, l.TLSConfig.Load().(*tls.Config))
		c.conn = conn
		c.bufferedReader.Reset(conn)
		c.Capabilities |= CapabilityClientSSL
		return "", "", nil, nil
	}

	// username
	username, pos, ok := readNullString(data, pos)
	if !ok {
		return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read username")
	}

	// auth-response can have three forms.
	var authResponse []byte
	if clientFlags&CapabilityClientPluginAuthLenencClientData != 0 {
		var l uint64
		l, pos, ok = readLenEncInt(data, pos)
		if !ok {
			return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read auth-response variable length")
		}
		authResponse, pos, ok = readBytesCopy(data, pos, int(l))
		if !ok {
			return "", "", nil, vterrors.Errorf(vtrpc.Code_INTERNAL, "parseClientHandshakePacket: can't read auth-response")
		}

	} else if clientFlags&CapabilityClientSecureConnection != 0 {
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

// getUserHostPort parses the username sent by mysql client
// and extract the real username, along with the target mysql host
// and the target mysql port. username expected format : user$host#port
func getUserHostPort(username string) (string, string, int, error) {
	stringSlice := strings.Split(username, "$")
	user := stringSlice[0]
	addressSlice := strings.Split(strings.Join(stringSlice[1:], ""), "#")
	host := addressSlice[0]
	port, err := strconv.Atoi(addressSlice[1:][0])
	return user, host, port, err
}
