package datastore

import (
	"crypto/rand"
	"io"
	"strings"

	"vitess.io/vitess/go/stats"
	"vitess.io/vitess/go/vt/proto/vtrpc"
	"vitess.io/vitess/go/vt/vterrors"
)

const (
	// DefaultServerVersion is the default server version we're sending to the client.
	// Can be changed.

	// timing metric keys
	connectTimingKey  = "Connect"
	queryTimingKey    = "Query"
	versionTLS10      = "TLS10"
	versionTLS11      = "TLS11"
	versionTLS12      = "TLS12"
	versionTLS13      = "TLS13"
	versionTLSUnknown = "UnknownTLSVersion"
	versionNoTLS      = "None"
)

var (
	// Metrics
	timings    = stats.NewTimings("MysqlServerTimings", "MySQL server timings", "operation")
	connCount  = stats.NewGauge("MysqlServerConnCount", "Active MySQL server connections")
	connAccept = stats.NewCounter("MysqlServerConnAccepted", "Connections accepted by MySQL server")
	connRefuse = stats.NewCounter("MysqlServerConnRefused", "Connections refused by MySQL server")
	connSlow   = stats.NewCounter("MysqlServerConnSlow", "Connections that took more than the configured mysql_slow_connect_warn_threshold to establish")

	connCountByTLSVer = stats.NewGaugesWithSingleLabel("MysqlServerConnCountByTLSVer", "Active MySQL server connections by TLS version", "tls")
	connCountPerUser  = stats.NewGaugesWithSingleLabel("MysqlServerConnCountPerUser", "Active MySQL server connections per user", "count")
	_                 = stats.NewGaugeFunc("MysqlServerConnCountUnauthenticated", "Active MySQL server connections that haven't authenticated yet", func() int64 {
		totalUsers := int64(0)
		for _, v := range connCountPerUser.Counts() {
			totalUsers += v
		}
		return connCount.Get() - totalUsers
	})
)

func newSalt() ([]byte, error) {
	salt := make([]byte, 20)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	// Salt must be a legal UTF8 string.
	for i := range len(salt) {
		salt[i] &= 0x7f
		if salt[i] == '\x00' || salt[i] == '$' {
			salt[i]++
		}
	}

	return salt, nil
}

// writeHandshakeV10 writes the Initial Handshake Packet, server side.
// It returns the salt data.
func (c *Conn) writeHandshakeV10(serverVersion string, charset uint8, enableTLS bool) ([]byte, error) {
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

	// Should fetchable from the config file
	// This can only be either mysql_native_password or caching_sha2_password
	authMethod := MysqlNativePassword

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
