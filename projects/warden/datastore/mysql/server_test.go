package datastore

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"vitess.io/vitess/go/mysql/collations"
	"vitess.io/vitess/go/sqltypes"
	"vitess.io/vitess/go/test/utils"
	venv "vitess.io/vitess/go/vt/env"
	"vitess.io/vitess/go/vt/vtenv"

	querypb "vitess.io/vitess/go/vt/proto/query"
)

var selectRowsResult = &sqltypes.Result{
	Fields: []*querypb.Field{
		{
			Name:    "id",
			Type:    querypb.Type_INT32,
			Charset: collations.CollationBinaryID,
			Flags:   uint32(querypb.MySqlFlag_NUM_FLAG),
		},
		{
			Name:    "name",
			Type:    querypb.Type_VARCHAR,
			Charset: uint32(collations.CollationUtf8mb4ID),
		},
	},
	Rows: [][]sqltypes.Value{
		{
			sqltypes.MakeTrusted(querypb.Type_INT32, []byte("10")),
			sqltypes.MakeTrusted(querypb.Type_VARCHAR, []byte("nice name")),
		},
		{
			sqltypes.MakeTrusted(querypb.Type_INT32, []byte("20")),
			sqltypes.MakeTrusted(querypb.Type_VARCHAR, []byte("nicer name")),
		},
	},
}

type testHandler struct {
	UnimplementedHandler
	mu       sync.Mutex
	lastConn *Conn
	result   *sqltypes.Result
	err      error
	warnings uint16
}

func (th *testHandler) LastConn() *Conn {
	th.mu.Lock()
	defer th.mu.Unlock()
	return th.lastConn
}

func (th *testHandler) Result() *sqltypes.Result {
	th.mu.Lock()
	defer th.mu.Unlock()
	return th.result
}

func (th *testHandler) SetErr(err error) {
	th.mu.Lock()
	defer th.mu.Unlock()
	th.err = err
}

func (th *testHandler) Err() error {
	th.mu.Lock()
	defer th.mu.Unlock()
	return th.err
}

func (th *testHandler) SetWarnings(count uint16) {
	th.mu.Lock()
	defer th.mu.Unlock()
	th.warnings = count
}

func (th *testHandler) NewConnection(c *Conn) {
	th.mu.Lock()
	defer th.mu.Unlock()
	th.lastConn = c
}

const benchmarkQueryPrefix = "benchmark "

func (th *testHandler) ComQuery(c *Conn, query string, callback func(*sqltypes.Result) error) error {
	if result := th.Result(); result != nil {
		callback(result)
		return nil
	}

	switch query {
	case "error":
		return th.Err()
	case "panic":
		panic("test panic attack!")
	case "select rows":
		callback(selectRowsResult)
	case "error after send":
		callback(selectRowsResult)
		return th.Err()
	case "insert":
		callback(&sqltypes.Result{
			RowsAffected: 123,
			InsertID:     123456789,
		})
	case "schema echo":
		callback(&sqltypes.Result{
			Fields: []*querypb.Field{
				{
					Name:    "schema_name",
					Type:    querypb.Type_VARCHAR,
					Charset: uint32(collations.MySQL8().DefaultConnectionCharset()),
				},
			},
			Rows: [][]sqltypes.Value{
				{
					sqltypes.MakeTrusted(querypb.Type_VARCHAR, []byte(c.schemaName)),
				},
			},
		})
	case "ssl echo":
		value := "OFF"
		if c.Capabilities&CapabilityClientSSL > 0 {
			value = "ON"
		}
		callback(&sqltypes.Result{
			Fields: []*querypb.Field{
				{
					Name:    "ssl_flag",
					Type:    querypb.Type_VARCHAR,
					Charset: uint32(collations.MySQL8().DefaultConnectionCharset()),
				},
			},
			Rows: [][]sqltypes.Value{
				{
					sqltypes.MakeTrusted(querypb.Type_VARCHAR, []byte(value)),
				},
			},
		})
	case "userData echo":
		callback(&sqltypes.Result{
			Fields: []*querypb.Field{
				{
					Name:    "user",
					Type:    querypb.Type_VARCHAR,
					Charset: uint32(collations.MySQL8().DefaultConnectionCharset()),
				},
				{
					Name:    "user_data",
					Type:    querypb.Type_VARCHAR,
					Charset: uint32(collations.MySQL8().DefaultConnectionCharset()),
				},
			},
			Rows: [][]sqltypes.Value{
				{
					sqltypes.MakeTrusted(querypb.Type_VARCHAR, []byte(c.User)),
				},
			},
		})
	case "50ms delay":
		callback(&sqltypes.Result{
			Fields: []*querypb.Field{{
				Name:    "result",
				Type:    querypb.Type_VARCHAR,
				Charset: uint32(collations.MySQL8().DefaultConnectionCharset()),
			}},
		})
		time.Sleep(50 * time.Millisecond)
		callback(&sqltypes.Result{
			Rows: [][]sqltypes.Value{{
				sqltypes.MakeTrusted(querypb.Type_VARCHAR, []byte("delayed")),
			}},
		})
	default:
		if strings.HasPrefix(query, benchmarkQueryPrefix) {
			callback(&sqltypes.Result{
				Fields: []*querypb.Field{
					{
						Name:    "result",
						Type:    querypb.Type_VARCHAR,
						Charset: uint32(collations.MySQL8().DefaultConnectionCharset()),
					},
				},
				Rows: [][]sqltypes.Value{
					{
						sqltypes.MakeTrusted(querypb.Type_VARCHAR, []byte(query)),
					},
				},
			})
		}

		callback(&sqltypes.Result{})
	}
	return nil
}

func (th *testHandler) WarningCount(c *Conn) uint16 {
	th.mu.Lock()
	defer th.mu.Unlock()
	return th.warnings
}

func (th *testHandler) Env() *vtenv.Environment {
	return vtenv.NewTestEnv()
}

func getHostPort(t *testing.T, a net.Addr) (string, int) {
	host := a.(*net.TCPAddr).IP.String()
	port := a.(*net.TCPAddr).Port
	t.Logf("listening on address '%v' port %v", host, port)
	return host, port
}

func TestConnectionFromListener(t *testing.T) {
	ctx := utils.LeakCheckContext(t)
	th := &testHandler{}
	// Make sure we can create our own net.Listener for use with the mysql
	// listener
	listener, err := net.Listen("tcp", "127.0.0.1:")
	require.NoError(t, err, "net.Listener failed")

	l, err := NewFromListener(listener, th, 0, 0, false, 0, 0)
	require.NoError(t, err, "NewListener failed")
	host, port := getHostPort(t, l.Addr())
	fmt.Printf("host: %s, port: %d\n", host, port)
	// Setup the right parameters.
	params := &ConnParams{
		Host:  host,
		Port:  port,
		Uname: "user123",
		Pass:  "password1",
	}
	go l.Accept()
	defer cleanupListener(ctx, l, params)

	c, err := Connect(ctx, params)
	require.NoError(t, err, "Should be able to connect to server")
	c.Close()
}

func TestConnectionWithoutSourceHost(t *testing.T) {
	ctx := utils.LeakCheckContext(t)
	th := &testHandler{}

	l, err := NewListener("tcp", "127.0.0.1:", th, 0, 0, false, false, 0, 0)
	require.NoError(t, err, "NewListener failed")
	host, port := getHostPort(t, l.Addr())
	// Setup the right parameters.
	params := &ConnParams{
		Host:  host,
		Port:  port,
		Uname: "user1",
		Pass:  "password1",
	}
	go l.Accept()
	defer cleanupListener(ctx, l, params)

	c, err := Connect(ctx, params)
	require.NoError(t, err, "Should be able to connect to server")
	c.Close()
}

func TestClientFoundRows(t *testing.T) {
	ctx := utils.LeakCheckContext(t)
	th := &testHandler{}

	l, err := NewListener("tcp", "127.0.0.1:", th, 0, 0, false, false, 0, 0)
	require.NoError(t, err, "NewListener failed")
	host, port := getHostPort(t, l.Addr())
	// Setup the right parameters.
	params := &ConnParams{
		Host:  host,
		Port:  port,
		Uname: "user1",
		Pass:  "password1",
	}
	go l.Accept()
	defer cleanupListener(ctx, l, params)

	// Test without flag.
	c, err := Connect(ctx, params)
	require.NoError(t, err, "Connect failed")
	foundRows := th.LastConn().Capabilities & CapabilityClientFoundRows
	assert.Equal(t, uint32(0), foundRows, "FoundRows flag: %x, second bit must be 0", th.LastConn().Capabilities)
	c.Close()
	assert.True(t, c.IsClosed(), "IsClosed should be true on Close-d connection.")

	// Test with flag.
	params.Flags |= CapabilityClientFoundRows
	c, err = Connect(ctx, params)
	require.NoError(t, err, "Connect failed")
	foundRows = th.LastConn().Capabilities & CapabilityClientFoundRows
	assert.NotZero(t, foundRows, "FoundRows flag: %x, second bit must be set", th.LastConn().Capabilities)
	c.Close()
}

func TestConnCounts(t *testing.T) {
	ctx := utils.LeakCheckContext(t)
	th := &testHandler{}

	user := "anotherNotYetConnectedUser1"
	passwd := "password1"

	l, err := NewListener("tcp", "127.0.0.1:", th, 0, 0, false, false, 0, 0)
	require.NoError(t, err, "NewListener failed")
	host, port := getHostPort(t, l.Addr())
	// Test with one new connection.
	params := &ConnParams{
		Host:  host,
		Port:  port,
		Uname: user,
		Pass:  passwd,
	}
	go l.Accept()
	defer cleanupListener(ctx, l, params)

	c, err := Connect(ctx, params)
	require.NoError(t, err, "Connect failed")

	checkCountsForUser(t, user, 1)

	// Test with a second new connection.
	c2, err := Connect(ctx, params)
	require.NoError(t, err)
	checkCountsForUser(t, user, 2)

	// Test after closing connections.
	c.Close()
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		checkCountsForUser(t, user, 1)
	}, 1*time.Second, 10*time.Millisecond)

	c2.Close()
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		checkCountsForUser(t, user, 0)
	}, 1*time.Second, 10*time.Millisecond)
}

func checkCountsForUser(t assert.TestingT, user string, expected int64) {
	connCounts := connCountPerUser.Counts()

	userCount, ok := connCounts[user]
	assert.True(t, ok, "No count found for user %s", user)
	assert.Equal(t, expected, userCount)
}

const enableCleartextPluginPrefix = "enable-cleartext-plugin: "

// runMysql forks a mysql command line process connecting to the provided server.
func runMysql(t *testing.T, params *ConnParams, command string) (string, bool) {
	output, err := runMysqlWithErr(t, params, command)
	if err != nil {
		return output, false
	}
	return output, true

}

func runMysqlWithErr(t *testing.T, params *ConnParams, command string) (string, error) {
	dir, err := venv.VtMysqlRoot()
	require.NoError(t, err)
	name, err := binaryPath(dir, "mysql")
	require.NoError(t, err)
	// The args contain '-v' 3 times, to switch to very verbose output.
	// In particular, it has the message:
	// Query OK, 1 row affected (0.00 sec)
	args := []string{
		"-v", "-v", "-v",
	}
	if strings.HasPrefix(command, enableCleartextPluginPrefix) {
		command = command[len(enableCleartextPluginPrefix):]
		args = append(args, "--enable-cleartext-plugin")
	}
	if command == "--version" {
		args = append(args, command)
	} else {
		args = append(args, "-e", command)
		if params.UnixSocket != "" {
			args = append(args, "-S", params.UnixSocket)
		} else {
			args = append(args,
				"-h", params.Host,
				"-P", fmt.Sprintf("%v", params.Port))
		}
		if params.Uname != "" {
			args = append(args, "-u", params.Uname)
		}
		if params.Pass != "" {
			args = append(args, "-p"+params.Pass)
		}
		if params.DbName != "" {
			args = append(args, "-D", params.DbName)
		}
		if params.SslEnabled() {
			args = append(args,
				"--ssl",
				"--ssl-ca", params.SslCa,
				"--ssl-cert", params.SslCert,
				"--ssl-key", params.SslKey,
				"--ssl-verify-server-cert")
		}
	}
	env := []string{
		"LD_LIBRARY_PATH=" + path.Join(dir, "lib/mysql"),
	}

	t.Logf("Running mysql command: %v %v", name, args)
	cmd := exec.Command(name, args...)
	cmd.Env = env
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		return output, err
	}
	return output, nil
}

// binaryPath does a limited path lookup for a command,
// searching only within sbin and bin in the given root.
func binaryPath(root, binary string) (string, error) {
	subdirs := []string{"sbin", "bin"}
	for _, subdir := range subdirs {
		binPath := path.Join(root, subdir, binary)
		if _, err := os.Stat(binPath); err == nil {
			return binPath, nil
		}
	}
	return "", fmt.Errorf("%s not found in any of %s/{%s}",
		binary, root, strings.Join(subdirs, ","))
}

// The listener's Accept() loop actually only ends on a connection
// error, which will occur when trying to connect after the listener
// has been closed. So this function closes the listener and then
// calls Connect to trigger the error which ends that work.
var cleanupListener = func(ctx context.Context, l *Listener, params *ConnParams) {
	l.Close()
	_, _ = Connect(ctx, params)
}
