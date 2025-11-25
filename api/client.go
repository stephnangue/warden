package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"golang.org/x/net/http2"
	"golang.org/x/time/rate"
)

const (
	EnvWardenAddress          = "WARDEN_ADDR"
	EnvWardenCACert           = "WARDEN_CACERT"
	EnvWardenCACertBytes      = "WARDEN_CACERT_BYTES"
	EnvWardenCAPath           = "WARDEN_CAPATH"
	EnvWardenClientCert       = "WARDEN_CLIENT_CERT"
	EnvWardenClientKey        = "WARDEN_CLIENT_KEY"
	EnvWardenClientTimeout    = "WARDEN_CLIENT_TIMEOUT"
	EnvWardenSRVLookup        = "WARDEN_SRV_LOOKUP"
	EnvWardenSkipVerify       = "WARDEN_SKIP_VERIFY"
	EnvWardenTLSServerName    = "WARDEN_TLS_SERVER_NAME"
	EnvWardenMaxRetries       = "WARDEN_MAX_RETRIES"
	EnvWardenToken            = "WARDEN_TOKEN"
	EnvRateLimit              = "WARDEN_RATE_LIMIT"
	EnvHTTPProxy              = "WARDEN_HTTP_PROXY"
	EnvWardenProxyAddr        = "WARDEN_PROXY_ADDR"


	TLSErrorString = "This error usually means that the server is running with TLS disabled\n" +
		"but the client is configured to use TLS. Please either enable TLS\n" +
		"on the server or run the client with -address set to an address\n" +
		"that uses the http protocol:\n\n" +
		"    warden <command> -address http://<address>\n\n" +
		"You can also set the WARDEN_ADDR environment variable:\n\n\n" +
		"    WARDEN_ADDR=http://<address> warden <command>\n\n" +
		"where <address> is replaced by the actual address to the server."
)

// Config is used to configure the creation of the client.
type Config struct {
	modifyLock sync.RWMutex
	// Address is the address of the Warden server. This should be a complete
	// URL such as "http://warden.example.com". If you need a custom SSL
	// cert or want to enable insecure mode, you need to specify a custom
	// HttpClient.
	Address string

	// HttpClient is the HTTP client to use. Warden sets sane defaults for the
	// http.Client and its associated http.Transport created in DefaultConfig.
	// If you must modify Warden's defaults, it is suggested that you start with
	// that client and modify as needed rather than start with an empty client
	// (or http.DefaultClient).
	HttpClient *http.Client

	// MinRetryWait controls the minimum time to wait before retrying when a 5xx
	// error occurs. Defaults to 1000 milliseconds.
	MinRetryWait time.Duration

	// MaxRetryWait controls the maximum time to wait before retrying when a 5xx
	// error occurs. Defaults to 1500 milliseconds.
	MaxRetryWait time.Duration

	// MaxRetries controls the maximum number of times to retry when a 5xx
	// error occurs. Set to 0 to disable retrying. Defaults to 2 (for a total
	// of three tries).
	MaxRetries int

	// If there is an error when creating the configuration, this will be the
	// error
	Error error

	// OutputCurlString causes the actual request to return an error of type
	// *OutputStringError. Type asserting the error message will allow
	// fetching a cURL-compatible string for the operation.
	//
	// Note: It is not thread-safe to set this and make concurrent requests
	// with the same client. Cloning a client will not clone this value.
	OutputCurlString bool

	// OutputPolicy causes the actual request to return an error of type
	// *OutputPolicyError. Type asserting the error message will display
	// an example of the required policy HCL needed for the operation.
	//
	// Note: It is not thread-safe to set this and make concurrent requests
	// with the same client. Cloning a client will not clone this value.
	OutputPolicy bool

	// curlCACert, curlCAPath, curlClientCert and curlClientKey are used to keep
	// track of the name of the TLS certs and keys when OutputCurlString is set.
	// Cloning a client will also not clone those values.
	curlCACert, curlCAPath        string
	curlClientCert, curlClientKey string

	// SRVLookup enables the client to lookup the host through DNS SRV lookup
	SRVLookup bool

	// Timeout, given a non-negative value, will apply the request timeout
	// to each request function unless an earlier deadline is passed to the
	// request function through context.Context.
	Timeout time.Duration

	// The Backoff function to use; a default is used if not provided
	Backoff retryablehttp.Backoff

	// The CheckRetry function to use; a default is used if not provided
	CheckRetry retryablehttp.CheckRetry

	// Logger is the leveled logger to provide to the retryable HTTP client.
	Logger retryablehttp.LeveledLogger

	// Limiter is the rate limiter used by the client.
	// If this pointer is nil, then there will be no limit set.
	// In contrast, if this pointer is set, even to an empty struct,
	// then that limiter will be used. Note that an empty Limiter
	// is equivalent blocking all events.
	Limiter *rate.Limiter

	clientTLSConfig *tls.Config
}

// TLSConfig contains the parameters needed to configure TLS on the HTTP client
// used to communicate with Warden.
type TLSConfig struct {
	// CACert is the path to a PEM-encoded CA cert file to use to verify the
	// Warden server SSL certificate. It takes precedence over CACertBytes
	// and CAPath.
	CACert string

	// CACertBytes is a PEM-encoded certificate or bundle. It takes precedence
	// over CAPath.
	CACertBytes []byte

	// CAPath is the path to a directory of PEM-encoded CA cert files to verify
	// the Warden server SSL certificate.
	CAPath string

	// ClientCert is the path to the certificate for Warden communication
	ClientCert string

	// ClientKey is the path to the private key for Warden communication
	ClientKey string

	// TLSServerName, if set, is used to set the SNI host when connecting via
	// TLS.
	TLSServerName string

	// Insecure enables or disables SSL verification
	Insecure bool
}

// DefaultConfig returns a default configuration for the client. It is
// safe to modify the return value of this function.
//
// The default Address is https://127.0.0.1:5000, but this can be overridden by
// setting the `WARDEN_ADDR` environment variable.
//
// If an error is encountered, the Error field on the returned *Config will be populated with the specific error.
func DefaultConfig() *Config {
	config := &Config{
		Address:      "https://127.0.0.1:5000",
		HttpClient:   cleanhttp.DefaultPooledClient(),
		Timeout:      time.Second * 60,
		MinRetryWait: time.Millisecond * 1000,
		MaxRetryWait: time.Millisecond * 1500,
		MaxRetries:   2,
		Backoff:      retryablehttp.RateLimitLinearJitterBackoff,
	}

	transport := config.HttpClient.Transport.(*http.Transport)
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if err := http2.ConfigureTransport(transport); err != nil {
		config.Error = err
		return config
	}

	if err := config.ReadEnvironment(); err != nil {
		config.Error = err
		return config
	}

	// Ensure redirects are not automatically followed
	// Note that this is sane for the API client as it has its own
	// redirect handling logic (and thus also for command/meta),
	// but in e.g. http_test actual redirect handling is necessary
	config.HttpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// Returning this value causes the Go net library to not close the
		// response body and to nil out the error. Otherwise retry clients may
		// try three times on every redirect because it sees an error from this
		// function (to prevent redirects) passing through to it.
		return http.ErrUseLastResponse
	}

	return config
}

// configureTLS is a lock free version of ConfigureTLS that can be used in
// ReadEnvironment where the lock is already hold
func (c *Config) configureTLS(t *TLSConfig) error {
	if c.HttpClient == nil {
		c.HttpClient = DefaultConfig().HttpClient
	}
	clientTLSConfig := c.HttpClient.Transport.(*http.Transport).TLSClientConfig

	var clientCert tls.Certificate
	foundClientCert := false

	switch {
	case t.ClientCert != "" && t.ClientKey != "":
		var err error
		clientCert, err = tls.LoadX509KeyPair(t.ClientCert, t.ClientKey)
		if err != nil {
			return err
		}
		foundClientCert = true
		c.curlClientCert = t.ClientCert
		c.curlClientKey = t.ClientKey
	case t.ClientCert != "" || t.ClientKey != "":
		return errors.New("both client cert and client key must be provided")
	}

	if t.CACert != "" || len(t.CACertBytes) != 0 || t.CAPath != "" {
		c.curlCACert = t.CACert
		c.curlCAPath = t.CAPath
		rootConfig := &certConfig{
			CAFile:        t.CACert,
			CACertificate: t.CACertBytes,
			CAPath:        t.CAPath,
		}
		if err := configureTLS(clientTLSConfig, rootConfig); err != nil {
			return err
		}
	}

	if t.Insecure {
		clientTLSConfig.InsecureSkipVerify = true
	}

	if foundClientCert {
		// We use this function to ignore the server's preferential list of
		// CAs, otherwise any CA used for the cert auth backend must be in the
		// server's CA pool
		clientTLSConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &clientCert, nil
		}
	}

	if t.TLSServerName != "" {
		clientTLSConfig.ServerName = t.TLSServerName
	}
	c.clientTLSConfig = clientTLSConfig

	return nil
}

func (c *Config) TLSConfig() *tls.Config {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()
	return c.clientTLSConfig.Clone()
}

// ConfigureTLS takes a set of TLS configurations and applies those to the
// HTTP client.
func (c *Config) ConfigureTLS(t *TLSConfig) error {
	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	return c.configureTLS(t)
}

// ReadEnvironment reads configuration information from the environment. If
// there is an error, no configuration value is updated.
func (c *Config) ReadEnvironment() error {
	var envAddress string
	var envCACert string
	var envCACertBytes []byte
	var envCAPath string
	var envClientCert string
	var envClientKey string
	var envClientTimeout time.Duration
	var envInsecure bool
	var envTLSServerName string
	var envMaxRetries *int
	var envSRVLookup bool
	var limit *rate.Limiter
	var envWardenProxy string

	// Parse the environment variables
	if v := ReadWardenVariable(EnvWardenAddress); v != "" {
		envAddress = v
	}
	if v := ReadWardenVariable(EnvWardenMaxRetries); v != "" {
		maxRetries, err := parseutil.SafeParseIntRange(v, 0, math.MaxInt)
		if err != nil {
			return err
		}
		mRetries := int(maxRetries)
		envMaxRetries = &mRetries
	}
	if v := ReadWardenVariable(EnvWardenCACert); v != "" {
		envCACert = v
	}
	if v := ReadWardenVariable(EnvWardenCACertBytes); v != "" {
		envCACertBytes = []byte(v)
	}
	if v := ReadWardenVariable(EnvWardenCAPath); v != "" {
		envCAPath = v
	}
	if v := ReadWardenVariable(EnvWardenClientCert); v != "" {
		envClientCert = v
	}
	if v := ReadWardenVariable(EnvWardenClientKey); v != "" {
		envClientKey = v
	}
	if v := ReadWardenVariable(EnvRateLimit); v != "" {
		rateLimit, burstLimit, err := parseRateLimit(v)
		if err != nil {
			return err
		}
		limit = rate.NewLimiter(rate.Limit(rateLimit), burstLimit)
	}
	if t := ReadWardenVariable(EnvWardenClientTimeout); t != "" {
		clientTimeout, err := parseutil.ParseDurationSecond(t)
		if err != nil {
			return fmt.Errorf("could not parse %q", EnvWardenClientTimeout)
		}
		envClientTimeout = clientTimeout
	}
	if v := ReadWardenVariable(EnvWardenSkipVerify); v != "" {
		var err error
		envInsecure, err = strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("could not parse %s", EnvWardenSkipVerify)
		}
	}
	if v := ReadWardenVariable(EnvWardenSRVLookup); v != "" {
		var err error
		envSRVLookup, err = strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("could not parse %s", EnvWardenSRVLookup)
		}
	}

	if v := ReadWardenVariable(EnvWardenTLSServerName); v != "" {
		envTLSServerName = v
	}

	if v := ReadWardenVariable(EnvHTTPProxy); v != "" {
		envWardenProxy = v
	}

	// WARDEN_PROXY_ADDR supersedes WARDEN_HTTP_PROXY
	if v := ReadWardenVariable(EnvWardenProxyAddr); v != "" {
		envWardenProxy = v
	}

	// Configure the HTTP clients TLS configuration.
	t := &TLSConfig{
		CACert:        envCACert,
		CACertBytes:   envCACertBytes,
		CAPath:        envCAPath,
		ClientCert:    envClientCert,
		ClientKey:     envClientKey,
		TLSServerName: envTLSServerName,
		Insecure:      envInsecure,
	}

	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	c.SRVLookup = envSRVLookup
	c.Limiter = limit

	if err := c.configureTLS(t); err != nil {
		return err
	}

	if envAddress != "" {
		c.Address = envAddress
	}

	if envMaxRetries != nil {
		c.MaxRetries = *envMaxRetries
	}

	if envClientTimeout != 0 {
		c.Timeout = envClientTimeout
	}

	if envWardenProxy != "" {
		u, err := url.Parse(envWardenProxy)
		if err != nil {
			return err
		}

		transport := c.HttpClient.Transport.(*http.Transport)
		transport.Proxy = http.ProxyURL(u)
	}

	return nil
}

// ParseAddress transforms the provided address into a url.URL and handles
// the case of Unix domain sockets by setting the DialContext in the
// configuration's HttpClient.Transport. This function must be called with
// c.modifyLock held for write access.
func (c *Config) ParseAddress(address string) (*url.URL, error) {
	u, err := url.Parse(address)
	if err != nil {
		return nil, err
	}

	c.Address = address

	if strings.HasPrefix(address, "unix://") {
		// When the address begins with unix://, always change the transport's
		// DialContext (to match previous behaviour)
		socket := strings.TrimPrefix(address, "unix://")

		if transport, ok := c.HttpClient.Transport.(*http.Transport); ok {
			transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
				return net.Dial("unix", socket)
			}

			// Since the address points to a unix domain socket, the scheme in the
			// *URL would be set to `unix`. The *URL in the client is expected to
			// be pointing to the protocol used in the application layer and not to
			// the transport layer. Hence, setting the fields accordingly.
			u.Scheme = "http"
			u.Host = "localhost"
			u.Path = ""
		} else {
			return nil, errors.New("attempting to specify unix:// address with non-transport transport")
		}
	} else if strings.HasPrefix(c.Address, "unix://") {
		// When the address being set does not begin with unix:// but the previous
		// address in the Config did, change the transport's DialContext back to
		// use the default configuration that cleanhttp uses.

		if transport, ok := c.HttpClient.Transport.(*http.Transport); ok {
			transport.DialContext = cleanhttp.DefaultPooledTransport().DialContext
		}
	}

	return u, nil
}

func parseRateLimit(val string) (rate float64, burst int, err error) {
	_, err = fmt.Sscanf(val, "%f:%d", &rate, &burst)
	if err != nil {
		rate, err = strconv.ParseFloat(val, 64)
		if err != nil {
			err = fmt.Errorf("%v was provided but incorrectly formatted", EnvRateLimit)
		}
		burst = int(rate)
	}

	return rate, burst, err
}

// Client is the client to the Warden API. Create a client with NewClient.
type Client struct {
	modifyLock         sync.RWMutex
	addr               *url.URL
	config             *Config
	token              string
}

// NewClient returns a new client for the given configuration.
//
// If the configuration is nil, Warden will use configuration from
// DefaultConfig(), which is the recommended starting configuration.
//
// If the environment variable `WARDEN_TOKEN` is present, the token will be
// automatically added to the client. Otherwise, you must manually call
// `SetToken()`.
func NewClient(c *Config) (*Client, error) {
	def := DefaultConfig()
	if def == nil {
		return nil, errors.New("could not create/read default configuration")
	}
	if def.Error != nil {
		return nil, fmt.Errorf("error encountered setting up default configuration: %w", def.Error)
	}

	if c == nil {
		c = def
	}

	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	if c.MinRetryWait == 0 {
		c.MinRetryWait = def.MinRetryWait
	}

	if c.MaxRetryWait == 0 {
		c.MaxRetryWait = def.MaxRetryWait
	}

	if c.HttpClient == nil {
		c.HttpClient = def.HttpClient
	}
	if c.HttpClient.Transport == nil {
		c.HttpClient.Transport = def.HttpClient.Transport
	}

	address := c.Address

	u, err := c.ParseAddress(address)
	if err != nil {
		return nil, err
	}

	client := &Client{
		addr:    u,
		config:  c,
	}

	if token := ReadWardenVariable(EnvWardenToken); token != "" {
		client.token = token
	}

	return client, nil
}

// SetAddress sets the address of Warden in the client. The format of address should be
// "<Scheme>://<Host>:<Port>". Setting this on a client will override the
// value of WARDEN_ADDR environment variable.
func (c *Client) SetAddress(addr string) error {
	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	parsedAddr, err := c.config.ParseAddress(addr)
	if err != nil {
		return fmt.Errorf("failed to set address: %w", err)
	}

	c.addr = parsedAddr
	return nil
}

// Address returns the Warden URL the client is configured to connect to
func (c *Client) Address() string {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()

	return c.addr.String()
}

// SetLimiter will set the rate limiter for this client.
// This method is thread-safe.
// rateLimit and burst are specified according to https://godoc.org/golang.org/x/time/rate#NewLimiter
func (c *Client) SetLimiter(rateLimit float64, burst int) {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()
	c.config.modifyLock.Lock()
	defer c.config.modifyLock.Unlock()

	c.config.Limiter = rate.NewLimiter(rate.Limit(rateLimit), burst)
}

func (c *Client) Limiter() *rate.Limiter {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()
	c.config.modifyLock.RLock()
	defer c.config.modifyLock.RUnlock()

	return c.config.Limiter
}

// SetMinRetryWait sets the minimum time to wait before retrying in the case of certain errors.
func (c *Client) SetMinRetryWait(retryWait time.Duration) {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()
	c.config.modifyLock.Lock()
	defer c.config.modifyLock.Unlock()

	c.config.MinRetryWait = retryWait
}

func (c *Client) MinRetryWait() time.Duration {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()
	c.config.modifyLock.RLock()
	defer c.config.modifyLock.RUnlock()

	return c.config.MinRetryWait
}

// SetMaxRetryWait sets the maximum time to wait before retrying in the case of certain errors.
func (c *Client) SetMaxRetryWait(retryWait time.Duration) {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()
	c.config.modifyLock.Lock()
	defer c.config.modifyLock.Unlock()

	c.config.MaxRetryWait = retryWait
}

func (c *Client) MaxRetryWait() time.Duration {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()
	c.config.modifyLock.RLock()
	defer c.config.modifyLock.RUnlock()

	return c.config.MaxRetryWait
}

// SetMaxRetries sets the number of retries that will be used in the case of certain errors
func (c *Client) SetMaxRetries(retries int) {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()
	c.config.modifyLock.Lock()
	defer c.config.modifyLock.Unlock()

	c.config.MaxRetries = retries
}

func (c *Client) SetMaxIdleConnections(idle int) {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()
	c.config.modifyLock.Lock()
	defer c.config.modifyLock.Unlock()

	c.config.HttpClient.Transport.(*http.Transport).MaxIdleConns = idle
}

func (c *Client) MaxIdleConnections() int {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()
	c.config.modifyLock.Lock()
	defer c.config.modifyLock.Unlock()

	return c.config.HttpClient.Transport.(*http.Transport).MaxIdleConns
}

func (c *Client) SetDisableKeepAlives(disable bool) {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()
	c.config.modifyLock.Lock()
	defer c.config.modifyLock.Unlock()

	c.config.HttpClient.Transport.(*http.Transport).DisableKeepAlives = disable
}

func (c *Client) DisableKeepAlives() bool {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()
	c.config.modifyLock.RLock()
	defer c.config.modifyLock.RUnlock()

	return c.config.HttpClient.Transport.(*http.Transport).DisableKeepAlives
}

func (c *Client) MaxRetries() int {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()
	c.config.modifyLock.RLock()
	defer c.config.modifyLock.RUnlock()

	return c.config.MaxRetries
}

func (c *Client) SetSRVLookup(srv bool) {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()
	c.config.modifyLock.Lock()
	defer c.config.modifyLock.Unlock()

	c.config.SRVLookup = srv
}

func (c *Client) SRVLookup() bool {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()
	c.config.modifyLock.RLock()
	defer c.config.modifyLock.RUnlock()

	return c.config.SRVLookup
}

// SetCheckRetry sets the CheckRetry function to be used for future requests.
func (c *Client) SetCheckRetry(checkRetry retryablehttp.CheckRetry) {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()
	c.config.modifyLock.Lock()
	defer c.config.modifyLock.Unlock()

	c.config.CheckRetry = checkRetry
}

func (c *Client) CheckRetry() retryablehttp.CheckRetry {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()
	c.config.modifyLock.RLock()
	defer c.config.modifyLock.RUnlock()

	return c.config.CheckRetry
}

// SetClientTimeout sets the client request timeout
func (c *Client) SetClientTimeout(timeout time.Duration) {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()
	c.config.modifyLock.Lock()
	defer c.config.modifyLock.Unlock()

	c.config.Timeout = timeout
}

func (c *Client) ClientTimeout() time.Duration {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()
	c.config.modifyLock.RLock()
	defer c.config.modifyLock.RUnlock()

	return c.config.Timeout
}

func (c *Client) OutputCurlString() bool {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()
	c.config.modifyLock.RLock()
	defer c.config.modifyLock.RUnlock()

	return c.config.OutputCurlString
}

func (c *Client) SetOutputCurlString(curl bool) {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()
	c.config.modifyLock.Lock()
	defer c.config.modifyLock.Unlock()

	c.config.OutputCurlString = curl
}

func (c *Client) OutputPolicy() bool {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()
	c.config.modifyLock.RLock()
	defer c.config.modifyLock.RUnlock()

	return c.config.OutputPolicy
}

func (c *Client) SetOutputPolicy(isSet bool) {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()
	c.config.modifyLock.Lock()
	defer c.config.modifyLock.Unlock()

	c.config.OutputPolicy = isSet
}

// Token returns the access token being used by this client. It will
// return the empty string if there is no token set.
func (c *Client) Token() string {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()
	return c.token
}

// SetToken sets the token directly. This won't perform any auth
// verification, it simply sets the token properly for future requests.
func (c *Client) SetToken(v string) {
	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()
	c.token = v
}

// ClearToken deletes the token if it is set or does nothing otherwise.
func (c *Client) ClearToken() {
	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()
	c.token = ""
}

// SetBackoff sets the backoff function to be used for future requests.
func (c *Client) SetBackoff(backoff retryablehttp.Backoff) {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()
	c.config.modifyLock.Lock()
	defer c.config.modifyLock.Unlock()

	c.config.Backoff = backoff
}

func (c *Client) SetLogger(logger retryablehttp.LeveledLogger) {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()
	c.config.modifyLock.Lock()
	defer c.config.modifyLock.Unlock()

	c.config.Logger = logger
}

// NewRequest creates a new raw request object to query the Vault server
// configured for this client. 
func (c *Client) NewRequest(method, requestPath string) *Request {
	c.modifyLock.RLock()
	addr := c.addr
	token := c.token
	c.modifyLock.RUnlock()

	host := addr.Host
	// if SRV records exist (see https://tools.ietf.org/html/draft-andrews-http-srv-02), lookup the SRV
	// record and take the highest match; this is not designed for high-availability, just discovery
	// Internet Draft specifies that the SRV record is ignored if a port is given
	if addr.Port() == "" && c.config.SRVLookup {
		_, addrs, err := net.LookupSRV("http", "tcp", addr.Hostname())
		if err == nil && len(addrs) > 0 {
			host = fmt.Sprintf("%s:%d", addrs[0].Target, addrs[0].Port)
		}
	}

	req := &Request{
		Method: method,
		URL: &url.URL{
			User:   addr.User,
			Scheme: addr.Scheme,
			Host:   host,
			Path:   path.Join(addr.Path, requestPath),
		},
		Host:        addr.Host,
		ClientToken: token,
		Params:      make(map[string][]string),
	}

	return req
}

func (c *Client) RawRequestWithContext(ctx context.Context, r *Request) (*Response, error) {
	// Note: we purposefully do not call cancel manually. The reason is
	// when canceled, the request.Body will EOF when reading due to the way
	// it streams data in. Cancel will still be run when the timeout is
	// hit, so this doesn't really harm anything.
	ctx, _ = c.withConfiguredTimeout(ctx)
	return c.rawRequestWithContext(ctx, r)
}

func (c *Client) rawRequestWithContext(ctx context.Context, r *Request) (*Response, error) {
	c.modifyLock.RLock()

	c.config.modifyLock.RLock()
	limiter := c.config.Limiter
	minRetryWait := c.config.MinRetryWait
	maxRetryWait := c.config.MaxRetryWait
	maxRetries := c.config.MaxRetries
	checkRetry := c.config.CheckRetry
	backoff := c.config.Backoff
	httpClient := c.config.HttpClient
	outputCurlString := c.config.OutputCurlString
	logger := c.config.Logger
	c.config.modifyLock.RUnlock()

	c.modifyLock.RUnlock()

	if limiter != nil {
		limiter.Wait(ctx)
	}

	req, err := r.toRetryableHTTP()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("nil request created")
	}

	if outputCurlString {
		LastOutputStringError = &OutputStringError{
			Request:       req,
			TLSSkipVerify: c.config.HttpClient.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify,
			ClientCert:    c.config.curlClientCert,
			ClientKey:     c.config.curlClientKey,
			ClientCACert:  c.config.curlCACert,
			ClientCAPath:  c.config.curlCAPath,
		}
		return nil, LastOutputStringError
	}

	req.Request = req.Request.WithContext(ctx)

	if backoff == nil {
		backoff = retryablehttp.RateLimitLinearJitterBackoff
	}

	if checkRetry == nil {
		checkRetry = DefaultRetryPolicy
	}

	client := &retryablehttp.Client{
		HTTPClient:   httpClient,
		RetryWaitMin: minRetryWait,
		RetryWaitMax: maxRetryWait,
		RetryMax:     maxRetries,
		Backoff:      backoff,
		CheckRetry:   checkRetry,
		Logger:       logger,
		ErrorHandler: retryablehttp.PassthroughErrorHandler,
	}

	var result *Response
	resp, err := client.Do(req)
	if resp != nil {
		result = &Response{Response: resp}
	}
	if err != nil {
		if strings.Contains(err.Error(), "tls: oversized") {
			err = fmt.Errorf("%w\n\n"+TLSErrorString, err) //nolint:staticcheck // user-facing error
		}
		return result, err
	}

	if err := result.Error(); err != nil {
		return result, err
	}

	return result, nil
}

// withConfiguredTimeout wraps the context with a timeout from the client configuration.
func (c *Client) withConfiguredTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := c.ClientTimeout()

	if timeout > 0 {
		return context.WithTimeout(ctx, timeout)
	}

	return ctx, func() {}
}

// DefaultRetryPolicy is the default retry policy used by new Client objects.
// It is the same as retryablehttp.DefaultRetryPolicy except that it also retries
// 412 requests, which will be used later
func DefaultRetryPolicy(ctx context.Context, resp *http.Response, err error) (bool, error) {
	retry, err := retryablehttp.DefaultRetryPolicy(ctx, resp, err)
	if err != nil || retry {
		return retry, err
	}
	if resp != nil && resp.StatusCode == 412 {
		return true, nil
	}
	return false, nil
}
