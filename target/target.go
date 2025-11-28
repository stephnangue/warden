package target

type Target interface {
	GetName() string
	GetType() string

	GetHostname() string
	GetPort() string

	IsMtlsEnabled() bool

	GetCACert() string
	GetClientCert() string
	GetClientKey() string
}
