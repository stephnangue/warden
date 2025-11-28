package core

import (
	"context"
	"errors"
	"maps"
	"sync"

	"github.com/openbao/openbao/helper/locking"
	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/auth"
	"github.com/stephnangue/warden/auth/token"
	"github.com/stephnangue/warden/authorize"
	"github.com/stephnangue/warden/config"
	"github.com/stephnangue/warden/cred"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/provider"
	"github.com/stephnangue/warden/storage"
	"github.com/stephnangue/warden/target"
)

var (
	// errNoMatchingMount is returned if the mount is not found
	errNoMatchingMount = errors.New("no matching mount")
)

type Core struct {
	storage   storage.Storage
	storageMu sync.RWMutex

	config config.Config

	logger logger.Logger

	tokenStore token.TokenStore

	accessControl *authorize.AccessControl

	roles *authorize.RoleRegistry

	credSources *cred.CredSourceRegistry

	targets *target.TargetRegistry

	auditDevices map[string]audit.Factory

	authMethods map[string]auth.Factory

	providers map[string]provider.Factory

	auditManager audit.AuditManager

	audit *MountTable

	// auditLock is used to ensure that the audit table does not
	// change underneath a calling function
	auditLock sync.RWMutex

	router *Router

	mounts *MountTable

	// mountsLock is used to ensure that the mounts table does not
	// change underneath a calling function
	mountsLock locking.DeadlockRWMutex
}

type CoreConfig struct {
	RawConfig    *config.Config
	AuditDevices map[string]audit.Factory
	AuthMethods  map[string]auth.Factory
	Providers    map[string]provider.Factory
	TokenStore   token.TokenStore
	Storage      storage.Storage
	Logger       logger.Logger
}

func (c *Core) Init(ctx context.Context) error {

	// Load system backend first
	if err := c.LoadSystemBackend(ctx); err != nil {
		return err
	}

	c.LoadRoles(ctx)

	c.LoadCredSources(ctx)

	c.InitAccessControl(ctx)

	c.LoadTargets(ctx)

	err := c.LoadMounts(ctx)
	if err != nil {
		return err
	}

	err = c.LoadAudits(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (c *Core) Shutdown() error {
	c.logger.Info("Shutting down the core")

	c.tokenStore.Close()

	c.storageMu.Lock()
	defer c.storageMu.Unlock()
	c.storage.Stop()

	c.logger.Info("Core shutdown successfully")

	return nil
}

// CreateCore creates, initializes and configures a Warden node (core).
func CreateCore(conf *CoreConfig) (*Core, error) {
	c := &Core{
		storage:      conf.Storage,
		config:       *conf.RawConfig,
		logger:       conf.Logger,
		tokenStore:   conf.TokenStore,
		auditManager: audit.NewAuditManager(conf.Logger.WithSystem("audit")),
		router:       NewRouter(conf.Logger.WithSystem("router")),
		mounts:       NewMountTable(),
		audit:        NewMountTable(),
	}

	// Provider backends
	c.configureProvider(conf.Providers)

	// Auth backends
	c.configureAuthMethods(conf.AuthMethods)

	// Audit backends
	c.configureAuditDevices(conf.AuditDevices)

	return c, nil
}

func (c *Core) configureProvider(backends map[string]provider.Factory) {
	providers := make(map[string]provider.Factory, len(backends))
	maps.Copy(providers, backends)
	c.providers = providers
}

func (c *Core) configureAuthMethods(backends map[string]auth.Factory) {
	auths := make(map[string]auth.Factory, len(backends))
	maps.Copy(auths, backends)
	c.authMethods = auths
}

func (c *Core) configureAuditDevices(backends map[string]audit.Factory) {
	audits := make(map[string]audit.Factory, len(backends))
	maps.Copy(audits, backends)
	c.auditDevices = audits
}

func (c *Core) Roles() *authorize.RoleRegistry {
	return c.roles
}

func (c *Core) CredSources() *cred.CredSourceRegistry {
	return c.credSources
}

func (c *Core) Targets() *target.TargetRegistry {
	return c.targets
}

func (c *Core) LoadRoles(ctx context.Context) {
	// load the roles from the storage
	c.logger.Info("loading roles from storage")

	roleRegistry := authorize.NewRoleRegistry()
	roleRegistry.Register(authorize.Role{
		Name: "system_admin",
		Type: "system",
	})
	roleRegistry.Register(authorize.Role{
		Name:           "market_reader",
		Type:           "static_database_userpass",
		CredSourceName: "default",
		CredConfig: map[string]string{
			"database": "myapp",
			"username": "vaultadmin",
			"password": "vaultpassword",
		},
		TargetName: "mysql_backend",
	})
	roleRegistry.Register(authorize.Role{
		Name:           "sales_admin",
		Type:           "static_database_userpass",
		CredSourceName: "vault_docker",
		CredConfig: map[string]string{
			"kv2_mount":   "kv_static_secret",
			"secret_path": "database/mysql/prod",
		},
		TargetName: "mysql_backend",
	})
	roleRegistry.Register(authorize.Role{
		Name:           "ondemand_role",
		Type:           "dynamic_database_userpass",
		CredSourceName: "vault_docker",
		CredConfig: map[string]string{
			"database":       "myapp",
			"database_mount": "database",
			"role_name":      "my-role",
		},
		TargetName: "mysql_backend",
	})
	roleRegistry.Register(authorize.Role{
		Name:           "aws_dev_account_local",
		Type:           "static_aws_access_keys",
		CredSourceName: "default",
		CredConfig: map[string]string{
			"access_key_id":     "myapp",
			"secret_access_key": "database",
		},
	})
	roleRegistry.Register(authorize.Role{
		Name:           "aws_dev_account_vault",
		Type:           "static_aws_access_keys",
		CredSourceName: "vault_docker",
		CredConfig: map[string]string{
			"kv2_mount":   "kv_static_secret",
			"secret_path": "aws/prod",
		},
	})
	roleRegistry.Register(authorize.Role{
		Name:           "aws_prod_account_vault",
		Type:           "dynamic_aws_access_keys",
		CredSourceName: "vault_docker",
		CredConfig: map[string]string{
			"aws_mount":         "aws",
			"role_name":         "terraform",
			"ttl":               "900s",
			"role_session_name": "test",
			"role_arn":          "arn:aws:iam::905418489750:role/terraform-role-warden",
		},
	})
	c.roles = roleRegistry
}

func (c *Core) LoadCredSources(ctx context.Context) {
	// load the cred sources from the storage
	c.logger.Info("loading cred sources from storage")

	credSources := cred.NewCredSourceRegistry()
	credSources.Register(cred.CredSource{
		Name: "default",
		Type: "local",
	})
	credSources.Register(cred.CredSource{
		Name: "vault_docker",
		Type: "vault",
		Config: map[string]string{
			"vault_address":   "http://vault:8200",
			"vault_namespace": "root",
			"auth_method":     "approle",
			"approle_mount":   "warden_approle",
			"role_id":         "c0ae884e-b55e-1736-3710-bb1d88d76182",
			"secret_id":       "e0b8f9b8-6b32-5478-9a73-196e50734c2f",
		},
	})
	c.credSources = credSources
}

func (c *Core) InitAccessControl(ctx context.Context) {
	// load the role assignments
	c.logger.Info("loading role assignments from storage")

	accessControl := authorize.NewAccessControl()
	accessControl.AssignRole("service-client-1", "market_reader")
	accessControl.AssignRole("service-client-1", "ondemand_role")
	accessControl.AssignRole("service-client-1", "aws_dev_account_local")
	accessControl.AssignRole("service-client-1", "aws_dev_account_vault")
	accessControl.AssignRole("service-client-1", "aws_prod_account_vault")
	accessControl.AssignRole("service-client-2", "sales_admin")

	// System admin role assignments
	accessControl.AssignRole("service-client-1", "system_admin") // For testing
	accessControl.AssignRole("admin-user", "system_admin")

	c.accessControl = accessControl
}

func (c *Core) LoadTargets(ctx context.Context) {
	// load the targets from the storage
	targets := target.NewTargetRegistry()
	targets.Register(&target.MysqlTarget{
		Name:        "mysql_backend",
		Hostname:    "mysql-server",
		Port:        "3306",
		MtlsEnabled: true,
		CACert: `-----BEGIN CERTIFICATE-----
MIIFizCCA3OgAwIBAgIUKV0KFYH8n+NMn4RIID/08RaE2hYwDQYJKoZIhvcNAQEL
BQAwVTELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVN0YXRlMQ0wCwYDVQQHDARDaXR5
MRUwEwYDVQQKDAxPcmdhbml6YXRpb24xEDAOBgNVBAMMB1Jvb3QgQ0EwHhcNMjUx
MDE2MTYxODI2WhcNMjYxMDE2MTYxODI2WjBVMQswCQYDVQQGEwJVUzEOMAwGA1UE
CAwFU3RhdGUxDTALBgNVBAcMBENpdHkxFTATBgNVBAoMDE9yZ2FuaXphdGlvbjEQ
MA4GA1UEAwwHUm9vdCBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
AM61xrG8DUPJchhxisMMYGLpw+dfiITkVRSxMkT/Nkzzk8uJ+GZOvJ0+jhJYbF19
ZNVxoTjrc8j0Ojvb8ATQdSkeAKMIdykP7yHOAmboN73bHP+Opde1ZMxGFQYXLTYj
DPWhIqn8dR58LKwkSj6taRKqekMEbP663faGEC+IZkCEMWOZYGkMHFn0C2NUynVP
TX2pnrC+h3XOCsR56FNFbX6EZktBLy+8I5ofpfCkQW/PfNp59mtyhp2/Cyod/FcN
+qZNPKVpiCUqkV2YhMwWudGpdjtZl6BtM0QG4WQwwEfmP1vKO19QrOLLWIvu/tnD
az+awxZLN/+wtAETl6bAaVrmyKeTrUZXRjTyHqZSmnargTc+9ATmFO0TihzVmshP
bk5KdyJ8Ixhbc6DZIDY24GXCGH8dcZaq95OYiBLwxUPHrQi28MeTRKfHMEjtW+ma
BLPfIVTC/qRkZGbE+4lMzCCFaLFeNchLfSavMA7yv7nzALAn80E1D60UBunIH9+K
w55hV6n6Waa9zvHlLWQnuo4NKZkIofiaVwQM2P+Ffgwad4HXCxZ7ebVK1Ur8nnwP
fApZ2StyK1R8cnERFP6ppBwx0+RT3MsPrrSFYnxyiIsRgHPdzuxG4R5PnbQk9+Uw
CJ5z6ihEy4+il+yMjiPoTHcNR7VFwhdRwbIerxnMkz0HAgMBAAGjUzBRMB0GA1Ud
DgQWBBTeN9HrqBjmEhk8hUu94RDsZQA/ETAfBgNVHSMEGDAWgBTeN9HrqBjmEhk8
hUu94RDsZQA/ETAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQCh
emFkwLedcePho6iDtzbZEjJoWl9YbqYICZuRRnN1cABAPvMNYJVppYTKxrklnXev
BqoG7BIcixmxQAiX7ifuI83t2IDBI78wvBmXRGkzoXjIxy73fUhorVxN+7A0RD9C
aWpnycbpuvziHTyKGPwtfxcECq6xmHidXKojcEdO/v6CYP4bBLBL+NMfXYDRIb13
8/OH94bJOhMrRsA9G7/TLLDEODZI+U9Nuwlovbp1QL+wKEDd/HKlxN9ET0Dg9Hd9
Xb/3oHV+OPEbcEWOWdudU5Rf6NaAeDKEZJeTygsBdx3vdKhMMrvPIZUSOWugN0Ls
H/uoSUMQQsa4Dt2rDHvYLXnQ3EcG8u4jVCxvrnQeuUSu7TFA5pmDWjdzB4ZvDVt1
hiWZlHsTCxDPSi9eiM5YGTXlBU9F9iCOX3y/lGB1oJtwXRdu7j4bf/0T/643m4qH
0bn+dXYlL4yV0NP/09xvzpjJGu+UMjAquv63OGOMRpgJ5W6/QNIXkQ/9iGVlICYA
+Co87WfQEDYTGfORMMwyvqJtbiXka94rH4CP+Ahm8T2IxA16rQ2DPZsp4FE7UDRW
rl3XB7qdvv6khQliu2+vKmkcjMdqeKGVuTtDByAL9opm+IP6Z9ldBHAANDJQjNJe
cpliwKYo8WlwstvVBdrDzDbfbv4vzSeOpem3VvXRSQ==
-----END CERTIFICATE-----
`,
		ClientCert: `-----BEGIN CERTIFICATE-----
MIIFlDCCA3ygAwIBAgIUfnupTqlwijm9GSB3zYBKYtokQ2gwDQYJKoZIhvcNAQEL
BQAwVTELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVN0YXRlMQ0wCwYDVQQHDARDaXR5
MRUwEwYDVQQKDAxPcmdhbml6YXRpb24xEDAOBgNVBAMMB1Jvb3QgQ0EwHhcNMjUx
MDE2MTYxODI5WhcNMjYxMDE2MTYxODI5WjBaMQswCQYDVQQGEwJVUzEOMAwGA1UE
CAwFU3RhdGUxDTALBgNVBAcMBENpdHkxFTATBgNVBAoMDE9yZ2FuaXphdGlvbjEV
MBMGA1UEAwwMbXlzcWwtY2xpZW50MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
CgKCAgEAvGxjQwUWd5Sd0S1c6/UYWCymTIQaBhYu1Jgxp0Xdz8emrB03veh/ck8R
YjtSUtTYijO1oIjAvfqeCNic7DZHjfIHmHeU7Hu8JJJ4rn/7Y/MClp1G+97Nc7Ul
XxU51ph8vFBxOillFA9MiAQRzWNEAuNpGjmmOLr+DxTp3MfyXWmbm9W2ohRpc6sb
WEk46CPA8ddLlKej9RZEsepTV2MGfJZRjTl/8zXsNMXno5d5dsTl6vyP9qBBfMYP
Goxxe6lAgu/ZyHNdCvYAhipKEuivJ6LwBeW1aQz2jl6j/FDeCtWOXtsFYGbeCURv
Vi5hPS3X1HIykmYYpJJNOK01OiDdqHUNWcPzob31yGHy9qvxfJrowt2gTzLtoSOC
VTDYQU80gK13k9j5U8duUiY60sr7Uq9OoP4cOXK0jjq8GT92JbgAmHu3V15QyQ+q
EQtlCj9JzwdxxNtW9VWOp0qx7NmeYOGnd2onAHsVV6a+tldQt9QucRa9+Gnyp0tF
pBwvPMHzUn12MFXNgTcTTajmAGnsG7Yt1oO3wPY5tjO/nrFshKA4AAeFrAD7LpVE
N8g8sI2/YeglwAg+sa7mrlZZdf/zMTSU0DqTOYANqiCQThFQxWpMfbwINOwIAZsF
T2Xfmy/Xod3Zsbuam/5C3hxCTYMwPobGGukIVMUA3Itb2uBUlDMCAwEAAaNXMFUw
EwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFBo2P4yTtFLonfK2lJreTZhE
dPvgMB8GA1UdIwQYMBaAFN430euoGOYSGTyFS73hEOxlAD8RMA0GCSqGSIb3DQEB
CwUAA4ICAQCjcrZbsiRAmw8demgAMos+222AdV0BZqk2xescGFPJSMtrHetIMByo
BMHmIQWtW2jbt68mQunrk+SkYPPHBdLSkNWqTsNcO/+OzVmYr3nOrYjt24ZyAqOq
wxP7gfQkFEryxgsFDEE1d1a9ueUO3CKhPRkA7hGSmPSPkWbVNc4euUyWd5rGEzXu
REHRb1opnUjDampupDZk+8pKrcJlAP9HlAxDq+O94r13dq17D2+wWf9usmwu9o2l
sQKqp3w5YqCfBN0mcWd5SU5ez1j9nZnEkV+aYqLoZXUbRRZcaQZJJdyF3srDf2wB
qPkhuFwHQVIEfy+SL+EeDdLQT88pCB5CH+dFcDCtJxFXqQyfiUN/E5Fbzp9SLZQB
qpKqF0NiTgogRfmrdGsH6dw4N71BFrSCjv8IqBAu9cBDcmjj7SFa/4ZDoqxH42I+
GyBA05dSsRVOUJMSbBk/cofbUUG3FpUpW3Vb+ciJ1wryvYFikr9c8mCg+OWrQO1d
oRICNKZf3/Mv/eDgju20j3EWFT+NsEP3YVv1+c1Za91mz7UTmaJkBeIBGyE5JKQM
ilKqT8ZCxnXeXce0SyBBtWB3C+XC8xZkdD5h2G84oqyIFAfBf7eeFOleVOnstCRA
9FB8O35VocuRpL3S2+BoqyoNuDhJKZ3yoTrWNrZFggdY4J2FgV3v/w==
-----END CERTIFICATE-----
`,
		ClientKey: `-----BEGIN PRIVATE KEY-----
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
cVs1CNZyx2Epxma3FYINYJdklZNKn5I=
-----END PRIVATE KEY-----
`,
	})
	c.targets = targets
}
