package cred

import "time"

const (
	DATABASE_USERPASS = "database_userpass"
	AWS_ACCESS_KEYS = "aws_access_keys"
)

type DatabaseUserpass struct {
	Username    string
	Password    string
	Database    string
	LeaseTTL    string
}

// generic credential
type Credential struct {
	Type      string // database_userpass, aws_access_keys, azure_service_principal_creds, gcp_service_account_creds
	LeaseTTL  time.Duration
	LeaseID   string // used for revocation
	TokenID   string // each credential is bound to a token
	Data      map[string]string
}