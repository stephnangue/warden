package target

type MysqlTarget struct {
	Name            string
	Hostname        string
	Port      		string
	MtlsEnabled     bool
	CACert          string
	ClientCert      string
	ClientKey       string
}

func (t *MysqlTarget) GetName() string {
	return t.Name
}

func (t *MysqlTarget) GetHostname() string {
	return t.Hostname
}

func (t *MysqlTarget) GetPort() string {
	return t.Port
}

func (t *MysqlTarget) GetType() string {
	return "mysql"
}

func (t *MysqlTarget) IsMtlsEnabled() bool {
	return t.MtlsEnabled
}

func (t *MysqlTarget) GetCACert() string {
	return t.CACert
}

func (t *MysqlTarget) GetClientCert() string {
	return t.ClientCert
}

func (t *MysqlTarget) GetClientKey() string {
	return t.ClientKey
}