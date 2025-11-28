package mysql

import (
	"context"
	"fmt"

	mysqlClient "github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/stephnangue/warden/authorize"
	"github.com/stephnangue/warden/cred"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/target"
)

type MysqlHandler struct {
	principalID string // the principal using this connection
	roleName    string // the covenant role used by the principal

	connProvider ConnProvider

	roles       *authorize.RoleRegistry
	credSources *cred.CredSourceRegistry
	targets     *target.TargetRegistry

	logger logger.Logger
}

func NewMysqlHandler(roles *authorize.RoleRegistry, credSources *cred.CredSourceRegistry, targets *target.TargetRegistry, logger logger.Logger) (*MysqlHandler, error) {
	return &MysqlHandler{
		roles:       roles,
		credSources: credSources,
		targets:     targets,
		logger:      logger,
	}, nil
}

// getBackendConn returns a backend connection
// it creates the connection provider lazily if needed
func (h *MysqlHandler) getBackendConn() (*BackendConn, error) {
	if h.connProvider == nil {
		role, ok := h.roles.GetRole(h.roleName)
		if !ok {
			return nil, fmt.Errorf("role named '%s' not found", h.roleName)
		}
		credSource, ok := h.credSources.GetSource(role.CredSourceName)
		if !ok {
			return nil, fmt.Errorf("credential source named '%s' not found", role.CredSourceName)
		}
		target, ok := h.targets.GetTarget(role.TargetName)
		if !ok {
			return nil, fmt.Errorf("target named '%s' not found", role.TargetName)
		}

		switch role.Type {
		case "static_database_userpass":
			provider, err := NewStaticConnProvider(role, credSource, target, h.logger.WithSubsystem("conn.provider"))
			if err != nil {
				return nil, err
			}
			h.connProvider = provider
		case "dynamic_database_userpass":
			provider, err := NewDynamicConnProvider(role, credSource, target, h.logger.WithSubsystem("conn.provider"))
			if err != nil {
				return nil, err
			}
			h.connProvider = provider
		default:
			return nil, fmt.Errorf("no connection provider found for role type '%s'", role.Type)
		}
	}

	return h.connProvider.GetConn(context.Background())
}

// UseDB changes the current database
func (h *MysqlHandler) UseDB(dbName string) error {
	h.logger.Tracef("USE DB: %s", dbName)

	conn, err := h.getBackendConn()
	defer conn.Release()
	if err != nil {
		return err
	}

	_, err = conn.Execute(fmt.Sprintf("USE `%s`", dbName))

	return err
}

// HandleQuery handles a query command
func (h *MysqlHandler) HandleQuery(query string) (*mysql.Result, error) {
	h.logger.Tracef("Query: %s", query)

	conn, err := h.getBackendConn()
	defer conn.Release()
	if err != nil {
		h.logger.Error("connection error", logger.Err(err))
		return nil, err
	}

	result, err := conn.Execute(query)
	if err != nil {
		h.logger.Error("query error", logger.Err(err))
		return nil, err
	}

	h.logger.Trace("query OK", logger.Int64("rows_affected", int64(result.AffectedRows)), logger.Int64("rows_returned", int64(len(result.Values))))
	return result, nil
}

// HandleFieldList handles a field list command
func (h *MysqlHandler) HandleFieldList(table string, fieldWildcard string) ([]*mysql.Field, error) {
	h.logger.Tracef("Field List: table=%s, wildcard=%s", table, fieldWildcard)

	conn, err := h.getBackendConn()
	defer conn.Release()
	if err != nil {
		return nil, err
	}

	// Use SHOW COLUMNS to get field information
	query := fmt.Sprintf("SHOW COLUMNS FROM `%s`", table)
	if fieldWildcard != "" {
		query += fmt.Sprintf(" LIKE '%s'", fieldWildcard)
	}

	result, err := conn.Execute(query)
	if err != nil {
		return nil, err
	}

	// Convert result to Field list
	fields := make([]*mysql.Field, 0, len(result.Values))
	for _, row := range result.Values {
		field := &mysql.Field{
			Name: row[0].AsString(),
			Type: mysql.MYSQL_TYPE_VAR_STRING, // Simplified
		}
		fields = append(fields, field)
	}

	return fields, nil
}

// HandleStmtPrepare handles statement preparation
func (h *MysqlHandler) HandleStmtPrepare(query string) (params int, columns int, context interface{}, err error) {
	h.logger.Tracef("Prepare: %s", query)

	conn, err := h.getBackendConn()
	defer conn.Release()
	if err != nil {
		return 0, 0, nil, err
	}

	stmt, err := conn.Prepare(query)
	if err != nil {
		h.logger.Error("prepare error", logger.Err(err))
		return 0, 0, nil, err
	}

	return stmt.ParamNum(), stmt.ColumnNum(), stmt, nil
}

// HandleStmtExecute handles prepared statement execution
func (h *MysqlHandler) HandleStmtExecute(context interface{}, query string, args []interface{}) (*mysql.Result, error) {
	h.logger.Tracef("Execute prepared: %s with %d args", query, len(args))

	stmt, ok := context.(*mysqlClient.Stmt)
	if !ok {
		return nil, fmt.Errorf("invalid statement context")
	}

	result, err := stmt.Execute(args...)
	if err != nil {
		h.logger.Error("execute error", logger.Err(err))
		return nil, err
	}

	return result, nil
}

// HandleStmtClose handles prepared statement closing
func (h *MysqlHandler) HandleStmtClose(context interface{}) error {
	h.logger.Trace("Close prepared statement")

	stmt, ok := context.(*mysqlClient.Stmt)
	if !ok {
		return fmt.Errorf("invalid statement context")
	}

	return stmt.Close()
}

// HandleOtherCommand handles other MySQL commands
func (h *MysqlHandler) HandleOtherCommand(cmd byte, data []byte) error {
	h.logger.Tracef("Other command: %d, data length: %d", cmd, len(data))
	return nil
}

func (h *MysqlHandler) SetPrincipal(principalID string) {
	h.principalID = principalID
}

func (h *MysqlHandler) SetRole(roleName string) {
	h.roleName = roleName
}

func (h *MysqlHandler) Stop() {
	if h.connProvider != nil {
		h.connProvider.Stop()
	}
}
