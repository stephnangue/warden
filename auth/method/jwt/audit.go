package jwt

import (
	"maps"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/auth/token"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

func (m *JWTAuthMethod) auditResponse(w http.ResponseWriter, r *http.Request, body *JWTLoginRequest, clientToken *audit.Token, token *token.Token, authData *token.AuthData, statusCode int, message string, errorMessage string) bool {
	var auth *audit.Auth
	if authData != nil && clientToken != nil {
		auth = m.buildAuth(clientToken, authData.RoleName, authData.PrincipalID)
	} else {
		if authData == nil {
			auth = m.buildAuth(clientToken, "", "")
		}
	}
	entry := audit.LogEntry{
		Type:      string(audit.EntryTypeResponse),
		Timestamp: time.Now(),
		Auth:      auth,
		Request:   m.buildRequest(r, body),
		Response:  m.buildResponse(w, r, token, statusCode, message),
		Error:     errorMessage,
	}
	ok, err := m.auditAccess.LogResponse(r.Context(), &entry)
	if err != nil {
		m.logger.Error("failed to audit response", logger.Err(err), logger.String("request_id", middleware.GetReqID(r.Context())))
	}
	return ok
}

func (m *JWTAuthMethod) buildRequest(r *http.Request, body *JWTLoginRequest) *audit.Request {
	clientIP := r.RemoteAddr
	// Remove port if present
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}
	var data map[string]interface{}
	if body != nil {
		data = body.ToMap()
	}

	headersCopy := make(http.Header, len(r.Header))
	maps.Copy(headersCopy, r.Header)

	return &audit.Request{
		ID:            middleware.GetReqID(r.Context()),
		Method:        r.Method,
		ClientIP:      clientIP,
		Path:          r.Context().Value(logical.OriginalPath).(string),
		Headers:       headersCopy,
		MountType:     m.GetType(),
		MountPath:     m.mountPath,
		MountAccessor: m.accessor,
		MountClass:    m.backendClass,
		Data:          data,
	}
}

func (m *JWTAuthMethod) buildResponse(w http.ResponseWriter, r *http.Request, token *token.Token, statusCode int, message string) *audit.Response {
	// convert map[string]string to map[string]interface{} for the audit response
	var data map[string]interface{}
	if token != nil && token.Data != nil {
		data = make(map[string]interface{}, len(token.Data))
		for k, v := range token.Data {
			data[k] = v
		}
	}

	resp := audit.Response{
		Data:          data,
		StatusCode:    statusCode,
		Message:       message,
		MountType:     m.GetType(),
		MountAccessor: m.accessor,
		MountPath:     m.mountPath,
		MountClass:    m.backendClass,
	}

	return &resp
}

func (m *JWTAuthMethod) buildAuth(clientToken *audit.Token, roleName, principalID string) *audit.Auth {
	auth := audit.Auth{
		ClientToken: clientToken,
		RoleName:    roleName,
		PrincipalID: principalID,
	}
	return &auth
}
