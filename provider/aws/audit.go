package aws

import (
	"bytes"
	"io"
	"maps"
	"net"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/go-chi/chi/middleware"
	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/auth/token"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

func (p *AWSProvider) auditResponse(res *http.Response, r *http.Request, clientToken *audit.Token, awsCreds *aws.Credentials, token *token.Token, roleName, principalID string, statusCode int, message string, errorMessage string, targetURL string, metadata map[string]interface{}) bool {
	var auth *audit.Auth
	if clientToken != nil {
		data := make(map[string]string, len(clientToken.Data))
		maps.Copy(data, clientToken.Data)
		auth = p.buildAuth(&audit.Token{
			Type: clientToken.Type,
			TokenID: clientToken.TokenID,
			TokenTTL: clientToken.TokenTTL,
			TokenIssuer: clientToken.TokenIssuer,
			Data: data,
		}, roleName, principalID)
	}

	var responseCred *audit.Cred
	if token != nil && awsCreds != nil {
		responseCred = p.buildCred(token, awsCreds)
	}

	entry := audit.LogEntry{
		Type:      string(audit.EntryTypeResponse),
		Timestamp: time.Now(),
		Auth:      auth,
		Request:   p.buildRequest(r, targetURL),
		Response:  p.buildResponse(res, responseCred, statusCode, message),
		Error:     errorMessage,
		Metadata:  metadata,
	}
	ok, err := p.auditAccess.LogResponse(r.Context(), &entry)
	if err != nil {
		p.logger.Error("failed to audit response", logger.Err(err), logger.String("request_id", middleware.GetReqID(r.Context())))
	}
	return ok
}

func (p *AWSProvider) buildRequest(r *http.Request, targetURL string) *audit.Request {
	clientIP := r.RemoteAddr
	// Remove port if present
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}

	// Copy headers to prevent audit formatters from modifying the original request
	headersCopy := make(http.Header, len(r.Header))
	maps.Copy(headersCopy, r.Header)

	return &audit.Request{
		ID:            middleware.GetReqID(r.Context()),
		Method:        r.Method,
		ClientIP:      clientIP,
		Path:          r.Context().Value(logical.OriginalPath).(string),
		Headers:       headersCopy,
		MountType:     p.GetType(),
		MountPath:     p.mountPath,
		MountAccessor: p.accessor,
		MountClass:    p.backendClass,
		TargetUrl:     targetURL,
	}
}

func (p *AWSProvider) buildResponse(res *http.Response, cred *audit.Cred, statusCode int, message string) *audit.Response {
	// Read body for logging
	bodyBytes, _ := io.ReadAll(res.Body)
	
	// Restore body
	res.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	var data map[string]interface{}
	if len(bodyBytes) > 0 {
		data = map[string]interface{}{
			"body": string(bodyBytes),
		}
	}
	headerCopy := make(http.Header, len(res.Header))
	maps.Copy(headerCopy, res.Header)
	resp := audit.Response{
		Cred:          cred,
		StatusCode:    statusCode,
		Message:       message,
		MountType:     p.GetType(),
		MountAccessor: p.accessor,
		MountPath:     p.mountPath,
		MountClass:    p.backendClass,
		Headers:       headerCopy,
		Data:          data,
	}

	return &resp
}

func (p *AWSProvider) buildAuth(clientToken *audit.Token, roleName, principalID string) *audit.Auth {
	auth := audit.Auth{
		ClientToken: clientToken,
		RoleName:    roleName,
		PrincipalID: principalID,
	}
	return &auth
}

func (p *AWSProvider) buildCred(token *token.Token, awsCreds *aws.Credentials) *audit.Cred {
	// Determine credential type
	credType := string(token.Type)

	if awsCreds.CanExpire {
		return &audit.Cred{
			Type:     credType,
			LeaseTTL: int64(time.Until(awsCreds.Expires).Seconds()),
			TokenID:  token.ID,
			Origin:   awsCreds.Source,
			Data:     map[string]string{
				"access_key_id":     awsCreds.AccessKeyID,
				"secret_access_key": awsCreds.SecretAccessKey,
				"session_token":     awsCreds.SessionToken,
			},
		}
	} else {
		return &audit.Cred{
			Type:     credType,
			TokenID:  token.ID,
			Origin:   awsCreds.Source,
			Data:     map[string]string{
				"access_key_id":     awsCreds.AccessKeyID,
				"secret_access_key": awsCreds.SecretAccessKey,
			},
		}
	}
}
