package core

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/internal/namespace"
)

// msgraphCookbook is the policy cookbook the msgraph docs and skill publish. Each
// recipe must pass the same parse — HCL, CEL type check and cost estimate — that
// `warden policy write` runs, so the published policies cannot drift into ones
// an operator cannot write.
var msgraphCookbook = map[string]string{
	"read-only own data": `
path "msgraph/role/+/gateway/v1.0/me" {
  capabilities = ["read"]
  condition    = "user.present == true"
}

path "msgraph/role/+/gateway/v1.0/me/*" {
  capabilities = ["read"]
  condition    = "user.present == true"
}
`,
	"page size and projection": `
path "msgraph/role/+/gateway/v1.0/me/messages" {
  capabilities = ["read"]
  condition    = <<-CEL
    user.present &&
    '$select' in request.data && size(request.data['$select']) > 0 &&
    (!('$top' in request.data) || int(request.data['$top']) <= 25)
  CEL
}
`,
	"internal recipients only": `
path "msgraph/role/+/gateway/v1.0/me/sendMail" {
  capabilities = ["create"]
  condition    = <<-CEL
    user.present &&
    has(request.data.message) &&
    request.data.message.toRecipients.all(r, r.emailAddress.address.endsWith('@contoso.com')) &&
    (!has(request.data.message.ccRecipients) ||
      request.data.message.ccRecipients.all(r, r.emailAddress.address.endsWith('@contoso.com'))) &&
    (!has(request.data.message.bccRecipients) ||
      request.data.message.bccRecipients.all(r, r.emailAddress.address.endsWith('@contoso.com'))) &&
    size(request.data.message.toRecipients)
      + (has(request.data.message.ccRecipients) ? size(request.data.message.ccRecipients) : 0)
      + (has(request.data.message.bccRecipients) ? size(request.data.message.bccRecipients) : 0) <= 10
  CEL
}
`,
	"internal-only meetings": `
path "msgraph/role/+/gateway/v1.0/me/events" {
  capabilities = ["read", "create"]
  condition    = <<-CEL
    request.operation == 'read' || (
      user.present &&
      has(request.data.subject) &&
      (!has(request.data.attendees) ||
        request.data.attendees.all(a, a.emailAddress.address.endsWith('@contoso.com'))) &&
      !request.data.?isOnlineMeeting.orValue(false)
    )
  CEL
}

path "msgraph/role/+/gateway/v1.0/me/events/+" {
  capabilities = ["read", "patch"]
  condition    = <<-CEL
    request.operation == 'read' || (
      user.present &&
      (!has(request.data.attendees) ||
        request.data.attendees.all(a, a.emailAddress.address.endsWith('@contoso.com'))) &&
      !request.data.?isOnlineMeeting.orValue(false)
    )
  CEL
}
`,
	"teams one channel": `
path "msgraph/role/+/gateway/v1.0/teams/team-1/channels/channel-1/messages" {
  capabilities = ["read", "create"]
  condition    = <<-CEL
    request.operation == 'read' || (
      user.present &&
      has(request.data.body) &&
      request.data.body.contentType == 'text' &&
      size(request.data.body.content) <= 2000 &&
      !has(request.data.mentions) &&
      now.getDayOfWeek('Europe/Paris') in [1, 2, 3, 4, 5] &&
      now.getHours('Europe/Paris') >= 8 &&
      now.getHours('Europe/Paris') < 19
    )
  CEL
}

path "msgraph/role/+/gateway/v1.0/me/chats*" {
  capabilities = ["read"]
  condition    = "user.present == true"
}
`,
	"sharepoint one site": `
path "msgraph/role/+/gateway/v1.0/sites/site-1/*" {
  capabilities = ["read"]
  condition    = "user.present && user.metadata.department == 'Finance'"
}
`,
	"deletes from a dedicated role": `
path "msgraph/role/mail-janitor/gateway/v1.0/me/messages/+" {
  capabilities = ["read", "delete"]
  condition    = "request.operation == 'read' || (user.present && cidrContains('10.0.0.0/8', request.client_ip))"
}
`,
	"off beta and other users": `
path "msgraph/role/+/gateway/beta/*" {
  capabilities = ["deny"]
}

path "msgraph/role/+/gateway/v1.0/users/*" {
  capabilities = ["deny"]
}
`,
	"app-only reads, user-gated writes": `
path "msgraph/role/+/gateway/v1.0/groups/+/calendar/events*" {
  capabilities = ["read", "create"]
  condition    = "request.operation == 'read' || (user.present && user.metadata.client_app == 'app-1')"
}
`,
	"intune devices": `
path "msgraph/role/+/gateway/v1.0/deviceManagement/managedDevices*" {
  capabilities = ["read"]
  condition    = "user.present == true"
}

path "msgraph/role/+/gateway/v1.0/deviceManagement/managedDevices/+/syncDevice" {
  capabilities = ["create"]
  condition    = "user.present == true"
}

path "msgraph/role/intune-admin/gateway/v1.0/deviceManagement/managedDevices/+/retire" {
  capabilities = ["create"]
  condition    = <<-CEL
    user.present &&
    cidrContains('10.0.0.0/8', request.client_ip) &&
    now.getDayOfWeek('Europe/Paris') in [1, 2, 3, 4, 5]
  CEL
}

path "msgraph/role/+/gateway/beta/deviceManagement/deviceCompliancePolicies*" {
  capabilities = ["read"]
  condition    = "user.present == true"
}
`,
}

func TestMSGraphCookbookPoliciesCompile(t *testing.T) {
	for name, rules := range msgraphCookbook {
		t.Run(name, func(t *testing.T) {
			_, err := ParseCBPPolicy(namespace.RootNamespace, rules)
			require.NoError(t, err)
		})
	}
}

// The rule the cookbook warns about: iterating an orValue() result has no size
// bound, so the cost estimate refuses it at write time. If this ever compiles,
// the cookbook's has()-guarded form is no longer needed and the warning is stale.
func TestMSGraphCookbook_IteratingOrValueIsRefused(t *testing.T) {
	_, err := ParseCBPPolicy(namespace.RootNamespace, `
path "msgraph/role/+/gateway/v1.0/me/sendMail" {
  capabilities = ["create"]
  condition    = "request.data.message.?ccRecipients.orValue([]).all(r, r.emailAddress.address.endsWith('@contoso.com'))"
}
`)
	require.Error(t, err)
}
