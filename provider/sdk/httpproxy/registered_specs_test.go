// This file is an external test package on purpose: it imports the provider
// packages, which themselves import httpproxy.
package httpproxy_test

import (
	"testing"

	"github.com/stephnangue/warden/provider/ansible_tower"
	"github.com/stephnangue/warden/provider/anthropic"
	"github.com/stephnangue/warden/provider/atlassian"
	"github.com/stephnangue/warden/provider/cohere"
	"github.com/stephnangue/warden/provider/datadog"
	"github.com/stephnangue/warden/provider/dynatrace"
	"github.com/stephnangue/warden/provider/elastic"
	"github.com/stephnangue/warden/provider/github"
	"github.com/stephnangue/warden/provider/gitlab"
	"github.com/stephnangue/warden/provider/grafana"
	"github.com/stephnangue/warden/provider/honeycomb"
	"github.com/stephnangue/warden/provider/kubernetes"
	"github.com/stephnangue/warden/provider/mcp"
	"github.com/stephnangue/warden/provider/mistral"
	"github.com/stephnangue/warden/provider/newrelic"
	"github.com/stephnangue/warden/provider/openai"
	"github.com/stephnangue/warden/provider/pagerduty"
	"github.com/stephnangue/warden/provider/prometheus"
	"github.com/stephnangue/warden/provider/rest"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
	"github.com/stephnangue/warden/provider/sentry"
	"github.com/stephnangue/warden/provider/servicenow"
	"github.com/stephnangue/warden/provider/slack"
	"github.com/stephnangue/warden/provider/splunk"
	"github.com/stephnangue/warden/provider/tfe"
	"github.com/stretchr/testify/assert"
)

// TestRegisteredProviderSpecsValid asserts every shipped spec satisfies the
// contract the factory enforces. A provider added without an extractor fails
// here rather than at the first request it serves; a provider added without
// being listed here is caught by the count.
func TestRegisteredProviderSpecsValid(t *testing.T) {
	specs := map[string]*httpproxy.ProviderSpec{
		"ansible_tower": ansible_tower.Spec,
		"anthropic":     anthropic.Spec,
		"atlassian":     atlassian.Spec,
		"cohere":        cohere.Spec,
		"datadog":       datadog.Spec,
		"dynatrace":     dynatrace.Spec,
		"elastic":       elastic.Spec,
		"github":        github.Spec,
		"gitlab":        gitlab.Spec,
		"grafana":       grafana.Spec,
		"honeycomb":     honeycomb.Spec,
		"kubernetes":    kubernetes.Spec,
		"mcp":           mcp.Spec,
		"mistral":       mistral.Spec,
		"newrelic":      newrelic.Spec,
		"openai":        openai.Spec,
		"pagerduty":     pagerduty.Spec,
		"prometheus":    prometheus.Spec,
		"rest":          rest.Spec,
		"sentry":        sentry.Spec,
		"servicenow":    servicenow.Spec,
		"slack":         slack.Spec,
		"splunk":        splunk.Spec,
		"tfe":           tfe.Spec,
	}

	for name, spec := range specs {
		t.Run(name, func(t *testing.T) {
			assert.NoError(t, httpproxy.ValidateSpec(spec))
		})
	}
}
