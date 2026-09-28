package helpers

import (
	"bytes"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/stephnangue/warden/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func samplePlan() *api.KeylessPlan {
	return &api.KeylessPlan{
		Source: &api.KeylessObject{
			Name: "aws-prod-keyless", Type: "aws", Replaces: "aws-prod",
			Config: map[string]string{"auth_method": "oidc_federation", "region": "us-east-1"},
		},
		Specs: []api.KeylessObject{{
			Name: "deploy-keyless", Type: "aws_access_keys", Source: "aws-prod-keyless", Replaces: "deploy",
			Config: map[string]string{"role_arn": "arn:aws:iam::1:role/it's", "subject_token_source": "warden_identity"},
			MaxTTL: 3600,
		}},
		Prerequisites: []api.KeylessPrerequisite{{Title: "IAM OIDC identity provider", Where: "account 1", Format: "shell", Body: "aws iam create-open-id-connect-provider"}},
		Leftovers:     []api.KeylessLeftover{{Kind: "IAM access key", ID: "AKIAOLD", WhereToDelete: "aws iam delete-access-key"}},
		Ready:         true,
	}
}

func TestRenderKeylessPlan_Table(t *testing.T) {
	var out bytes.Buffer
	SetOutputWriter(&out)
	SetOutputFormat("table")
	t.Cleanup(func() { ResetWriters(); SetOutputFormat("") })

	require.NoError(t, RenderKeylessPlan("source", "aws-prod", samplePlan()))
	got := out.String()

	assert.Contains(t, got, "(ready). Nothing has been written.")
	assert.Contains(t, got, "aws iam create-open-id-connect-provider")
	assert.Contains(t, got, "warden cred source create aws-prod-keyless -json '{")
	assert.Contains(t, got, "warden cred spec create deploy-keyless -json '{")
	assert.Contains(t, got, "deploy → deploy-keyless")
	assert.Contains(t, got, "warden cred spec delete deploy\n")
	assert.Contains(t, got, "warden cred source delete aws-prod\n")
	assert.Contains(t, got, "  - IAM access key (AKIAOLD)\n    aws iam delete-access-key\n", "the command sits on its own line")
	assert.Less(t, strings.Index(got, "spec delete"), strings.Index(got, "source delete"), "specs go before their source")
}

// The rendered create commands are pasted into a shell, so a single quote in a
// value must survive the quoting and the payload must parse back.
func TestRenderKeylessPlan_CreateCommandIsShellSafe(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	spec := samplePlan().Specs[0]
	cmd := createCommand("spec", spec.Name, specPayload(&spec))
	payload := strings.TrimPrefix(cmd, "warden cred spec create deploy-keyless -json ")

	var stdout bytes.Buffer
	c := exec.Command(sh, "-c", "printf '%s' "+payload)
	c.Stdout = &stdout
	require.NoError(t, c.Run())

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &decoded))
	assert.Equal(t, "arn:aws:iam::1:role/it's", decoded["config"].(map[string]any)["role_arn"])
	assert.Equal(t, float64(3600), decoded["max_ttl"])
}

func TestRenderKeylessPlan_NothingToCreate(t *testing.T) {
	var out bytes.Buffer
	SetOutputWriter(&out)
	SetOutputFormat("table")
	t.Cleanup(func() { ResetWriters(); SetOutputFormat("") })

	require.NoError(t, RenderKeylessPlan("spec", "static-key", &api.KeylessPlan{
		Specs:    []api.KeylessObject{},
		Blockers: []string{"on the local source"},
	}))
	got := out.String()
	assert.Contains(t, got, "(blocked)")
	assert.Contains(t, got, "on the local source")
	assert.NotContains(t, got, "1. ", "no steps when nothing would be created")
}

func TestRenderKeylessPlan_JSON(t *testing.T) {
	var out bytes.Buffer
	SetOutputWriter(&out)
	SetOutputFormat("json")
	t.Cleanup(func() { ResetWriters(); SetOutputFormat("") })

	require.NoError(t, RenderKeylessPlan("source", "aws-prod", samplePlan()))
	var decoded api.KeylessPlan
	require.NoError(t, json.Unmarshal(out.Bytes(), &decoded))
	assert.Equal(t, *samplePlan(), decoded)
}

func TestKeylessPlanInput(t *testing.T) {
	in, err := KeylessPlanInput("", "vault-wif", map[string]string{"jwt_role": "warden"},
		map[string]string{"app-db/name": "app-db-wif", "app-db/role_arn": "r"})
	require.NoError(t, err)
	assert.Equal(t, &api.KeylessPlanInput{
		NewName: "vault-wif",
		Target:  map[string]string{"jwt_role": "warden"},
		Specs:   map[string]map[string]string{"app-db": {"name": "app-db-wif", "role_arn": "r"}},
	}, in)

	_, err = KeylessPlanInput("", "", nil, map[string]string{"no-slash": "x"})
	assert.True(t, errors.Is(err, ErrUsage))

	in, err = KeylessPlanInput(`{"new_name":"x","specs":{"a":{"name":"b"}}}`, "", nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "x", in.NewName)
	assert.Equal(t, "b", in.Specs["a"]["name"])

	_, err = KeylessPlanInput(`{"new_name":"x"}`, "y", nil, nil)
	assert.Error(t, err, "-json excludes the flags")
}
