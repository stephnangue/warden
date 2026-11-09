package processor

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stephnangue/warden/logical"
)

// bedrockContext is a request for rawPath under a mount at mountPrefix, as
// the router hands it to a processor: the URL keeps the client's escaping,
// the logical path is mount-relative and decoded.
func bedrockContext(t *testing.T, service, region, mountPrefix, rawPath string) *ProcessorContext {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://localhost:8400"+mountPrefix+rawPath, nil)
	path, cut := strings.CutPrefix(req.URL.Path, mountPrefix)
	if !cut {
		t.Fatalf("%q does not start with %q", req.URL.Path, mountPrefix)
	}
	return &ProcessorContext{
		LogicalRequest: &logical.Request{
			HTTPRequest: req,
			Path:        strings.TrimPrefix(path, "/"),
		},
		Service: service,
		Region:  region,
	}
}

func TestBedrockRuntimeProcessor_RoutesRuntimeOperations(t *testing.T) {
	proc := NewBedrockRuntimeProcessor(nil, nil)
	tests := []struct {
		name     string
		rawPath  string
		wantPath string
	}{
		{"Converse", "/model/amazon.nova-lite-v1%3A0/converse", "/model/amazon.nova-lite-v1%3A0/converse"},
		{"ConverseStream", "/model/amazon.nova-lite-v1%3A0/converse-stream", "/model/amazon.nova-lite-v1%3A0/converse-stream"},
		{"InvokeModel", "/model/amazon.nova-lite-v1%3A0/invoke", "/model/amazon.nova-lite-v1%3A0/invoke"},
		{"InvokeModelWithResponseStream", "/model/amazon.nova-lite-v1%3A0/invoke-with-response-stream", "/model/amazon.nova-lite-v1%3A0/invoke-with-response-stream"},
		{"CountTokens", "/model/amazon.nova-lite-v1%3A0/count-tokens", "/model/amazon.nova-lite-v1%3A0/count-tokens"},
		{"StartAsyncInvoke", "/async-invoke", "/async-invoke"},
		{"GetAsyncInvoke", "/async-invoke/arn%3Aaws%3Abedrock%3Aus-east-1%3A123456789012%3Aasync-invoke%2Fabc", "/async-invoke/arn%3Aaws%3Abedrock%3Aus-east-1%3A123456789012%3Aasync-invoke%2Fabc"},
		{"ApplyGuardrail", "/guardrail/g1/version/1/apply", "/guardrail/g1/version/1/apply"},
		{"InvokeGuardrailChecks", "/guardrail-checks/invoke", "/guardrail-checks/invoke"},
		// An inference profile ARN carries an escaped '/', which must not
		// become a path separator on the way out.
		{"Converse on an inference profile ARN",
			"/model/arn%3Aaws%3Abedrock%3Aus-east-1%3A123456789012%3Ainference-profile%2Fus.amazon.nova-lite-v1%3A0/converse",
			"/model/arn%3Aaws%3Abedrock%3Aus-east-1%3A123456789012%3Ainference-profile%2Fus.amazon.nova-lite-v1%3A0/converse"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := bedrockContext(t, "bedrock", "us-east-1", "/v1/bedrock", "/gateway"+tt.rawPath)
			if !proc.CanProcess(ctx) {
				t.Fatalf("CanProcess(%s) = false, want true", tt.rawPath)
			}
			result, err := proc.Process(ctx)
			if err != nil {
				t.Fatalf("Process: %v", err)
			}
			if result.TargetURL != "https://bedrock-runtime.us-east-1.amazonaws.com" {
				t.Errorf("TargetURL = %q", result.TargetURL)
			}
			if result.TargetHost != "bedrock-runtime.us-east-1.amazonaws.com" {
				t.Errorf("TargetHost = %q", result.TargetHost)
			}
			if result.Service != "bedrock" {
				t.Errorf("Service = %q, want the signing name bedrock", result.Service)
			}
			if result.TransformedPath != tt.wantPath || !result.TransformedPathIsEncoded {
				t.Errorf("path = %q (encoded %v), want %q (encoded)", result.TransformedPath, result.TransformedPathIsEncoded, tt.wantPath)
			}
		})
	}
}

// The control plane signs as "bedrock" too; its calls are left to the
// generic processor.
func TestBedrockRuntimeProcessor_LeavesControlPlane(t *testing.T) {
	proc := NewBedrockRuntimeProcessor(nil, nil)
	for _, rawPath := range []string{
		"/foundation-models",
		"/foundation-models/amazon.nova-lite-v1%3A0",
		"/guardrails",
		"/guardrails/g1",
		"/model-invocation-jobs",
		"/model-invocation-job/j1/stop",
		"/model-customization-jobs",
		"/inference-profiles",
		"/async-invokes",
		"/",
	} {
		ctx := bedrockContext(t, "bedrock", "us-east-1", "/v1/bedrock", "/gateway"+rawPath)
		if proc.CanProcess(ctx) {
			t.Errorf("CanProcess(%s) = true, want false", rawPath)
		}
	}
	// Another service's request on a runtime-looking path is not Bedrock's.
	if proc.CanProcess(bedrockContext(t, "sagemaker", "us-east-1", "/v1/bedrock", "/gateway/model/x/invoke")) {
		t.Error("CanProcess claimed a sagemaker request")
	}
}

func TestBedrockRuntimeProcessor_Partitions(t *testing.T) {
	proc := NewBedrockRuntimeProcessor(nil, nil)
	for region, want := range map[string]string{
		"eu-central-1":  "bedrock-runtime.eu-central-1.amazonaws.com",
		"cn-north-1":    "bedrock-runtime.cn-north-1.amazonaws.com.cn",
		"us-gov-west-1": "bedrock-runtime.us-gov-west-1.amazonaws.com",
	} {
		result, err := proc.Process(bedrockContext(t, "bedrock", region, "/v1/bedrock", "/gateway/model/m/converse"))
		if err != nil {
			t.Fatalf("Process(%s): %v", region, err)
		}
		if result.TargetHost != want {
			t.Errorf("%s: TargetHost = %q, want %q", region, result.TargetHost, want)
		}
	}
}

// The region is the client's own and becomes part of the upstream host, so
// one that is not a region's shape is refused rather than sent anywhere.
func TestBedrockRuntimeProcessor_RefusesRegionThatIsNotARegion(t *testing.T) {
	proc := NewBedrockRuntimeProcessor(nil, nil)
	for _, region := range []string{"attacker.example#", "us-east-1.evil", "us-east-1@evil", "aws-global", "US-EAST-1", ""} {
		if _, err := proc.Process(bedrockContext(t, "bedrock", region, "/v1/bedrock", "/gateway/model/m/converse")); err == nil {
			t.Errorf("Process accepted region %q", region)
		}
	}
}

// The mount may sit under a namespace, and a namespace or mount may itself be
// named gateway: the AWS path is still the one after the mount.
func TestBedrockRuntimeProcessor_MountPrefixes(t *testing.T) {
	proc := NewBedrockRuntimeProcessor(nil, nil)
	for _, mountPrefix := range []string{"/v1/bedrock", "/v1/team-a/bedrock", "/v1/gateway/bedrock", "/v1/team/gateway"} {
		ctx := bedrockContext(t, "bedrock", "us-east-1", mountPrefix, "/gateway/model/amazon.nova-lite-v1%3A0/converse")
		result, err := proc.Process(ctx)
		if err != nil {
			t.Fatalf("%s: Process: %v", mountPrefix, err)
		}
		if result.TransformedPath != "/model/amazon.nova-lite-v1%3A0/converse" || !result.TransformedPathIsEncoded {
			t.Errorf("%s: path = %q (encoded %v)", mountPrefix, result.TransformedPath, result.TransformedPathIsEncoded)
		}
	}
}

// When the logical path does not end the URL path, the decoded path is sent,
// as the generic processor would.
func TestBedrockRuntimeProcessor_FallsBackToDecodedPath(t *testing.T) {
	proc := NewBedrockRuntimeProcessor(nil, nil)
	ctx := bedrockContext(t, "bedrock", "us-east-1", "/v1/bedrock", "/gateway/model/m%3A0/converse")
	ctx.LogicalRequest.Path = "gateway/model/m:0/converse/"
	result, err := proc.Process(ctx)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if result.TransformedPath != "/model/m:0/converse/" || result.TransformedPathIsEncoded {
		t.Errorf("path = %q (encoded %v), want the decoded logical path", result.TransformedPath, result.TransformedPathIsEncoded)
	}
}

// Through the registry: runtime calls reach this processor, control plane
// calls the generic one and its bedrock.<region> host.
func TestBedrockRuntimeProcessor_Registry(t *testing.T) {
	registry := NewProcessorRegistry()
	registry.Register(NewBedrockRuntimeProcessor(nil, nil))
	registry.Register(NewGenericAWSProcessor(nil, nil))

	runtime := bedrockContext(t, "bedrock", "us-east-1", "/v1/bedrock", "/gateway/model/m/converse")
	if got := registry.FindProcessor(runtime).Name(); got != "bedrock-runtime" {
		t.Errorf("runtime call went to %q", got)
	}

	control := bedrockContext(t, "bedrock", "us-east-1", "/v1/bedrock", "/gateway/foundation-models")
	proc := registry.FindProcessor(control)
	if proc.Name() != "generic-aws" {
		t.Fatalf("control plane call went to %q", proc.Name())
	}
	result, err := proc.Process(control)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if result.TargetHost != "bedrock.us-east-1.amazonaws.com" {
		t.Errorf("control plane TargetHost = %q", result.TargetHost)
	}
}
