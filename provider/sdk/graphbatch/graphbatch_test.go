package graphbatch

import "testing"

func TestIsBatchPath(t *testing.T) {
	refused := []string{
		"/v1.0/$batch",
		"/beta/$batch",
		"/V1.0/$Batch",
		"/v1.0/$BATCH/",
		"/v1.0//$batch",
		"/v1.0/me/../$batch",
		"v1.0/$batch",
		"/$batch",
		"/v1.0/./$batch",
		`/v1.0\$batch`,
		`/v1.0/me\..\$batch`,
		"/v1.0/$batch;x=1",
		"/v1.0/$BATCH;",
	}
	for _, p := range refused {
		if !IsBatchPath(p) {
			t.Errorf("IsBatchPath(%q) = false, want true", p)
		}
	}

	allowed := []string{
		"/v1.0/me/messages",
		"/v1.0/me/messages?$batch=1",
		"/v1.0/batchjobs",
		"/v1.0/me/$batchy",
		"/v1.0/me/x$batch",
		"",
		"/",
	}
	for _, p := range allowed {
		if IsBatchPath(p) {
			t.Errorf("IsBatchPath(%q) = true, want false", p)
		}
	}
}

func TestIsGraphHost(t *testing.T) {
	for _, h := range []string{"graph.microsoft.com", "GRAPH.microsoft.com", "graph.microsoft.com.", "graph.microsoft.us",
		"dod-graph.microsoft.us", "microsoftgraph.chinacloudapi.cn", "x.graph.microsoft.com"} {
		if !IsGraphHost(h) {
			t.Errorf("IsGraphHost(%q) = false, want true", h)
		}
	}
	for _, h := range []string{"management.azure.com", "graph.microsoft.com.evil.example", "notgraph.microsoft.com",
		"microsoft.com", ""} {
		if IsGraphHost(h) {
			t.Errorf("IsGraphHost(%q) = true, want false", h)
		}
	}

	got := Hosts()
	got[0] = "changed"
	if Hosts()[0] == "changed" {
		t.Error("Hosts must return a copy")
	}
}
