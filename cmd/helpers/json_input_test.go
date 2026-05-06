package helpers

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestResolveJSONInput_Empty(t *testing.T) {
	got, err := ResolveJSONInput("")
	if err != nil {
		t.Fatalf("empty input should be (nil, nil); got err=%v", err)
	}
	if got != nil {
		t.Errorf("empty input should be nil; got %v", got)
	}
}

func TestResolveJSONInput_Literal(t *testing.T) {
	got, err := ResolveJSONInput(`{"type":"aws","region":"us-east-1"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := map[string]any{"type": "aws", "region": "us-east-1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v; want %v", got, want)
	}
}

func TestResolveJSONInput_File(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "payload.json")
	if err := os.WriteFile(tmp, []byte(`{"type":"jwt"}`), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	got, err := ResolveJSONInput("@" + tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["type"] != "jwt" {
		t.Errorf("got %v; want type=jwt", got)
	}
}

func TestResolveJSONInput_FileNotFound(t *testing.T) {
	_, err := ResolveJSONInput("@/definitely/does/not/exist.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "@/definitely/does/not/exist.json") {
		t.Errorf("expected path in error; got %q", err.Error())
	}
}

func TestResolveJSONInput_RejectsInvalidJSON(t *testing.T) {
	_, err := ResolveJSONInput(`{not valid json`)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput; got %v", err)
	}
}

func TestResolveJSONInput_RejectsEmptyFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(tmp, []byte(""), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	_, err := ResolveJSONInput("@" + tmp)
	if err == nil {
		t.Fatal("expected error for empty file")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput; got %v", err)
	}
}

func TestResolveJSONInput_TrimsWhitespace(t *testing.T) {
	got, err := ResolveJSONInput(`   {"x": 1}   `)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["x"] == nil {
		t.Errorf("expected parsed payload after trim; got %v", got)
	}
}

func TestResolveJSONInput_AcceptsNonObjectAsValid(t *testing.T) {
	// JSON arrays/scalars at top level — current contract is map[string]any
	// only, so they fail unmarshal. Pin that behavior so a future relaxation
	// is intentional.
	_, err := ResolveJSONInput(`[1,2,3]`)
	if err == nil {
		t.Fatal("expected unmarshal error for non-object root")
	}
}

func TestResolveJSONInput_RejectsNullRoot(t *testing.T) {
	// JSON null unmarshals into a nil map; without an explicit reject
	// callers would treat this as "no --json was provided" and silently
	// fall through to typed-flag mode.
	_, err := ResolveJSONInput(`null`)
	if err == nil {
		t.Fatal("expected error for JSON null root")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput; got %v", err)
	}
	if !strings.Contains(err.Error(), "null") {
		t.Errorf("expected error to mention null; got %q", err.Error())
	}
}

func TestResolveJSONInput_RejectsWhitespaceOnly(t *testing.T) {
	// "   \n\t  " trims to empty pre-parse, but a file containing only
	// whitespace would slip past the bare-string check. Verify the
	// post-trim len-zero gate catches it.
	tmp := filepath.Join(t.TempDir(), "ws.json")
	if err := os.WriteFile(tmp, []byte("   \n\t   "), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	_, err := ResolveJSONInput("@" + tmp)
	if err == nil {
		t.Fatal("expected error for whitespace-only file")
	}
}

func TestRejectFlagsWithJSON_Clean(t *testing.T) {
	err := RejectFlagsWithJSON(true, map[string]bool{
		"--type":   false,
		"--config": false,
	})
	if err != nil {
		t.Errorf("expected no error when no conflicting flags set; got %v", err)
	}
}

func TestRejectFlagsWithJSON_FlagsConflict(t *testing.T) {
	err := RejectFlagsWithJSON(true, map[string]bool{
		"--type":   true,
		"--config": false,
	})
	if err == nil {
		t.Fatal("expected error when --type set alongside --json")
	}
	if !errors.Is(err, ErrUsage) {
		t.Errorf("expected ErrUsage; got %v", err)
	}
	if !strings.Contains(err.Error(), "--type") {
		t.Errorf("expected error to name conflicting flag; got %q", err.Error())
	}
}

func TestRejectFlagsWithJSON_NoJSONNoCheck(t *testing.T) {
	// When --json wasn't provided, presence of typed flags is fine.
	err := RejectFlagsWithJSON(false, map[string]bool{
		"--type": true,
	})
	if err != nil {
		t.Errorf("expected no error when --json not provided; got %v", err)
	}
}

func TestRejectFlagsWithJSON_ListsAllConflicts(t *testing.T) {
	err := RejectFlagsWithJSON(true, map[string]bool{
		"--type":   true,
		"--config": true,
		"--source": true,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"--type", "--config", "--source"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("expected error to mention %q; got %q", want, err.Error())
		}
	}
}

func TestRejectFlagsWithJSON_DeterministicOrder(t *testing.T) {
	// Run multiple times to surface map-iteration-order non-determinism
	// if the implementation regresses on sort. The error message should
	// be byte-identical across runs.
	want := ""
	for i := 0; i < 20; i++ {
		err := RejectFlagsWithJSON(true, map[string]bool{
			"--zeta":  true,
			"--alpha": true,
			"--mu":    true,
		})
		if err == nil {
			t.Fatal("expected error")
		}
		got := err.Error()
		if i == 0 {
			want = got
			continue
		}
		if got != want {
			t.Fatalf("error message differs across runs: %q vs %q", want, got)
		}
	}
	if !strings.Contains(want, "--alpha, --mu, --zeta") {
		t.Errorf("expected sorted flag list; got %q", want)
	}
}

func TestMountPathFromArgOrPayload(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		payload map[string]any
		want    string
	}{
		{
			name: "positional arg wins",
			args: []string{"custom-mount"},
			payload: map[string]any{"type": "jwt"},
			want: "custom-mount/",
		},
		{
			name: "no arg, derive from payload type",
			args: nil,
			payload: map[string]any{"type": "jwt"},
			want: "jwt/",
		},
		{
			name: "no arg, no type → empty",
			args: nil,
			payload: map[string]any{},
			want: "",
		},
		{
			name: "no arg, nil payload → empty",
			args: nil,
			payload: nil,
			want: "",
		},
		{
			name: "trailing slash preserved",
			args: []string{"already-slashed/"},
			payload: nil,
			want: "already-slashed/",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := MountPathFromArgOrPayload(tt.args, tt.payload); got != tt.want {
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}
}

func TestMergeServerResponseInto_MarkersWinOverServerCollisions(t *testing.T) {
	// The motivating regression: if the server happens to return a key
	// that collides with a CLI marker (e.g. "created"), the marker must
	// remain authoritative — agents rely on its presence.
	data := map[string]any{}
	resData := map[string]any{
		"created": "yesterday", // server says weird things
		"name":    "from-server",
		"extra":   42,
	}
	markers := map[string]any{
		"name":    "from-cli",
		"created": true,
	}
	MergeServerResponseInto(data, resData, markers)
	if data["created"] != true {
		t.Errorf("marker `created` clobbered by server: %v", data["created"])
	}
	if data["name"] != "from-cli" {
		t.Errorf("marker `name` clobbered by server: %v", data["name"])
	}
	if data["extra"] != 42 {
		t.Errorf("non-conflicting server field dropped: %v", data["extra"])
	}
}

func TestMergeServerResponseInto_NilResource(t *testing.T) {
	data := map[string]any{}
	MergeServerResponseInto(data, nil, map[string]any{"path": "x", "created": true})
	if data["path"] != "x" || data["created"] != true {
		t.Errorf("markers should still apply when resource data is nil; got %v", data)
	}
}
