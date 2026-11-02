package helps

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

func TestCodexAccountFingerprintMatchesPlugin(t *testing.T) {
	auth := &cliproxyauth.Auth{ID: "first-file", Metadata: map[string]any{"account_id": "acct-one", "chatgpt_user_id": "user-one"}}
	const wantSeed = "a5efb09d-84cf-4e5e-80ce-5939e3387ac3"
	const wantInstall = "866b0bfd-ca88-43f8-aaf7-02053e402033"
	const wantUA = "codex-tui/0.166.0 (Mac OS 26.5.1; arm64) vscode/1.104.2 (codex-tui; 0.166.0)"
	assertIdentity := func(auth *cliproxyauth.Auth) {
		t.Helper()
		got := CodexIdentityForAuth(auth)
		if CodexAccountIdentitySeed(auth) != wantSeed || got.InstallationID != wantInstall || got.UserAgent != wantUA {
			t.Fatalf("account manager compatibility vector changed: %+v", got)
		}
	}
	assertIdentity(auth)
	auth.ID = "duplicate-renamed-file"
	auth.Metadata["access_token"] = "refreshed-token"
	auth.Metadata["codex_fingerprint_seed"] = "11111111-1111-4111-8111-111111111111"
	assertIdentity(auth)
	claims := `{"https://api.openai.com/auth":{"chatgpt_account_id":"acct-one","chatgpt_user_id":"user-one"}}`
	assertIdentity(&cliproxyauth.Auth{Metadata: map[string]any{"id_token": "e30." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".sig"}})
	assertIdentity(&cliproxyauth.Auth{Metadata: map[string]any{"id_token": "e30." + base64.URLEncoding.EncodeToString([]byte(claims)) + ".sig"}})
	assertIdentity(&cliproxyauth.Auth{Metadata: map[string]any{"id_token": claims}})
	assertIdentity(&cliproxyauth.Auth{Metadata: map[string]any{"id_token": map[string]any{"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "acct-one", "chatgpt_user_id": "user-one"}}}})
	auth.Metadata["chatgpt_user_id"] = "user-two"
	if CodexIdentityForAuth(auth).InstallationID == wantInstall {
		t.Fatal("different users in one workspace share an installation")
	}
	auth.Metadata["account_id"] = "acct-two"
	if CodexIdentityForAuth(auth).InstallationID == wantInstall {
		t.Fatal("different accounts share an installation")
	}
}

func TestCodexAccountFingerprintConcurrentAndRestart(t *testing.T) {
	if os.Getenv("CPA_TEST_FINGERPRINT_CHILD") == "1" {
		identity := CodexIdentityForAuth(&cliproxyauth.Auth{ID: "fresh-process", Metadata: map[string]any{"account_id": "acct-one", "chatgpt_user_id": "user-one"}})
		fmt.Println("fingerprint=" + identity.InstallationID + "|" + identity.UserAgent)
		return
	}
	var previous string
	for range 2 {
		cmd := exec.Command(os.Args[0], "-test.run=^TestCodexAccountFingerprintConcurrentAndRestart$")
		cmd.Env = append(os.Environ(), "CPA_TEST_FINGERPRINT_CHILD=1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("fresh process: %v: %s", err, output)
		}
		line := strings.SplitN(string(output), "\n", 2)[0]
		if !strings.HasPrefix(line, "fingerprint=866b0bfd-ca88-43f8-aaf7-02053e402033|") || previous != "" && previous != line {
			t.Fatalf("fingerprint changed across process restarts: %q", line)
		}
		previous = line
	}
	auth := &cliproxyauth.Auth{Metadata: map[string]any{"account_id": "acct-one", "chatgpt_user_id": "user-one"}}
	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() {
			if got := CodexIdentityForAuth(auth); got.InstallationID != "866b0bfd-ca88-43f8-aaf7-02053e402033" {
				t.Errorf("concurrent identity changed: %+v", got)
			}
		})
	}
	wg.Wait()
}

func TestCodexFingerprintMetadataPreservesLifetimesAndUnicode(t *testing.T) {
	identity := CodexIdentityForAuth(&cliproxyauth.Auth{Metadata: map[string]any{"account_id": "acct-one", "chatgpt_user_id": "user-one"}})
	raw := `{"installation_id":"caller-install","session_id":"session-one","thread_id":"thread-one","turn_id":"turn-one","window_id":"window-one","workspaces":{"中🚀":{"commit":9007199254740993}},"tool_namespaces_info":{"tools":[]}}`
	metadata, _ := json.Marshal(map[string]any{"X-Codex-Turn-Metadata": raw, "X-Codex-Installation-Id": "caller-install", "traceparent": "keep"})
	body := []byte(`{"client_metadata":` + string(metadata) + `}`)
	body = ApplyCodexFingerprintMetadata(body, http.Header{"x-codex-turn-metadata": {`{"sandbox":"keep"}`}}, identity)
	turnBody := gjson.GetBytes(body, "client_metadata.x-codex-turn-metadata").String()
	if gjson.Get(turnBody, "installation_id").String() != identity.InstallationID || gjson.GetBytes(body, "client_metadata.X-Codex-Installation-Id").Exists() {
		t.Fatal("caller installation or case alias survived account binding")
	}
	for key, want := range map[string]string{"session_id": "session-one", "thread_id": "thread-one", "turn_id": "turn-one", "window_id": "window-one", "sandbox": "keep"} {
		if got := gjson.Get(turnBody, key).String(); got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
	if gjson.Get(turnBody, "workspaces.中🚀.commit").Raw != "9007199254740993" || strings.ContainsFunc(turnBody, func(r rune) bool { return r > 127 }) {
		t.Fatal("Unicode or numeric metadata was corrupted")
	}
	headers := http.Header{"x-codex-installation-id": {"caller-install"}, "session_id": {"caller-session"}}
	ApplyCodexFingerprintHeaders(headers, body, false, false)
	if headers.Get("X-Codex-Installation-Id") != "" || headers.Get("X-Client-Request-Id") != "thread-one" || headers.Get("Session-Id") != "session-one" {
		t.Fatalf("incorrect HTTP compatibility headers: %v", headers)
	}
	if gjson.Get(headers.Get("X-Codex-Turn-Metadata"), "tool_namespaces_info").Exists() || !gjson.Get(turnBody, "tool_namespaces_info").Exists() {
		t.Fatal("tool inventory must remain only in the request body")
	}
	ApplyCodexFingerprintHeaders(headers, body, true, false)
	if headers.Get("X-Codex-Installation-Id") != identity.InstallationID || headers.Get("X-Client-Request-Id") != "" {
		t.Fatal("legacy compact header shape is incorrect")
	}
	ApplyCodexFingerprintHeaders(headers, body, false, true)
	if headers.Get("X-Codex-Installation-Id") != "" || headers.Get("X-Client-Request-Id") != "" {
		t.Fatal("WS handshake contains HTTP-only identity headers")
	}
	first := ApplyCodexFingerprintMetadata([]byte(`{"prompt_cache_key":"session-a"}`), nil, identity)
	second := ApplyCodexFingerprintMetadata([]byte(`{"prompt_cache_key":"session-a"}`), nil, identity)
	third := ApplyCodexFingerprintMetadata([]byte(`{"prompt_cache_key":"session-b"}`), nil, identity)
	if gjson.GetBytes(first, "client_metadata.turn_id").String() == gjson.GetBytes(second, "client_metadata.turn_id").String() {
		t.Fatal("new turns reuse one turn ID")
	}
	if gjson.GetBytes(first, "client_metadata.x-codex-window-id").String() != gjson.GetBytes(second, "client_metadata.x-codex-window-id").String() || gjson.GetBytes(first, "client_metadata.x-codex-window-id").String() == gjson.GetBytes(third, "client_metadata.x-codex-window-id").String() {
		t.Fatal("window fallback is not scoped to the conversation")
	}
}

func TestCodexFingerprintHeaderOnlyIdentity(t *testing.T) {
	identity := CodexIdentityForAuth(&cliproxyauth.Auth{Metadata: map[string]any{"account_id": "acct-one", "chatgpt_user_id": "user-one"}})
	headers := http.Header{"x-codex-turn-metadata": {`{"installation_id":"caller-device","thread_id":"keep"}`}, "x-codex-installation-id": {"caller-device"}}
	BindCodexInstallationHeaders(headers, identity)
	if headers.Get("X-Codex-Installation-Id") != "866b0bfd-ca88-43f8-aaf7-02053e402033" || gjson.Get(headers.Get("X-Codex-Turn-Metadata"), "installation_id").String() != identity.InstallationID || gjson.Get(headers.Get("X-Codex-Turn-Metadata"), "thread_id").String() != "keep" || len(headers) != 2 {
		t.Fatalf("header-only account identity is inconsistent: %v", headers)
	}
	empty := http.Header{}
	BindCodexInstallationHeaders(empty, identity)
	if len(empty) != 0 {
		t.Fatal("header-only binding invented endpoint-specific headers")
	}
}
