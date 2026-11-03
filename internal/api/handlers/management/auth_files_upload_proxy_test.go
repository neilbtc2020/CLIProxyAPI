package management

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func testUploadPool(t *testing.T, body string) uploadProxyPool {
	t.Helper()
	var pool uploadProxyPool
	if err := json.Unmarshal([]byte(body), &pool); err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestNativeUploadProxyAssignsAndPreservesRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account.json")
	pool := testUploadPool(t, `{"auto_assign":true,"entries":[{"state":"available","display_url":"socks5h://127.0.0.1:41001"}]}`)
	raw := []byte(`{"type":"codex","access_token":"first","disabled":true,"priority":37,"custom":{"integer":9007199254740993}}`)
	prepared, err := prepareUploadedAuthProxy(path, raw, func() (uploadProxyPool, error) { return pool, nil })
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(prepared, &fields)
	if string(fields["proxy_url"]) != `"socks5h://127.0.0.1:41001"` || string(fields["disabled"]) != "true" || string(fields["custom"]) != `{"integer":9007199254740993}` {
		t.Fatalf("assignment changed account metadata: %s", prepared)
	}
	if err = os.WriteFile(path, prepared, 0o600); err != nil {
		t.Fatal(err)
	}
	// A credential refresh/retry must not depend on pool availability or rotate
	// the persisted proxy, even when the new body omits that field.
	retried, err := prepareUploadedAuthProxy(path, []byte(strings.Replace(string(raw), "first", "second", 1)), func() (uploadProxyPool, error) {
		t.Fatal("retry unexpectedly reselected a proxy")
		return uploadProxyPool{}, errors.New("pool unavailable")
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(retried, &fields)
	if string(fields["proxy_url"]) != `"socks5h://127.0.0.1:41001"` || string(fields["access_token"]) != `"second"` {
		t.Fatalf("retry failed to preserve proxy/update credential: %s", retried)
	}
}

func TestNativeUploadProxyExplicitAndOtherProviders(t *testing.T) {
	for _, raw := range []string{
		`{"type":"codex","proxy_url":"socks5h://127.0.0.1:42000"}`,
		`{"type":"codex","proxy_url":"direct"}`,
		`{"type":"claude"}`,
	} {
		got, err := prepareUploadedAuthProxy(filepath.Join(t.TempDir(), "auth.json"), []byte(raw), func() (uploadProxyPool, error) {
			t.Fatal("explicit proxy/non-Codex upload consulted the pool")
			return uploadProxyPool{}, nil
		})
		if err != nil || string(got) != raw {
			t.Fatalf("upload changed: got %s, err %v", got, err)
		}
	}
}

func TestNativeUploadProxyFailsClosedAndResolvesEnvironment(t *testing.T) {
	t.Setenv("CPA_UPLOAD_TEST_PROXY", "socks5h://user:secret@127.0.0.1:41002")
	for _, tc := range []struct {
		name, pool, expected string
		wantError            bool
	}{
		{"disabled", `{"auto_assign":false}`, "", false},
		{"empty", `{"auto_assign":true}`, "", true},
		{"unavailable", `{"auto_assign":true,"entries":[{"state":"unavailable","display_url":"socks5h://127.0.0.1:41001"}]}`, "", true},
		{"invalid", `{"auto_assign":true,"entries":[{"state":"available","display_url":"direct"}]}`, "", true},
		{"environment", `{"auto_assign":true,"entries":[{"state":"available","credential_env":"CPA_UPLOAD_TEST_PROXY","display_url":"socks5h://127.0.0.1:41002"}]}`, os.Getenv("CPA_UPLOAD_TEST_PROXY"), false},
		{"missing_environment", `{"auto_assign":true,"entries":[{"state":"available","credential_env":"CPA_UPLOAD_MISSING_TEST_PROXY","display_url":"socks5h://127.0.0.1:41002"}]}`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := testUploadPool(t, tc.pool)
			path := filepath.Join(t.TempDir(), "account.json")
			result, err := prepareUploadedAuthProxy(path, []byte(`{"type":"codex"}`), func() (uploadProxyPool, error) { return pool, nil })
			if (err != nil) != tc.wantError {
				t.Fatalf("error = %v, want error %v", err, tc.wantError)
			}
			if err == nil {
				var fields map[string]any
				_ = json.Unmarshal(result, &fields)
				proxy, _ := fields["proxy_url"].(string)
				if proxy != tc.expected {
					t.Fatal("incorrect proxy resolution")
				}
			}
			if _, errStat := os.Stat(path); !os.IsNotExist(errStat) {
				t.Fatal("preparation unexpectedly persisted an account")
			}
		})
	}
}

func TestNativeUploadProxyPluginReadErrors(t *testing.T) {
	for _, body := range []string{`not-json`, `{}`, `{"auto_assign":null}`, `{"storage_error":"unreadable"}`} {
		_, err := readUploadProxyPool(context.Background(), func(w http.ResponseWriter, req *http.Request) bool {
			if req.Method != http.MethodGet || req.Header.Get("Authorization") != "" || req.Body != nil {
				t.Fatal("pool read forwarded credentials or used a mutating request")
			}
			_, _ = w.Write([]byte(body))
			return true
		})
		if err == nil {
			t.Fatal("invalid pool response was accepted")
		}
	}
	_, err := readUploadProxyPool(context.Background(), func(http.ResponseWriter, *http.Request) bool { return false })
	if err == nil {
		t.Fatal("missing plugin route was accepted")
	}
}

func TestNativeUploadProxyFileStorePreservesExactMetadata(t *testing.T) {
	dir := t.TempDir()
	store := sdkAuth.NewFileTokenStore()
	store.SetBaseDir(dir)
	manager := coreauth.NewManager(store, nil, nil)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: dir}, manager)
	raw := []byte(`{"type":"codex","access_token":"fixture","proxy_url":"socks5h://127.0.0.1:41001","disabled":true,"priority":37,"custom":{"integer":9007199254740993}}`)
	for i := 0; i < 2; i++ {
		if err := h.writeAuthFile(context.Background(), "account.json", raw); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(dir, "account.json"))
		if err != nil {
			t.Fatal(err)
		}
		var metadata map[string]json.RawMessage
		_ = json.Unmarshal(data, &metadata)
		if string(metadata["custom"]) != `{"integer":9007199254740993}` || string(metadata["disabled"]) != "true" || string(metadata["proxy_url"]) != `"socks5h://127.0.0.1:41001"` {
			t.Fatalf("persisted upload metadata changed on iteration %d: %s", i, data)
		}
		auth, ok := manager.GetByID("account.json")
		if !ok || !auth.Disabled || auth.ProxyURL != "socks5h://127.0.0.1:41001" || auth.Attributes["priority"] != "37" {
			t.Fatal("runtime account lost uploaded settings")
		}
	}
}
