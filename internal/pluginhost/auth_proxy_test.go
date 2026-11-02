package pluginhost

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	tokenstore "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestReviewProxyPoolHostSaveHonorsRoutingFields(t *testing.T) {
	host := New()
	host.runtimeConfig = &config.Config{AuthDir: t.TempDir()}
	host.SetAuthManager(coreauth.NewManager(nil, nil, nil))
	_, err := host.saveAuthFile(context.Background(), "pool-account.json", []byte(`{"type":"codex","access_token":"test-token","proxy_url":"socks5h://proxy.example:1080","disabled":true,"prefix":"restricted"}`))
	if err != nil {
		t.Fatal(err)
	}
	auths := host.currentAuthManager().List()
	if len(auths) != 1 {
		t.Fatal("account not registered")
	}
	auth := auths[0]
	if auth.ProxyURL != "socks5h://proxy.example:1080" || !auth.Disabled || auth.Prefix != "restricted" {
		t.Fatalf("host save published incorrect routing: ProxyURL=%q Disabled=%v Prefix=%q metadata.proxy_url=%v", auth.ProxyURL, auth.Disabled, auth.Prefix, auth.Metadata["proxy_url"])
	}
}

func TestReviewProxyReplacementMustKeepDisabledOnDisk(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store := tokenstore.NewFileTokenStore()
	store.SetBaseDir(dir)
	host := New()
	host.runtimeConfig = &config.Config{AuthDir: dir}
	host.SetAuthManager(coreauth.NewManager(store, nil, nil))
	path := filepath.Join(dir, "disabled.json")
	_, err := host.currentAuthManager().Register(ctx, &coreauth.Auth{ID: "disabled.json", FileName: "disabled.json", Provider: "codex", Disabled: true, Status: coreauth.StatusDisabled, ProxyURL: "http://old.example:8080", Attributes: map[string]string{"path": path}, Metadata: map[string]any{"type": "codex", "access_token": "test-token", "disabled": true, "proxy_url": "http://old.example:8080"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = host.saveAuthFile(ctx, "disabled.json", []byte(`{"type":"codex","access_token":"test-token","disabled":true,"proxy_url":"http://new.example:8080"}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var disk map[string]any
	if err = json.Unmarshal(raw, &disk); err != nil {
		t.Fatal(err)
	}
	if disk["disabled"] != true {
		t.Fatalf("proxy replacement permanently enabled disabled account: disk.disabled=%v", disk["disabled"])
	}
}

func proxyCallbackFixture(t *testing.T) (*Host, string, string) {
	t.Helper()
	dir := t.TempDir()
	store := tokenstore.NewFileTokenStore()
	store.SetBaseDir(dir)
	host := New()
	host.runtimeConfig = &config.Config{AuthDir: dir}
	host.SetAuthManager(coreauth.NewManager(store, nil, nil))
	path, err := host.saveAuthFile(t.Context(), "proxy.json", []byte(`{"type":"codex","access_token":"token-1","refresh_token":"refresh-1","account_id":"alice","disabled":true,"prefix":"restricted","priority":7,"custom_number":9007199254740993,"proxy_url":"http://old.example:8080"}`))
	if err != nil {
		t.Fatal(err)
	}
	auths := host.currentAuthManager().List()
	if len(auths) != 1 {
		t.Fatal("missing auth")
	}
	return host, auths[0].Index, path
}

func proxyCallbackRevision(t *testing.T, host *Host, index string) string {
	t.Helper()
	body, _ := json.Marshal(pluginapi.HostAuthGetRequest{AuthIndex: index})
	response, err := host.callFromPlugin(t.Context(), pluginabi.MethodHostAuthGet, body)
	if err != nil {
		t.Fatal(err)
	}
	detail, err := decodeRPCEnvelope[pluginapi.HostAuthGetResponse](response)
	if err != nil {
		t.Fatal(err)
	}
	if len(detail.ProxyRevision) != 64 {
		t.Fatal("missing version capability")
	}
	return detail.ProxyRevision
}

func patchProxyCallback(t *testing.T, host *Host, index, revision string) string {
	t.Helper()
	body, _ := json.Marshal(pluginapi.HostAuthPatchProxyRequest{AuthIndex: index, Revision: revision, ProxyURL: "socks5h://proxy-user:proxy-secret@new.example:1080"})
	response, err := host.callFromPlugin(t.Context(), pluginabi.MethodHostAuthPatchProxy, body)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(response, []byte("proxy-secret")) || bytes.Contains(response, []byte("refresh-1")) {
		t.Fatal("callback leaked credentials")
	}
	outcome, err := decodeRPCEnvelope[pluginapi.HostAuthPatchProxyResponse](response)
	if err != nil {
		t.Fatal(err)
	}
	return outcome.Status
}

func TestHostProxyCallbackPreservesDisabledAndDocumentFields(t *testing.T) {
	host, index, path := proxyCallbackFixture(t)
	revision := proxyCallbackRevision(t, host, index)
	if status := patchProxyCallback(t, host, index, revision); status != "updated" {
		t.Fatalf("status=%s", status)
	}
	auth := host.currentAuthManager().List()[0]
	if !auth.Disabled || auth.Status != coreauth.StatusDisabled || auth.Prefix != "restricted" || auth.Attributes["priority"] != "7" || auth.ProxyURL != "socks5h://proxy-user:proxy-secret@new.example:1080" {
		t.Fatalf("runtime fields changed: disabled=%t status=%s prefix=%q priority=%q proxy_ok=%t", auth.Disabled, auth.Status, auth.Prefix, auth.Attributes["priority"], auth.ProxyURL == "socks5h://proxy-user:proxy-secret@new.example:1080")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"disabled":true`)) || !bytes.Contains(raw, []byte("9007199254740993")) || !bytes.Contains(raw, []byte("refresh-1")) {
		t.Fatalf("unrelated document fields lost: %s", raw)
	}
	if status := patchProxyCallback(t, host, index, revision); status != "conflict" {
		t.Fatalf("stale version accepted: %s", status)
	}
}

func TestHostProxyCallbackRejectsDiskReplacementBeforeWatcher(t *testing.T) {
	host, index, path := proxyCallbackFixture(t)
	revision := proxyCallbackRevision(t, host, index)
	replacement := []byte(`{"type":"codex","access_token":"bob-token","account_id":"bob"}`)
	if err := os.WriteFile(path, replacement, 0600); err != nil {
		t.Fatal(err)
	}
	if status := patchProxyCallback(t, host, index, revision); status != "conflict" {
		t.Fatalf("changed file accepted: %s", status)
	}
	raw, _ := os.ReadFile(path)
	if !bytes.Equal(raw, replacement) {
		t.Fatal("changed account overwritten")
	}
}

func TestHostProxyCallbackRejectsRefreshAndPreservesLaterRefresh(t *testing.T) {
	host, index, path := proxyCallbackFixture(t)
	revision := proxyCallbackRevision(t, host, index)
	manager := host.currentAuthManager()
	base := manager.List()[0]
	refreshed := base.Clone()
	refreshed.Metadata["access_token"], refreshed.Metadata["refresh_token"] = "fresh-access", "fresh-refresh"
	refreshed.CodexRefreshPatch = codex.NewCredentialRefreshPatch(base.Metadata, refreshed.Metadata, true, false)
	if _, err := manager.UpdateRefreshedAuth(t.Context(), base, refreshed); err != nil {
		t.Fatal(err)
	}
	if status := patchProxyCallback(t, host, index, revision); status != "conflict" {
		t.Fatalf("stale pre-refresh version accepted: %s", status)
	}
	revision = proxyCallbackRevision(t, host, index)
	base = manager.List()[0]
	if status := patchProxyCallback(t, host, index, revision); status != "updated" {
		t.Fatalf("fresh version failed: %s", status)
	}
	refreshed = base.Clone()
	refreshed.Metadata["access_token"], refreshed.Metadata["refresh_token"] = "next-access", "next-refresh"
	refreshed.CodexRefreshPatch = codex.NewCredentialRefreshPatch(base.Metadata, refreshed.Metadata, true, false)
	if _, err := manager.UpdateRefreshedAuth(t.Context(), base, refreshed); err != nil {
		t.Fatal(err)
	}
	latest := manager.List()[0]
	if latest.ProxyURL != "socks5h://proxy-user:proxy-secret@new.example:1080" || latest.Metadata["refresh_token"] != "next-refresh" || !latest.Disabled {
		t.Fatalf("refresh merge: proxy_ok=%t token_ok=%t disabled=%t status=%s", latest.ProxyURL == "socks5h://proxy-user:proxy-secret@new.example:1080", latest.Metadata["refresh_token"] == "next-refresh", latest.Disabled, latest.Status)
	}
	raw, _ := os.ReadFile(path)
	if !bytes.Contains(raw, []byte("next-refresh")) || !bytes.Contains(raw, []byte("new.example")) {
		t.Fatal("disk does not match latest runtime")
	}
}

func TestHostProxyCallbackRejectsMixedDiskAndRuntimeSnapshot(t *testing.T) {
	host, index, path := proxyCallbackFixture(t)
	replacement := []byte(`{"type":"codex","access_token":"bob-token","account_id":"bob"}`)
	if err := os.WriteFile(path, replacement, 0600); err != nil {
		t.Fatal(err)
	}
	// The UI opened after the file changed but before the watcher ran.
	revision := proxyCallbackRevision(t, host, index)
	if status := patchProxyCallback(t, host, index, revision); status != "conflict" {
		t.Fatalf("mixed snapshot accepted: %s", status)
	}
	raw, _ := os.ReadFile(path)
	if !bytes.Equal(raw, replacement) {
		t.Fatal("old runtime overwrote the new file")
	}
}

func TestHostProxyCallbackUpdatesEnabledAccountWithoutExplicitDisabled(t *testing.T) {
	dir := t.TempDir()
	store := tokenstore.NewFileTokenStore()
	store.SetBaseDir(dir)
	host := New()
	host.runtimeConfig = &config.Config{AuthDir: dir}
	host.SetAuthManager(coreauth.NewManager(store, nil, nil))
	if _, err := host.saveAuthFile(t.Context(), "enabled.json", []byte(`{"type":"codex","access_token":"token"}`)); err != nil {
		t.Fatal(err)
	}
	index := host.currentAuthManager().List()[0].Index
	if status := patchProxyCallback(t, host, index, proxyCallbackRevision(t, host, index)); status != "updated" {
		t.Fatalf("implicit disabled=false rejected: %s", status)
	}
}
