package management

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"os"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/proxyutil"
)

const uploadProxyPlugin = "cpa-account-config-manager"

type uploadProxyPool struct {
	AutoAssign   bool   `json:"auto_assign"`
	StorageError string `json:"storage_error"`
	Entries      []struct {
		DisplayURL    string `json:"display_url"`
		CredentialEnv string `json:"credential_env"`
		State         string `json:"state"`
	} `json:"entries"`
}

// Read the plugin's current pool, including its auto-assign switch, rather than
// maintaining a second list that can drift from the account management UI.
func (h *Handler) loadUploadProxyPool(ctx context.Context) (uploadProxyPool, error) {
	h.mu.Lock()
	host := h.pluginHost
	enabled := false
	if h.cfg != nil && h.cfg.Plugins.Enabled {
		item := h.cfg.Plugins.Configs[uploadProxyPlugin]
		enabled = item.Enabled != nil && *item.Enabled
	}
	h.mu.Unlock()
	if !enabled {
		return uploadProxyPool{}, nil
	}
	if host == nil {
		return uploadProxyPool{}, errors.New("upload proxy pool is unavailable")
	}
	return readUploadProxyPool(ctx, host.ServeManagementHTTP)
}

type uploadPoolResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (r *uploadPoolResponse) Header() http.Header    { return r.header }
func (r *uploadPoolResponse) WriteHeader(status int) { r.status = status }
func (r *uploadPoolResponse) Write(data []byte) (int, error) {
	if r.body.Len()+len(data) > 8<<20 {
		return 0, errors.New("upload proxy pool response too large")
	}
	return r.body.Write(data)
}

func readUploadProxyPool(ctx context.Context, serve func(http.ResponseWriter, *http.Request) bool) (uploadProxyPool, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "/v0/management/plugins/"+uploadProxyPlugin+"/proxy-pool", nil)
	if err != nil {
		return uploadProxyPool{}, errors.New("cannot read upload proxy pool")
	}
	// The outer management upload is already authenticated. This read-only
	// in-process route needs neither account tokens nor management credentials.
	response := &uploadPoolResponse{header: make(http.Header), status: http.StatusOK}
	var pool uploadProxyPool
	if !serve(response, request) || response.status != http.StatusOK || json.Unmarshal(response.body.Bytes(), &pool) != nil || pool.StorageError != "" {
		return uploadProxyPool{}, errors.New("upload proxy pool is unavailable")
	}
	var required struct {
		AutoAssign *bool `json:"auto_assign"`
	}
	if json.Unmarshal(response.body.Bytes(), &required) != nil || required.AutoAssign == nil {
		return uploadProxyPool{}, errors.New("upload proxy pool is unavailable")
	}
	return pool, nil
}

// The caller holds the Codex file lock through the following file write.
func prepareUploadedAuthProxy(path string, data []byte, load func() (uploadProxyPool, error)) ([]byte, error) {
	var document map[string]json.RawMessage
	if json.Unmarshal(data, &document) != nil || document == nil {
		return nil, errors.New("invalid auth upload")
	}
	var provider, explicit string
	_ = json.Unmarshal(document["type"], &provider)
	_ = json.Unmarshal(document["proxy_url"], &explicit)
	if !strings.EqualFold(strings.TrimSpace(provider), "codex") || strings.TrimSpace(explicit) != "" {
		return data, nil
	}
	previous, errRead := os.ReadFile(path)
	if errRead != nil && !errors.Is(errRead, os.ErrNotExist) {
		return nil, errors.New("cannot inspect previous upload proxy")
	}
	if errRead == nil {
		var existing map[string]json.RawMessage
		if json.Unmarshal(previous, &existing) != nil || existing == nil {
			return nil, errors.New("cannot inspect previous upload proxy")
		}
		var proxy string
		_ = json.Unmarshal(existing["proxy_url"], &proxy)
		if strings.TrimSpace(proxy) != "" {
			document["proxy_url"] = existing["proxy_url"]
			return json.Marshal(document)
		}
	}
	pool, err := load()
	if err != nil {
		return nil, err
	}
	if !pool.AutoAssign {
		return data, nil
	}
	var candidates []string
	for _, entry := range pool.Entries {
		if entry.State != "available" {
			continue
		}
		proxy := entry.DisplayURL
		if entry.CredentialEnv != "" {
			proxy = os.Getenv(entry.CredentialEnv)
		}
		if proxyutil.ValidRequestProxy(proxy) {
			candidates = append(candidates, strings.TrimSpace(proxy))
		}
	}
	if len(candidates) == 0 {
		return nil, errors.New("upload proxy pool has no available endpoint")
	}
	index, err := rand.Int(rand.Reader, big.NewInt(int64(len(candidates))))
	if err != nil {
		return nil, errors.New("cannot select upload proxy")
	}
	document["proxy_url"], _ = json.Marshal(candidates[index.Int64()])
	return json.Marshal(document)
}
