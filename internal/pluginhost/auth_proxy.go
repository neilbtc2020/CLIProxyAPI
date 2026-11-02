package pluginhost

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/proxyutil"
)

func (h *Host) callHostAuthPatchProxy(ctx context.Context, raw []byte) ([]byte, error) {
	respond := func(status string) ([]byte, error) {
		return marshalRPCResult(pluginapi.HostAuthPatchProxyResponse{Status: status})
	}
	var request pluginapi.HostAuthPatchProxyRequest
	if len(raw) > 16<<10 || json.Unmarshal(raw, &request) != nil {
		return respond("invalid")
	}
	if request.AuthIndex == "" || request.Revision == "" || len(request.ProxyURL) > 4096 {
		return respond("invalid")
	}
	setting, err := proxyutil.Parse(request.ProxyURL)
	if err != nil || setting.Mode != proxyutil.ModeProxy {
		return respond("invalid")
	}
	auth, err := h.authByIndex(strings.TrimSpace(request.AuthIndex))
	if err != nil {
		return respond("not_found")
	}
	manager := h.currentAuthManager()
	if manager == nil {
		return respond("unsupported")
	}
	_, err = manager.UpdateProxyURL(ctx, auth.ID, request.Revision, request.ProxyURL)
	switch {
	case err == nil:
		return respond("updated")
	case errors.Is(err, coreauth.ErrProxyUpdateConflict):
		return respond("conflict")
	case errors.Is(err, coreauth.ErrProxyUpdateUnavailable):
		return respond("unsupported")
	default:
		return respond("error")
	}
}
