package executor

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

func TestCodexToolChoiceAcrossTransportsAndPayloadBarrier(t *testing.T) {
	for _, flow := range []string{"http", "http-stream", "ws", "ws-stream", "fallback", "fallback-stream"} {
		for _, mode := range []string{"oauth", "api-key", "override", "filter"} {
			t.Run(fmt.Sprintf("%s/%s", flow, mode), func(t *testing.T) {
				auth := &cliproxyauth.Auth{ID: t.Name(), Provider: "codex", Metadata: map[string]any{"account_id": "compat-account", "access_token": "synthetic"}}
				cfg := &config.Config{}
				want := `"auto"`
				switch mode {
				case "api-key":
					auth.Attributes = map[string]string{"api_key": "synthetic-api-key"}
					want = `{"type":"auto"}`
				case "override":
					cfg.Payload.Override = []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: "gpt-6.1-sol"}}, Params: map[string]any{"tool_choice": map[string]any{"type": "auto"}}}}
					want = `{"type":"auto"}`
				case "filter":
					cfg.Payload.Filter = []config.PayloadFilterRule{{Models: []config.PayloadModelRule{{Name: "gpt-6.1-sol"}}, Params: []string{"tool_choice"}}}
					want = ""
				}
				body := []byte(`{"model":"gpt-6.1-sol","tool_choice":{"type":"auto"},"input":[{"type":"configuration_update","tool_choice":{"type":"none"}},{"role":"user","content":"Reply OK"}]}`)
				got := captureCodexFingerprintFlow(t, flow, cfg, auth, body, http.Header{})
				if choice := gjson.GetBytes(got.body, "tool_choice").Raw; choice != want {
					t.Fatalf("tool_choice = %s, want %s", choice, want)
				}
				wantUpdate := `"none"`
				if mode == "api-key" {
					wantUpdate = `{"type":"none"}`
				}
				if choice := gjson.GetBytes(got.body, "input.0.tool_choice").Raw; choice != wantUpdate {
					t.Fatalf("update choice = %s, want %s", choice, wantUpdate)
				}
			})
		}
	}
}
