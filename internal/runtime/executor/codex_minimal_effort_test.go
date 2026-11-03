package executor

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

func TestCodexMinimalEffortAcrossTransports(t *testing.T) {
	for _, flow := range []string{"http", "http-stream", "ws", "ws-stream", "fallback", "fallback-stream"} {
		for _, lite := range []bool{false, true} {
			for _, override := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/lite=%t/override=%t", flow, lite, override), func(t *testing.T) {
					headers := http.Header{}
					if lite {
						headers.Set("X-OpenAI-Internal-Codex-Responses-Lite", "true")
					}
					cfg := &config.Config{}
					wantBaseline := "low"
					if override {
						cfg.Payload.Override = []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: "gpt-6.1-sol"}}, Params: map[string]any{"reasoning.effort": "minimal"}}}
						wantBaseline = "minimal"
					}
					auth := &cliproxyauth.Auth{ID: t.Name(), Provider: "codex", Metadata: map[string]any{"account_id": "compat-account", "access_token": "synthetic"}}
					body := []byte(`{"model":"gpt-6.1-sol","reasoning":{"effort":"minimal","summary":"auto"},"input":[{"type":"configuration_update","reasoning":{"effort":"none"}},{"type":"configuration_update","reasoning":{"effort":"minimal"}},{"type":"configuration_update","reasoning":{"effort":"high"}},{"role":"user","content":"continue"}]}`)
					got := captureCodexFingerprintFlow(t, flow, cfg, auth, body, headers)
					for path, want := range map[string]string{
						"reasoning.effort":         wantBaseline,
						"reasoning.summary":        "auto",
						"input.0.reasoning.effort": "low",
						"input.1.reasoning.effort": "low",
						"input.2.reasoning.effort": "high",
					} {
						if value := gjson.GetBytes(got.body, path).String(); value != want {
							t.Fatalf("%s = %q, want %q; body=%s", path, value, want, got.body)
						}
					}
				})
			}
		}
	}
}
