package executor

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

func TestCodexChannel283CompatibilityAcrossTransports(t *testing.T) {
	for _, flow := range []string{"http", "http-stream", "ws", "ws-stream", "fallback", "fallback-stream"} {
		for _, lite := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/lite=%t", flow, lite), func(t *testing.T) {
				headers := http.Header{}
				if lite {
					headers.Set("X-OpenAI-Internal-Codex-Responses-Lite", "true")
				}
				auth := &cliproxyauth.Auth{ID: t.Name(), Provider: "codex", Metadata: map[string]any{"account_id": "compat-account", "access_token": "synthetic"}}
				ciphertext := validOpenAIResponsesReasoningEncryptedContentForTest()
				body := []byte(`{"model":"gpt-6.1-sol","store":false,"reasoning":{"effort":"none","summary":"auto"},"input":[{"type":"reasoning","id":"rs_external_mismatch","encrypted_content":"` + ciphertext + `","summary":[]},{"type":"web_search_call","id":"msg_external","status":"completed","action":{"type":"search","query":"sample"}},{"type":"configuration_update","reasoning":{"effort":"none"}},{"type":"message","role":"user","content":"continue"}]}`)
				got := captureCodexFingerprintFlow(t, flow, &config.Config{}, auth, body, headers)
				if gjson.GetBytes(got.body, "reasoning.effort").String() != "low" || gjson.GetBytes(got.body, "reasoning.summary").String() != "auto" {
					t.Fatalf("unsupported none was forwarded or summary changed: %s", got.body)
				}
				if lite && gjson.GetBytes(got.body, "reasoning.context").String() != "all_turns" {
					t.Fatalf("Lite context absent: %s", got.body)
				}
				foundReasoning, foundSearch, foundUpdate := false, false, false
				for _, item := range gjson.GetBytes(got.body, "input").Array() {
					switch item.Get("type").String() {
					case "reasoning":
						foundReasoning = true
						if item.Get("id").Exists() || item.Get("encrypted_content").String() != ciphertext {
							t.Fatal("reasoning was rewritten instead of preserving its ciphertext without an outer ID")
						}
					case "web_search_call":
						foundSearch = true
						if item.Get("id").String() != "ws_msg_external" {
							t.Fatal("web-search item has an invalid prefix")
						}
					case "configuration_update":
						foundUpdate = true
						if item.Get("reasoning.effort").String() != "low" {
							t.Fatal("in-turn disabled effort bypassed capability validation")
						}
					}
				}
				if !foundReasoning || !foundUpdate || !lite && !foundSearch {
					t.Fatalf("expected history was lost: %s", got.body)
				}
			})
		}
	}
}

func TestCodexChannel283CompatibilityPreservesPayloadBarrier(t *testing.T) {
	for _, flow := range []string{"http", "http-stream", "ws", "ws-stream", "fallback", "fallback-stream"} {
		for _, filter := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/filter=%t", flow, filter), func(t *testing.T) {
				cfg := &config.Config{}
				models := []config.PayloadModelRule{{Name: "gpt-6.1-sol"}}
				if filter {
					cfg.Payload.Filter = []config.PayloadFilterRule{{Models: models, Params: []string{"reasoning.context", "input.0.encrypted_content"}}}
				} else {
					cfg.Payload.Override = []config.PayloadRule{{Models: models, Params: map[string]any{"reasoning.context": "operator-context", "reasoning.effort": "none", "input.0.id": "operator-id"}}}
				}
				headers := http.Header{}
				headers.Set("X-OpenAI-Internal-Codex-Responses-Lite", "true")
				body := []byte(`{"model":"gpt-6.1-sol","reasoning":{"effort":"none"},"input":[{"type":"reasoning","id":"rs_old","encrypted_content":"` + validOpenAIResponsesReasoningEncryptedContentForTest() + `","summary":[]},{"type":"message","role":"user","content":"continue"}]}`)
				auth := &cliproxyauth.Auth{ID: t.Name(), Provider: "codex", Metadata: map[string]any{"account_id": "compat-account", "access_token": "synthetic"}}
				got := captureCodexFingerprintFlow(t, flow, cfg, auth, body, headers)
				if filter {
					if gjson.GetBytes(got.body, "reasoning.context").Exists() || gjson.GetBytes(got.body, "input.0.encrypted_content").Exists() {
						t.Fatal("compatibility logic restored a filtered field")
					}
				} else if gjson.GetBytes(got.body, "reasoning.context").String() != "operator-context" || gjson.GetBytes(got.body, "reasoning.effort").String() != "none" || gjson.GetBytes(got.body, "input.0.id").String() != "operator-id" {
					t.Fatalf("compatibility logic overwrote final payload rules: %s", got.body)
				}
			})
		}
	}
}
