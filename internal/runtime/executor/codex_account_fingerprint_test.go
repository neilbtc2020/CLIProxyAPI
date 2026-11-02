package executor

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

type codexFingerprintCapture struct {
	headers http.Header
	body    []byte
	path    string
}

func captureCodexFingerprintFlow(t *testing.T, flow string, cfg *config.Config, auth *cliproxyauth.Auth, body []byte, headers http.Header) codexFingerprintCapture {
	t.Helper()
	captured := make(chan codexFingerprintCapture, 1)
	const completed = `{"type":"response.completed","response":{"id":"resp_fp","object":"response","status":"completed","model":"gpt-5.5","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if websocket.IsWebSocketUpgrade(r) {
			if strings.HasPrefix(flow, "fallback") {
				w.WriteHeader(http.StatusUpgradeRequired)
				return
			}
			upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				t.Errorf("upgrade: %v", err)
				return
			}
			defer func() { _ = conn.Close() }()
			_, payload, errRead := conn.ReadMessage()
			if errRead != nil {
				t.Errorf("read WS request: %v", errRead)
				return
			}
			captured <- codexFingerprintCapture{r.Header.Clone(), payload, r.URL.Path}
			_ = conn.WriteMessage(websocket.TextMessage, []byte(completed))
			return
		}
		payload, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read HTTP request: %v", err)
			return
		}
		captured <- codexFingerprintCapture{r.Header.Clone(), payload, r.URL.Path}
		if strings.HasSuffix(r.URL.Path, "/compact") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":"cmp_fp","object":"response.compaction","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: "+completed+"\n\n")
	}))
	defer server.Close()
	auth = auth.Clone()
	if auth.Attributes == nil {
		auth.Attributes = map[string]string{}
	}
	auth.Attributes["base_url"] = server.URL
	var runner interface {
		Execute(context.Context, *cliproxyauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error)
		ExecuteStream(context.Context, *cliproxyauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error)
	} = NewCodexExecutor(cfg)
	if strings.HasPrefix(flow, "ws") || strings.HasPrefix(flow, "fallback") {
		runner = NewCodexWebsocketsExecutor(cfg)
	}
	opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, Headers: headers}
	if flow == "compact" {
		opts.Alt = "responses/compact"
	}
	req := cliproxyexecutor.Request{Model: "gpt-5.5", Payload: body}
	if strings.HasSuffix(flow, "stream") {
		result, err := runner.ExecuteStream(context.Background(), auth, req, opts)
		if err != nil {
			t.Fatalf("ExecuteStream: %v", err)
		}
		for chunk := range result.Chunks {
			if chunk.Err != nil {
				t.Fatalf("stream: %v", chunk.Err)
			}
		}
	} else if _, err := runner.Execute(context.Background(), auth, req, opts); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	select {
	case request := <-captured:
		return request
	default:
		t.Fatal("no upstream request captured")
		return codexFingerprintCapture{}
	}
}

func TestCodexAccountFingerprintTransportIsolation(t *testing.T) {
	const wantInstallation = "866b0bfd-ca88-43f8-aaf7-02053e402033"
	const wantUA = "codex-tui/0.166.0 (Mac OS 26.5.1; arm64) vscode/1.104.2 (codex-tui; 0.166.0)"
	for _, flow := range []string{"http", "http-stream", "compact", "ws", "ws-stream", "fallback", "fallback-stream"} {
		for _, variant := range []string{"initial", "duplicate-refreshed", "other-account"} {
			t.Run(flow+"/"+variant, func(t *testing.T) {
				auth := &cliproxyauth.Auth{ID: variant, Provider: "codex", Metadata: map[string]any{"account_id": "acct-one", "chatgpt_user_id": "user-one", "access_token": variant, "codex_fingerprint_seed": "11111111-1111-4111-8111-111111111111"}}
				if variant == "other-account" {
					auth.Metadata["account_id"] = "acct-two"
				}
				headers := http.Header{}
				headers.Set("User-Agent", "different-client/"+variant)
				headers.Set("Version", "0.100.0")
				headers.Set("Session-Id", "client-session-"+variant)
				headers.Set("Thread-Id", "client-thread-"+variant)
				headers.Set("X-Codex-Turn-Metadata", `{"installation_id":"caller-device","turn_id":"caller-turn","window_id":"caller-window","workspaces":{"中🚀":{"has_changes":true}}}`)
				body := []byte(`{"model":"gpt-5.5","input":[],"client_metadata":{"x-codex-installation-id":"caller-device","traceparent":"preserve"}}`)
				got := captureCodexFingerprintFlow(t, flow, &config.Config{}, auth, body, headers)
				installation := gjson.GetBytes(got.body, "client_metadata.x-codex-installation-id").String()
				if variant == "other-account" {
					if installation == "" || installation == wantInstallation || installation == "caller-device" {
						t.Fatalf("another account did not get its own installation: %q", installation)
					}
				} else if installation != wantInstallation || got.headers.Get("User-Agent") != wantUA {
					t.Fatalf("same account identity changed: installation=%q UA=%q", installation, got.headers.Get("User-Agent"))
				}
				if got.headers.Get("Version") != "0.166.0" || got.headers.Get("Originator") != "codex-tui" {
					t.Fatal("client version/originator did not match the verified release")
				}
				turn := got.headers.Get("X-Codex-Turn-Metadata")
				if gjson.Get(turn, "installation_id").String() != installation || gjson.GetBytes(got.body, "client_metadata.x-codex-turn-metadata").String() != turn {
					t.Fatal("body and header installation metadata disagree")
				}
				if strings.ContainsFunc(turn, func(r rune) bool { return r > 127 }) || !gjson.Get(turn, "workspaces.中🚀.has_changes").Bool() {
					t.Fatal("ASCII-compatible workspace metadata lost its meaning")
				}
				if got.headers.Get("Session-Id") != "client-session-"+variant || got.headers.Get("Thread-Id") != "client-thread-"+variant || gjson.Get(turn, "turn_id").String() != "caller-turn" || got.headers.Get("X-Codex-Window-Id") != "caller-window" {
					t.Fatal("account binding collapsed or rotated conversation identifiers")
				}
				if flow == "compact" {
					if got.path != "/responses/compact" || got.headers.Get("X-Codex-Installation-Id") != installation || got.headers.Get("X-Client-Request-Id") != "" {
						t.Fatal("incorrect legacy compact header contract")
					}
				} else if got.path != "/responses" || got.headers.Get("X-Codex-Installation-Id") != "" {
					t.Fatal("ordinary Responses contains a standalone installation header")
				}
				if strings.HasPrefix(flow, "ws") {
					if got.headers.Get("OpenAI-Beta") != codexResponsesWebsocketBetaHeaderValue || got.headers.Get("X-Client-Request-Id") != "" {
						t.Fatal("incorrect WebSocket handshake contract")
					}
				} else if flow != "compact" && got.headers.Get("X-Client-Request-Id") != "client-thread-"+variant {
					t.Fatal("HTTP request ID must match the thread ID")
				}
			})
		}
	}
}

func TestCodexAccountFingerprintPayloadAndPassthrough(t *testing.T) {
	for _, flow := range []string{"http", "http-stream", "compact", "ws", "ws-stream", "fallback", "fallback-stream"} {
		for _, mode := range []string{"filter", "override", "disabled", "api-key"} {
			t.Run(flow+"/"+mode, func(t *testing.T) {
				cfg := &config.Config{}
				auth := &cliproxyauth.Auth{ID: "account", Provider: "codex", Metadata: map[string]any{"account_id": "acct-one", "access_token": "synthetic-token"}}
				switch mode {
				case "filter":
					cfg.Payload.Filter = []config.PayloadFilterRule{{Models: []config.PayloadModelRule{{Name: "gpt-5.5"}}, Params: []string{"client_metadata"}}}
				case "override":
					cfg.Payload.Override = []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: "gpt-5.5"}}, Params: map[string]any{"client_metadata": map[string]string{"x-codex-installation-id": "operator-install", "session_id": "operator-session", "thread_id": "operator-thread", "x-codex-turn-metadata": `{"installation_id":"operator-install"}`}}}}
				case "disabled":
					auth.Attributes = map[string]string{cliproxyauth.AttributeCodexDisableCloaking: "true"}
				case "api-key":
					auth.Attributes = map[string]string{"api_key": "synthetic-key"}
				}
				headers := http.Header{"User-Agent": {"caller-agent"}, "Version": {"caller-version"}}
				headers.Set("X-Codex-Turn-Metadata", `{"installation_id":"caller-install"}`)
				body := []byte(`{"model":"gpt-5.5","input":[],"client_metadata":{"x-codex-installation-id":"caller-install"}}`)
				got := captureCodexFingerprintFlow(t, flow, cfg, auth, body, headers)
				switch mode {
				case "filter":
					if gjson.GetBytes(got.body, "client_metadata").Exists() || got.headers.Get("X-Codex-Turn-Metadata") != "" || got.headers.Get("X-Codex-Installation-Id") != "" {
						t.Fatal("fingerprint metadata restored after payload filter")
					}
				case "override":
					if gjson.GetBytes(got.body, "client_metadata.x-codex-installation-id").String() != "operator-install" || got.headers.Get("Session-Id") != "operator-session" || gjson.Get(got.headers.Get("X-Codex-Turn-Metadata"), "installation_id").String() != "operator-install" {
						t.Fatal("fingerprint overwrote the final payload override")
					}
				default:
					if gjson.GetBytes(got.body, "client_metadata.x-codex-installation-id").String() != "caller-install" || gjson.GetBytes(got.body, "client_metadata.turn_id").Exists() {
						t.Fatal("passthrough credential received account fingerprint metadata")
					}
					if mode == "disabled" && (got.headers.Get("User-Agent") != "caller-agent" || got.headers.Get("Version") != "caller-version") {
						t.Fatal("explicitly disabled identity rewrite still changed client identity")
					}
				}
			})
		}
	}
}

func TestCodexAccountFingerprintClipsDuplicateIdentityHeaders(t *testing.T) {
	headers := http.Header{"user-agent": {"caller"}, "version": {"old"}, "originator": {"caller"}}
	auth := &cliproxyauth.Auth{Metadata: map[string]any{"account_id": "acct-one", "chatgpt_user_id": "user-one"}}
	applyCodexCloakingHeaders(headers, &config.Config{}, auth)
	if len(headers) != 3 || headers.Get("User-Agent") != helps.CodexIdentityForAuth(auth).UserAgent || headers.Get("Version") != "0.166.0" {
		t.Fatal("case-variant identity headers can shadow the account profile")
	}
}

func TestCodexAccountFingerprintPreparedAuxiliaryRequest(t *testing.T) {
	auth := &cliproxyauth.Auth{Provider: "codex", Metadata: map[string]any{"account_id": "acct-one", "chatgpt_user_id": "user-one", "access_token": "synthetic"}}
	req, err := http.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/alpha/search", strings.NewReader(`{"query":"hello"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("User-Agent", "endpoint-specific-agent")
	req.Header.Set("X-Codex-Turn-Metadata", `{"installation_id":"caller-install","session_id":"keep-session"}`)
	if err := NewCodexExecutor(&config.Config{}).PrepareRequest(req, auth); err != nil {
		t.Fatal(err)
	}
	if gjson.Get(req.Header.Get("X-Codex-Turn-Metadata"), "installation_id").String() != "866b0bfd-ca88-43f8-aaf7-02053e402033" || gjson.Get(req.Header.Get("X-Codex-Turn-Metadata"), "session_id").String() != "keep-session" || req.Header.Get("User-Agent") != "endpoint-specific-agent" {
		t.Fatal("auxiliary request did not preserve endpoint headers with the account installation")
	}
	body, err := io.ReadAll(req.Body)
	if err != nil || string(body) != `{"query":"hello"}` {
		t.Fatal("auxiliary request body changed")
	}
}
