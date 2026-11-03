package thinking_test

import (
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/thinking"
	_ "github.com/router-for-me/CLIProxyAPI/v8/internal/thinking/provider/codex"
	"github.com/tidwall/gjson"
)

func TestCodexNativeNoneUsesCanonicalCapabilities(t *testing.T) {
	for _, mode := range []string{"unsupported", "supported", "custom"} {
		t.Run(mode, func(t *testing.T) {
			info := &registry.ModelInfo{ID: "fixture", SupportConfigurationUpdate: true, Thinking: &registry.ThinkingSupport{Levels: []string{"low", "medium", "high"}}}
			if mode == "supported" {
				info.Thinking.ZeroAllowed = true
			} else if mode == "custom" {
				info.UserDefined = true
			}
			body := []byte(`{"reasoning":{"effort":"none","summary":"auto"},"input":[{"type":"configuration_update","reasoning":{"effort":"none"},"tools":[]},{"type":"configuration_update","reasoning":{"effort":"high"}},{"role":"user","content":"continue"}]}`)
			snapshot := string(body)
			got, err := thinking.ApplyThinkingWithModelInfoAndSummary(body, body, "fixture", "openai-response", "codex", "codex", info, thinking.SummaryConfig{})
			if err != nil {
				t.Fatal(err)
			}
			want := "low"
			if mode != "unsupported" {
				want = "none"
			}
			if gjson.GetBytes(got, "reasoning.effort").String() != want || gjson.GetBytes(got, "input.0.reasoning.effort").String() != want || gjson.GetBytes(got, "input.1.reasoning.effort").String() != "high" || gjson.GetBytes(got, "reasoning.summary").String() != "auto" || !gjson.GetBytes(got, "input.0.tools").IsArray() {
				t.Fatalf("native reasoning capabilities or independent updates changed incorrectly: %s", got)
			}
			if string(body) != snapshot {
				t.Fatal("source payload mutated")
			}
		})
	}
}

func TestCodexNativeNoneUpdateWithExplicitSuffix(t *testing.T) {
	info := &registry.ModelInfo{ID: "fixture", SupportConfigurationUpdate: true, Thinking: &registry.ThinkingSupport{Levels: []string{"low", "medium", "high"}}}
	body := []byte(`{"reasoning":{"effort":"none"},"input":[{"type":"configuration_update","reasoning":{"effort":"none"}}]}`)
	got, err := thinking.ApplyThinkingWithModelInfoAndSummary(body, body, "fixture(high)", "openai-response", "codex", "codex", info, thinking.SummaryConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if gjson.GetBytes(got, "reasoning.effort").String() != "high" || gjson.GetBytes(got, "input.0.reasoning.effort").String() != "low" {
		t.Fatalf("suffix or in-turn capability normalization failed: %s", got)
	}
}

func TestCodexNativeMinimalUsesCanonicalCapabilities(t *testing.T) {
	for _, mode := range []string{"unsupported", "supported", "none supported", "zero allowed", "custom", "unknown", "no thinking"} {
		t.Run(mode, func(t *testing.T) {
			info := &registry.ModelInfo{ID: "fixture", SupportConfigurationUpdate: true, Thinking: &registry.ThinkingSupport{Levels: []string{"high", "low", "medium", "xhigh", "max"}}}
			wantMinimal, wantNone := "low", "low"
			switch mode {
			case "supported":
				info.Thinking.Levels = append(info.Thinking.Levels, "minimal")
				wantMinimal, wantNone = "minimal", "minimal"
			case "none supported":
				info.Thinking.Levels = append(info.Thinking.Levels, "none")
				wantNone = "none"
			case "zero allowed":
				info.Thinking.ZeroAllowed = true
				wantNone = "none"
			case "custom":
				info.UserDefined = true
				wantMinimal, wantNone = "minimal", "none"
			case "unknown":
				info = nil
				wantMinimal, wantNone = "minimal", "none"
			case "no thinking":
				info.Thinking = nil
				wantMinimal, wantNone = "minimal", "none"
			}
			body := []byte(`{"reasoning":{"effort":"minimal","summary":"auto"},"input":[{"type":"configuration_update","reasoning":{"effort":"none"},"tools":[]},{"type":"configuration_update","reasoning":{"effort":"minimal"}},{"type":"configuration_update","reasoning":{"effort":"high"}},{"type":"reasoning","encrypted_content":"ciphertext","summary":[]},{"role":"user","content":"minimal and none","sequence":9007199254740993}]}`)
			snapshot := string(body)
			got, err := thinking.ApplyThinkingWithModelInfoAndSummary(body, body, "fixture", "openai-response", "codex", "codex", info, thinking.SummaryConfig{})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "unknown" {
				// Unknown targets do not support native configuration updates.
				if gjson.GetBytes(got, "reasoning.effort").String() != "high" || len(gjson.GetBytes(got, "input").Array()) != 2 {
					t.Fatalf("unknown model update fallback changed: %s", got)
				}
			} else {
				want := strings.ReplaceAll(snapshot, `"effort":"minimal"`, `"effort":"`+wantMinimal+`"`)
				want = strings.ReplaceAll(want, `"effort":"none"`, `"effort":"`+wantNone+`"`)
				if string(got) != want {
					t.Fatalf("native history changed: got %s, want %s", got, want)
				}
			}
			if string(body) != snapshot {
				t.Fatal("source payload mutated")
			}
		})
	}
}

func TestCodexNativeMinimalUpdateWithExplicitSuffix(t *testing.T) {
	info := &registry.ModelInfo{ID: "fixture", SupportConfigurationUpdate: true, Thinking: &registry.ThinkingSupport{Levels: []string{"low", "medium", "high"}}}
	for _, tc := range []struct{ suffix, want string }{{"minimal", "low"}, {"high", "high"}} {
		t.Run(tc.suffix, func(t *testing.T) {
			body := []byte(`{"reasoning":{"effort":"high"},"input":[{"type":"configuration_update","reasoning":{"effort":"minimal"}}]}`)
			got, err := thinking.ApplyThinkingWithModelInfoAndSummary(body, body, "fixture("+tc.suffix+")", "openai-response", "codex", "codex", info, thinking.SummaryConfig{})
			if err != nil {
				t.Fatal(err)
			}
			if gjson.GetBytes(got, "reasoning.effort").String() != tc.want || gjson.GetBytes(got, "input.0.reasoning.effort").String() != "low" {
				t.Fatalf("suffix or in-turn capability normalization failed: %s", got)
			}
		})
	}
}
