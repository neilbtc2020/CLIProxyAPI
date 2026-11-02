package thinking_test

import (
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
