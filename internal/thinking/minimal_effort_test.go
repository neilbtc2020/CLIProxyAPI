package thinking_test

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/thinking"
	_ "github.com/router-for-me/CLIProxyAPI/v8/internal/thinking/provider/openai"
	"github.com/tidwall/gjson"
)

func TestMinimalEffortUsesLowestSupportedLevel(t *testing.T) {
	for _, tc := range []struct {
		name   string
		levels []string
		want   string
	}{
		{name: "reported levels", levels: []string{"low", "medium", "high", "xhigh", "max"}, want: "low"},
		{name: "unsorted levels and mode markers", levels: []string{"none", "max", "auto", " HIGH ", "medium"}, want: "medium"},
		{name: "minimal supported", levels: []string{"high", "minimal", "low"}, want: "minimal"},
	} {
		for _, format := range []string{"openai", "codex", "openai-response"} {
			for _, suffix := range []string{"", "(minimal)"} {
				t.Run(tc.name+"/"+format+"/"+suffix, func(t *testing.T) {
					info := &registry.ModelInfo{ID: "fixture", Thinking: &registry.ThinkingSupport{Levels: tc.levels}}
					body := []byte(`{"reasoning":{"effort":"minimal"},"input":"hello"}`)
					path := "reasoning.effort"
					if format == "openai" {
						body = []byte(`{"reasoning_effort":"minimal","messages":[{"role":"user","content":"hello"}]}`)
						path = "reasoning_effort"
					}
					got, err := thinking.ApplyThinkingWithModelInfoAndSummary(body, body, "fixture"+suffix, format, format, format, info, thinking.SummaryConfig{})
					if err != nil {
						t.Fatal(err)
					}
					if effort := gjson.GetBytes(got, path).String(); effort != tc.want {
						t.Fatalf("effort = %q, want %q; body=%s", effort, tc.want, got)
					}
				})
			}
		}
	}
}

func TestMinimalEffortDoesNotRelaxOtherSameFamilyLevels(t *testing.T) {
	info := &registry.ModelInfo{ID: "fixture", Thinking: &registry.ThinkingSupport{Levels: []string{"low", "medium", "high"}}}
	for _, level := range []thinking.ThinkingLevel{thinking.LevelXHigh, thinking.LevelMax, "unknown"} {
		t.Run(string(level), func(t *testing.T) {
			_, err := thinking.ValidateConfig(thinking.ThinkingConfig{Mode: thinking.ModeLevel, Level: level}, info, "codex", "codex", false)
			if err == nil {
				t.Fatalf("unsupported %q should still fail validation", level)
			}
		})
	}
}
