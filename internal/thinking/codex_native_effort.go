package thinking

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// normalizeNativeCodexNoneEffort keeps native baselines and in-turn updates
// separate while using canonical validation for an unsupported disabled effort.
func normalizeNativeCodexNoneEffort(body []byte, modelInfo *registry.ModelInfo, applier ProviderApplier) ([]byte, error) {
	if modelInfo == nil || IsUserDefinedModel(modelInfo) || modelInfo.Thinking == nil ||
		modelInfo.Thinking.ZeroAllowed || HasLevel(modelInfo.Thinking.Levels, string(LevelNone)) ||
		!bytes.Contains(body, []byte("none")) || !gjson.ValidBytes(body) {
		return body, nil
	}
	paths := []string{"reasoning.effort"}
	for index, item := range gjson.GetBytes(body, "input").Array() {
		if item.Get("type").String() == "configuration_update" {
			paths = append(paths, "input."+strconv.Itoa(index)+".reasoning.effort")
		}
	}
	var replacement string
	for _, path := range paths {
		value := gjson.GetBytes(body, path)
		if value.Type != gjson.String || strings.TrimSpace(value.String()) != string(LevelNone) {
			continue
		}
		if replacement == "" {
			validated, err := ValidateConfig(ThinkingConfig{Mode: ModeNone}, modelInfo, "codex", "codex", false)
			if err != nil || validated == nil {
				return body, err
			}
			applied, err := applier.Apply([]byte(`{"reasoning":{"effort":"none"}}`), *validated, modelInfo)
			if err != nil {
				return body, err
			}
			replacement = gjson.GetBytes(applied, "reasoning.effort").String()
			if replacement == "" || replacement == string(LevelNone) {
				return body, nil
			}
		}
		updated, err := sjson.SetBytes(body, path, replacement)
		if err != nil {
			return body, err
		}
		body = updated
	}
	return body, nil
}
