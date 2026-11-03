package thinking

import (
	"strconv"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// normalizeNativeCodexMinimumEffort keeps native baselines and in-turn updates
// separate while using canonical validation for unsupported none/minimal effort.
func normalizeNativeCodexMinimumEffort(body []byte, modelInfo *registry.ModelInfo, applier ProviderApplier) ([]byte, error) {
	if modelInfo == nil || IsUserDefinedModel(modelInfo) || modelInfo.Thinking == nil ||
		!gjson.ValidBytes(body) {
		return body, nil
	}
	paths := []string{"reasoning.effort"}
	for index, item := range gjson.GetBytes(body, "input").Array() {
		if item.Get("type").String() == "configuration_update" {
			paths = append(paths, "input."+strconv.Itoa(index)+".reasoning.effort")
		}
	}
	replacements := make(map[ThinkingLevel]string)
	for _, path := range paths {
		value := gjson.GetBytes(body, path)
		if value.Type != gjson.String {
			continue
		}
		level := ThinkingLevel(strings.ToLower(strings.TrimSpace(value.String())))
		config := ThinkingConfig{Mode: ModeLevel, Level: level}
		switch level {
		case LevelNone:
			if modelInfo.Thinking.ZeroAllowed || HasLevel(modelInfo.Thinking.Levels, string(LevelNone)) {
				continue
			}
			config = ThinkingConfig{Mode: ModeNone}
		case LevelMinimal:
			if HasLevel(modelInfo.Thinking.Levels, string(LevelMinimal)) {
				continue
			}
		default:
			continue
		}
		replacement, cached := replacements[level]
		if !cached {
			validated, err := ValidateConfig(config, modelInfo, "codex", "codex", false)
			if err != nil || validated == nil {
				return body, err
			}
			applied, err := applier.Apply([]byte(`{}`), *validated, modelInfo)
			if err != nil {
				return body, err
			}
			replacement = gjson.GetBytes(applied, "reasoning.effort").String()
			replacements[level] = replacement
		}
		if replacement == "" || replacement == string(level) {
			continue
		}
		updated, err := sjson.SetBytes(body, path, replacement)
		if err != nil {
			return body, err
		}
		body = updated
	}
	return body, nil
}
