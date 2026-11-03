package helps

import (
	"strconv"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// NormalizeCodexToolChoice unwraps scalar policies without broadening structured
// tool restrictions. Native in-turn updates retain their independent choices.
func NormalizeCodexToolChoice(body []byte) []byte {
	paths := []string{"tool_choice"}
	for index, item := range gjson.GetBytes(body, "input").Array() {
		if item.Get("type").String() == "configuration_update" {
			paths = append(paths, "input."+strconv.Itoa(index)+".tool_choice")
		}
	}
	for _, path := range paths {
		choice := gjson.GetBytes(body, path)
		if !choice.IsObject() || len(choice.Map()) != 1 {
			continue
		}
		policy := choice.Get("type")
		if policy.Type != gjson.String {
			continue
		}
		switch policy.String() {
		case "auto", "none", "required":
			if updated, err := sjson.SetBytes(body, path, policy.String()); err == nil {
				body = updated
			}
		}
	}
	return body
}
