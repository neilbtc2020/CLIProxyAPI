package chat_completions

import (
	"fmt"
	"testing"

	"github.com/tidwall/gjson"
)

func TestToolResultsSurviveInterleavedNotices(t *testing.T) {
	for _, role := range []string{"assistant", "developer", "system"} {
		t.Run(role, func(t *testing.T) {
			body := []byte(fmt.Sprintf(`{"messages":[{"role":"user","content":"start"},{"role":"assistant","tool_calls":[{"id":"call_a","type":"function","function":{"name":"lookup","arguments":"{}"}},{"id":"call_b","type":"function","function":{"name":"lookup","arguments":"{}"}}]},{"role":"tool","tool_call_id":"call_b","content":"second"},{"role":%q,"content":"notice"},{"role":"tool","tool_call_id":"call_a","content":"first"},{"role":"user","content":"continue"}]}`, role))
			got, err := ConvertOpenAIRequestToCodex("gpt-6.1-sol", body, true)
			if err != nil {
				t.Fatal(err)
			}
			calls, outputs := 0, map[string]string{}
			for _, item := range gjson.GetBytes(got, "input").Array() {
				if item.Get("type").String() == "function_call" {
					calls++
				} else if item.Get("type").String() == "function_call_output" {
					outputs[item.Get("call_id").String()] = item.Get("output").String()
				}
			}
			if calls != 2 || outputs["call_a"] != "first" || outputs["call_b"] != "second" {
				t.Fatalf("interleaved notice dropped or mispaired a real tool result: %s", got)
			}
		})
	}
}
