package helps

import (
	"strings"
	"testing"
)

func TestNormalizeCodexToolChoicePreservesRestrictionsAndHistory(t *testing.T) {
	for _, choice := range []string{`{"type":"auto"}`, `{"type":"none"}`, `{"type":"required"}`, `"auto"`, `{"type":"function","name":"lookup"}`, `{"type":"allowed_tools","mode":"auto","tools":[]}`, `{"type":"auto","future_restriction":true}`, `{"type":"future"}`, `null`} {
		t.Run(choice, func(t *testing.T) {
			body := `{"tool_choice":` + choice + `,"input":[{"type":"configuration_update","tool_choice":` + choice + `},{"type":"message","content":"auto","tool_choice":{"type":"auto"}}],"metadata":{"integer":9007199254740993}}`
			want := body
			for _, policy := range []string{"auto", "none", "required"} {
				if choice == `{"type":"`+policy+`"}` {
					want = strings.Replace(want, `"tool_choice":`+choice, `"tool_choice":"`+policy+`"`, 2)
				}
			}
			input := []byte(body)
			got := NormalizeCodexToolChoice(input)
			if string(got) != want || string(input) != body {
				t.Fatalf("normalization changed restrictions/history: got %s, want %s", got, want)
			}
			if again := NormalizeCodexToolChoice(got); string(again) != want {
				t.Fatal("normalization is not idempotent")
			}
		})
	}
}
