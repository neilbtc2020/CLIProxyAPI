package helps

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

func TestCodexStatelessReasoningRetainsCiphertextWithoutExternalID(t *testing.T) {
	for _, id := range []string{`"rs_wrong"`, `"msg_wrong"`, `null`, `123`, `"rs_` + strings.Repeat("x", 100) + `"`} {
		body := []byte(`{"store":false,"input":[{"type":"reasoning","id":` + id + `,"encrypted_content":"opaque-ciphertext","summary":[{"type":"summary_text","text":"retain"}],"future":{"n":9007199254740993}},{"type":"message","id":"msg_keep","role":"user","content":"continue"}]}`)
		before := string(body)
		got := SanitizeCodexInputItemIDs(body)
		if len(gjson.GetBytes(got, "input").Array()) != 2 || gjson.GetBytes(got, "input.0.id").Exists() || gjson.GetBytes(got, "input.0.encrypted_content").String() != "opaque-ciphertext" || gjson.GetBytes(got, "input.0.summary.0.text").String() != "retain" || gjson.GetBytes(got, "input.0.future.n").Raw != "9007199254740993" {
			t.Fatalf("encrypted reasoning was lost or changed: %s", got)
		}
		if string(body) != before || string(SanitizeCodexInputItemIDs(got)) != string(got) {
			t.Fatal("normalization mutated its input or was not idempotent")
		}
	}
}

func TestCodexWebSearchHistoryIDPrefix(t *testing.T) {
	body := []byte(`{"input":[{"type":"web_search_call","id":"msg_external","status":"completed","action":{"type":"search","query":"sample"},"call_id":"unchanged"},{"type":"web_search_call","id":"ws_existing"}]}`)
	got := SanitizeCodexInputItemIDs(body)
	for path, want := range map[string]string{"input.0.id": "ws_msg_external", "input.0.call_id": "unchanged", "input.0.action.query": "sample", "input.1.id": "ws_existing"} {
		if value := gjson.GetBytes(got, path).String(); value != want {
			t.Fatalf("%s = %q, want %q", path, value, want)
		}
	}
}

func TestCodexLiteContextFromHeaderAndMetadata(t *testing.T) {
	for _, marker := range []string{"header", "string", "boolean", "ordinary"} {
		t.Run(marker, func(t *testing.T) {
			headers := http.Header{}
			metadata := ""
			if marker == "header" {
				headers.Set("X-OpenAI-Internal-Codex-Responses-Lite", "true")
			} else if marker != "ordinary" {
				value := `"true"`
				if marker == "boolean" {
					value = "true"
				}
				metadata = `,"client_metadata":{"ws_request_header_x_openai_internal_codex_responses_lite":` + value + `}`
			}
			body := []byte(fmt.Sprintf(`{"reasoning":{"effort":"high","summary":"auto","context":"current_turn"}%s}`, metadata))
			got := EnsureCodexLiteReasoningContext(body, headers)
			want := "all_turns"
			if marker == "ordinary" {
				want = "current_turn"
			}
			if gjson.GetBytes(got, "reasoning.context").String() != want || gjson.GetBytes(got, "reasoning.effort").String() != "high" || gjson.GetBytes(got, "reasoning.summary").String() != "auto" {
				t.Fatalf("Lite normalization lost independent reasoning fields: %s", got)
			}
		})
	}
}
