package helps

import (
	"net/http"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// EnsureCodexLiteReasoningContext supplies the Lite wire requirement before
// payload configuration. Effort, summary and non-Lite requests remain intact.
func EnsureCodexLiteReasoningContext(body []byte, headers http.Header) []byte {
	if !util.IsCodexResponsesLiteRequest(body, headers) || gjson.GetBytes(body, "reasoning.context").String() == "all_turns" {
		return body
	}
	updated, err := sjson.SetBytes(body, "reasoning.context", "all_turns")
	if err != nil {
		return body
	}
	return updated
}
