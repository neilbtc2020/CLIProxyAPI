package helps

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf16"

	"github.com/google/uuid"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// CodexClientVersion tracks the verified stable openai/codex release, not main.
const CodexClientVersion = "0.166.0"
const CodexOriginator = "codex-tui"
const CodexUserAgent = "codex-tui/" + CodexClientVersion + " (Linux Unknown; x86_64) xterm-256color (codex-tui; " + CodexClientVersion + ")"

// Keep these lists and namespaces aligned with cpa-account-config-manager.
// Reordering them would rotate existing accounts' machine profiles.
var codexAccountOSVersions = [...]string{"26.6.2", "26.6.1", "26.6.0", "26.5.2", "26.5.1", "15.7.7"}
var codexAccountTerminals = [...]string{"iTerm.app/3.6.11", "iTerm.app/3.5.14", "Apple_Terminal/455", "Apple_Terminal/453", "WezTerm/20240203-110809-5046fc22", "ghostty/1.1.3", "vscode/1.104.2", "tmux/3.5a", "unknown"}

type CodexClientIdentity struct {
	UserAgent      string
	InstallationID string
}

// CodexAccountIdentitySeed uses account identity rather than rotating token bytes
// or credential filenames. It matches the account manager's existing contract.
func CodexAccountIdentitySeed(auth *cliproxyauth.Auth) string {
	if auth == nil {
		return ""
	}
	accountID := codexString(auth.Metadata, "account_id", "chatgpt_account_id")
	userID := codexString(auth.Metadata, "chatgpt_user_id", "user_id")
	for _, key := range []string{"id_token", "idToken", "access_token", "accessToken"} {
		claims := codexIdentityClaims(auth.Metadata[key])
		account, _ := claims["https://api.openai.com/auth"].(map[string]any)
		if accountID == "" {
			accountID = codexString(account, "chatgpt_account_id", "account_id")
		}
		if userID == "" {
			userID = codexString(account, "chatgpt_user_id", "user_id")
		}
	}
	if accountID != "" {
		return codexStableUUID("cpa:codex-account:v1:" + accountID + ":user:" + userID)
	}
	if seed := codexUUID(codexString(auth.Metadata, "codex_fingerprint_seed")); seed != "" {
		return seed
	}
	// Legacy opaque credentials have no recoverable account identity. A stable
	// credential ID is the last resort; never hash access/refresh tokens.
	if id := strings.TrimSpace(auth.ID); id != "" {
		return codexStableUUID("cpa:codex-credential:v1:" + id)
	}
	return ""
}

func codexIdentityClaims(value any) map[string]any {
	if claims, ok := value.(map[string]any); ok {
		return claims
	}
	raw, ok := value.(string)
	raw = strings.TrimSpace(raw)
	if !ok || len(raw) > 64<<10 {
		return nil
	}
	if json.Valid([]byte(raw)) {
		return codexJSONObject([]byte(raw))
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil
	}
	return codexJSONObject(payload)
}

func CodexIdentityForAuth(auth *cliproxyauth.Auth) CodexClientIdentity {
	identity := CodexClientIdentity{UserAgent: CodexUserAgent}
	seed := CodexAccountIdentitySeed(auth)
	if seed == "" {
		return identity
	}
	sum := sha256.Sum256([]byte("cli-proxy-api:codex-cli-identity:" + seed))
	osVersion := codexAccountOSVersions[int(binary.BigEndian.Uint16(sum[:2]))%len(codexAccountOSVersions)]
	terminal := codexAccountTerminals[int(binary.BigEndian.Uint16(sum[2:4]))%len(codexAccountTerminals)]
	arch := "arm64"
	if sum[4]%10 == 0 {
		arch = "x86_64"
	}
	identity.UserAgent = fmt.Sprintf("%s/%s (Mac OS %s; %s) %s (%s; %s)", CodexOriginator, CodexClientVersion, osVersion, arch, terminal, CodexOriginator, CodexClientVersion)
	identity.InstallationID = codexUUID(codexString(auth.Metadata, "device_id"))
	if identity.InstallationID == "" {
		identity.InstallationID = codexStableUUID("sub2api:codex-install-id:v2:" + seed)
	}
	return identity
}

// BindCodexInstallationHeaders also covers header-only calls such as images or
// search. It rewrites existing device fields without inventing Responses fields
// on endpoints with a different request schema.
func BindCodexInstallationHeaders(headers http.Header, identity CodexClientIdentity) {
	if identity.InstallationID == "" {
		return
	}
	if raw := codexHeader(headers, "X-Codex-Turn-Metadata"); raw != "" {
		turn := codexJSONObject([]byte(raw))
		codexSetValue(turn, "installation_id", identity.InstallationID)
		codexDeleteHeader(headers, "X-Codex-Turn-Metadata")
		headers.Set("X-Codex-Turn-Metadata", codexASCIIJSON(turn))
	}
	if codexHeader(headers, "X-Codex-Installation-Id") != "" {
		codexDeleteHeader(headers, "X-Codex-Installation-Id")
		headers.Set("X-Codex-Installation-Id", identity.InstallationID)
	}
}

// ApplyCodexFingerprintMetadata runs before user payload rules. Session and turn
// identifiers are preserved; only installation identity is bound to the account.
func ApplyCodexFingerprintMetadata(body []byte, source http.Header, identity CodexClientIdentity) []byte {
	if identity.InstallationID == "" || !gjson.ValidBytes(body) {
		return body
	}
	metadata := codexJSONObject([]byte(gjson.GetBytes(body, "client_metadata").Raw))
	turn := codexJSONObject([]byte(codexHeader(source, "X-Codex-Turn-Metadata")))
	for key, value := range codexJSONObject([]byte(codexString(metadata, "x-codex-turn-metadata"))) {
		turn[key] = value
	}
	sessionID := codexFirst(codexString(metadata, "session_id"), codexString(turn, "session_id"), codexHeader(source, "Session-Id"), codexHeader(source, "Session_id"), gjson.GetBytes(body, "prompt_cache_key").String())
	if sessionID == "" {
		sessionID = uuid.NewString()
	}
	threadID := codexFirst(codexString(metadata, "thread_id"), codexString(turn, "thread_id"), codexHeader(source, "Thread-Id"), sessionID)
	windowID := codexFirst(codexString(metadata, "x-codex-window-id"), codexString(turn, "window_id"), codexHeader(source, "X-Codex-Window-Id"))
	if windowID == "" {
		windowID = codexStableUUID("cpa:codex-window:v1:" + identity.InstallationID + ":" + threadID)
	}
	turnID := codexFirst(codexString(metadata, "turn_id"), codexString(turn, "turn_id"))
	if turnID == "" {
		turnID = uuid.NewString()
	}
	for key, value := range map[string]string{"installation_id": identity.InstallationID, "session_id": sessionID, "thread_id": threadID, "turn_id": turnID, "window_id": windowID} {
		codexSetValue(turn, key, value)
	}
	for key, value := range map[string]string{"x-codex-installation-id": identity.InstallationID, "session_id": sessionID, "thread_id": threadID, "turn_id": turnID, "x-codex-window-id": windowID, "x-codex-turn-metadata": codexASCIIJSON(turn)} {
		codexSetValue(metadata, key, value)
	}
	if codexString(metadata, "installation_id") != "" {
		codexSetValue(metadata, "installation_id", identity.InstallationID)
	}
	updated, err := sjson.SetBytes(body, "client_metadata", metadata)
	if err != nil {
		return body
	}
	return updated
}

// ApplyCodexFingerprintHeaders projects finalized metadata without mutating the
// business payload. Ordinary Responses has no standalone installation header.
func ApplyCodexFingerprintHeaders(headers http.Header, body []byte, compact, websocket bool) {
	metadata := codexJSONObject([]byte(gjson.GetBytes(body, "client_metadata").Raw))
	for _, name := range []string{"X-Codex-Installation-Id", "X-Codex-Turn-Metadata", "X-Codex-Window-Id", "Session-Id", "Session_id", "Conversation_id", "Thread-Id", "X-Client-Request-Id"} {
		codexDeleteHeader(headers, name)
	}
	for name, key := range map[string]string{"Session-Id": "session_id", "Thread-Id": "thread_id", "X-Codex-Window-Id": "x-codex-window-id"} {
		if value := codexString(metadata, key); value != "" {
			headers.Set(name, value)
		}
	}
	if compact {
		if id := codexString(metadata, "x-codex-installation-id"); id != "" {
			headers.Set("X-Codex-Installation-Id", id)
		}
	} else if !websocket {
		if id := codexString(metadata, "thread_id"); id != "" {
			headers.Set("X-Client-Request-Id", id)
		}
	}
	if raw := codexString(metadata, "x-codex-turn-metadata"); raw != "" && json.Valid([]byte(raw)) {
		turn := codexJSONObject([]byte(raw))
		delete(turn, "tool_namespaces_info")
		headers.Set("X-Codex-Turn-Metadata", codexASCIIJSON(turn))
	}
}

func codexStableUUID(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	id := uuid.UUID(sum[:16])
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return id.String()
}

func codexUUID(raw string) string {
	id, err := uuid.Parse(raw)
	if err != nil || id.Version() != 4 || id.Variant() != uuid.RFC4122 || !strings.EqualFold(raw, id.String()) {
		return ""
	}
	return id.String()
}

func codexJSONObject(raw []byte) map[string]any {
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil || value == nil {
		return map[string]any{}
	}
	return value
}

func codexString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := values[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
		for candidate, raw := range values {
			if value, ok := raw.(string); ok && strings.EqualFold(candidate, key) && strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
		}
	}
	return ""
}

func codexSetValue(values map[string]any, key, value string) {
	for candidate := range values {
		if strings.EqualFold(candidate, key) {
			delete(values, candidate)
		}
	}
	values[key] = value
}

func codexHeader(headers http.Header, name string) string {
	for key, values := range headers {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return strings.TrimSpace(values[0])
		}
	}
	return ""
}

func codexDeleteHeader(headers http.Header, name string) {
	for key := range headers {
		if strings.EqualFold(key, name) {
			delete(headers, key)
		}
	}
}

func codexFirst(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func codexASCIIJSON(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	var ascii strings.Builder
	for _, char := range string(raw) {
		if char <= 0x7f {
			ascii.WriteByte(byte(char))
		} else if char <= 0xffff {
			fmt.Fprintf(&ascii, "\\u%04x", char)
		} else {
			hi, lo := utf16.EncodeRune(char)
			fmt.Fprintf(&ascii, "\\u%04x\\u%04x", hi, lo)
		}
	}
	return ascii.String()
}
