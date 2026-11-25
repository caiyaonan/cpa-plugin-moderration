package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"cpa-moderation/internal/config"
	"cpa-moderation/internal/engine"
	"cpa-moderation/internal/moderation"
	"cpa-moderation/internal/policy"
)

const (
	bizKey   = "sk-poc-image-business"
	otherKey = "sk-poc-other"
)

type fakeModerator struct {
	calls atomic.Int32
	fn    func(items []moderation.Item) (moderation.Verdict, error)
}

func (f *fakeModerator) Moderate(_ context.Context, items []moderation.Item) (moderation.Verdict, error) {
	f.calls.Add(1)
	return f.fn(items)
}

func flagOn(word, category string) func([]moderation.Item) (moderation.Verdict, error) {
	return func(items []moderation.Item) (moderation.Verdict, error) {
		for _, it := range items {
			if strings.Contains(it.Text, word) || strings.Contains(it.URL, word) {
				return moderation.Verdict{Flagged: true, Categories: []string{category}, Calls: 1}, nil
			}
		}
		return moderation.Verdict{Calls: 1}, nil
	}
}

func newTestApp(t *testing.T, mod *fakeModerator, extraYAML string) (*App, string) {
	t.Helper()
	dir := t.TempDir()
	a := NewApp()
	a.logger = nil
	t.Cleanup(a.Shutdown)
	a.newModerator = func(config.Config) (engine.Moderator, *moderation.Client, error) { return mod, nil, nil }
	cfg := fmt.Sprintf("enabled: true\npriority: 1\nstate_file: %q\naudit_file: %q\n%s",
		filepath.ToSlash(filepath.Join(dir, "state.json")), filepath.ToSlash(filepath.Join(dir, "audit.jsonl")), extraYAML)
	reg := call(t, a, MethodPluginRegister, LifecycleRequest{ConfigYAML: []byte(cfg), SchemaVersion: 10})
	if !reg.OK {
		t.Fatalf("register failed: %+v", reg.Error)
	}
	if rt := a.rt.Load(); rt.broken != nil {
		t.Fatalf("configure: %v", rt.broken)
	}
	return a, dir
}

func call(t *testing.T, a *App, method string, payload any) Envelope {
	t.Helper()
	raw, _ := json.Marshal(payload)
	var env Envelope
	if err := json.Unmarshal(a.HandleMethod(method, raw), &env); err != nil {
		t.Fatalf("%s: bad envelope: %v", method, err)
	}
	return env
}

func mgmt(t *testing.T, a *App, method, path string, body any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	env := call(t, a, MethodManagementHandle, ManagementRequest{Method: method, Path: managementBase + path, Body: raw})
	var resp ManagementResponse
	_ = json.Unmarshal(env.Result, &resp)
	var out map[string]any
	_ = json.Unmarshal(resp.Body, &out)
	return resp.StatusCode, out
}

func setupPolicy(t *testing.T, a *App) {
	t.Helper()
	code, out := mgmt(t, a, http.MethodPost, "/keys/sync", map[string]any{"keys": []string{bizKey, otherKey}})
	if code != 200 || out["added"].(float64) != 2 {
		t.Fatalf("sync: %d %v", code, out)
	}
	rev := out["revision"].(float64)
	state := policy.State{
		Revision: int64(rev),
		Rules: []policy.Rule{{ID: "image-business", Enabled: true, Models: []string{"gpt-image-*", "gpt-6*"},
			CheckText: true, CheckImage: true, Wordlists: []string{"biz"}}},
		Wordlists: []policy.Wordlist{{ID: "biz", Enabled: true, Keywords: []string{"SYNTHETICBANNED"}}},
		Keys: []policy.Key{
			{Scope: policy.CallerScope(bizKey), Preview: "x", RuleIDs: []string{"image-business"}},
			{Scope: policy.CallerScope(otherKey), Preview: "y", RuleIDs: []string{}},
		},
	}
	if code, out := mgmt(t, a, http.MethodPut, "/state", state); code != 200 {
		t.Fatalf("put state: %d %v", code, out)
	}
}

func intercept(t *testing.T, a *App, key, format, model, body string) InterceptResponse {
	t.Helper()
	env := call(t, a, MethodRequestInterceptBefore, InterceptRequest{
		RequestID: "req-1", SourceFormat: format, Model: model, RequestedModel: model,
		Headers: http.Header{"Content-Type": {"application/json"}}, Body: []byte(body),
		CallerScope: policy.CallerScope(key),
		Metadata:    map[string]any{"caller_scope": policy.CallerScope(key), "request_path": "/v1/chat/completions"},
	})
	if !env.OK {
		t.Fatalf("intercept must never return an error envelope (host would fail open): %+v", env.Error)
	}
	var resp InterceptResponse
	_ = json.Unmarshal(env.Result, &resp)
	return resp
}

func chat(text string) string {
	b, _ := json.Marshal(map[string]any{"model": "gpt-image-1", "messages": []any{map[string]any{"role": "user", "content": text}}})
	return string(b)
}

func errCode(t *testing.T, r InterceptResponse) string {
	t.Helper()
	var payload map[string]any
	_ = json.Unmarshal(r.ResponseBody, &payload)
	e, _ := payload["error"].(map[string]any)
	if c, ok := e["code"].(string); ok {
		return c
	}
	if s, ok := e["type"].(string); ok {
		return s
	}
	return ""
}

func TestRegistrationMetadataIsComplete(t *testing.T) {
	a, _ := newTestApp(t, &fakeModerator{fn: flagOn("x", "y")}, "")
	var reg Registration
	_ = json.Unmarshal(call(t, a, MethodPluginRegister, LifecycleRequest{}).Result, &reg)
	m := reg.Metadata
	if m.Name == "" || m.Version == "" || m.Author == "" || m.GitHubRepository == "" || !reg.Capabilities.RequestInterceptor {
		t.Fatalf("host rejects incomplete metadata: %+v", reg)
	}
}

func TestMatchedAllowedBlockedAndSkipped(t *testing.T) {
	mod := &fakeModerator{fn: flagOn("FLAGME", "violence")}
	a, dir := newTestApp(t, mod, "")
	setupPolicy(t, a)

	// T01: bound key + matching model + clean content -> allowed, request untouched.
	r := intercept(t, a, bizKey, "openai", "gpt-image-1", chat("a mountain"))
	if r.Terminate || r.ResponseBody != nil {
		t.Fatalf("clean request must pass unchanged: %+v", r)
	}
	if mod.calls.Load() != 1 {
		t.Fatalf("moderator calls=%d", mod.calls.Load())
	}

	// T02: unbound key or unmatched model -> skipped, no moderation call.
	for _, c := range []struct{ key, model string }{{otherKey, "gpt-image-1"}, {bizKey, "mock-chat"}, {"sk-unknown", "gpt-image-1"}} {
		if r := intercept(t, a, c.key, "openai", c.model, chat("FLAGME")); r.Terminate {
			t.Fatalf("%v must be skipped", c)
		}
	}
	if mod.calls.Load() != 1 {
		t.Fatalf("skipped requests must not call the moderator, calls=%d", mod.calls.Load())
	}

	// T05: wordlist hit -> 403 without calling the moderator.
	r = intercept(t, a, bizKey, "openai", "gpt-6-mini", chat("contains ＳＹＮＴＨＥＴＩＣＢＡＮＮＥＤ word"))
	if !r.Terminate || r.StatusCode != 403 || errCode(t, r) != engine.CodeViolation || mod.calls.Load() != 1 {
		t.Fatalf("wordlist: %+v calls=%d", r, mod.calls.Load())
	}
	if strings.Contains(string(r.ResponseBody), "SYNTHETIC") {
		t.Fatal("refusal must not echo the matched word")
	}

	// T06: flagged -> 403 in the client's format.
	r = intercept(t, a, bizKey, "claude", "gpt-6-mini", `{"messages":[{"role":"user","content":"FLAGME"}]}`)
	if !r.Terminate || r.StatusCode != 403 || !strings.Contains(string(r.ResponseBody), `"type":"error"`) ||
		!strings.Contains(string(r.ResponseBody), "permission_error") {
		t.Fatalf("claude refusal: %d %s", r.StatusCode, r.ResponseBody)
	}
	r = intercept(t, a, bizKey, "gemini", "gpt-6-mini", `{"contents":[{"role":"user","parts":[{"text":"FLAGME"}]}]}`)
	if r.StatusCode != 403 || !strings.Contains(string(r.ResponseBody), "PERMISSION_DENIED") {
		t.Fatalf("gemini refusal: %s", r.ResponseBody)
	}

	// Invalid body -> 400; unsupported content -> 400.
	if r := intercept(t, a, bizKey, "openai", "gpt-image-1", "{nope"); r.StatusCode != 400 {
		t.Fatalf("invalid: %+v", r)
	}
	audio := `{"messages":[{"role":"user","content":[{"type":"input_audio","input_audio":{}}]}]}`
	if r := intercept(t, a, bizKey, "openai", "gpt-image-1", audio); r.StatusCode != 400 {
		t.Fatalf("unsupported: %+v", r)
	}

	// Audit trail exists and contains no content.
	raw, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil || strings.Count(string(raw), "\n") < 5 {
		t.Fatalf("audit: %v %q", err, raw)
	}
	for _, leak := range []string{"FLAGME", "mountain", "SYNTHETIC", bizKey} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("audit log leaks %q", leak)
		}
	}
	code, out := mgmt(t, a, http.MethodGet, "/status", nil)
	if code != 200 || out["healthy"] != true {
		t.Fatalf("status: %v", out)
	}
}

func TestProviderFailureFailsClosed(t *testing.T) {
	mod := &fakeModerator{fn: func([]moderation.Item) (moderation.Verdict, error) {
		return moderation.Verdict{}, fmt.Errorf("%w: upstream status 500", moderation.ErrUnavailable)
	}}
	a, _ := newTestApp(t, mod, "")
	setupPolicy(t, a)
	r := intercept(t, a, bizKey, "openai", "gpt-image-1", chat("hello"))
	if !r.Terminate || r.StatusCode != 503 || errCode(t, r) != engine.CodeUnavailable {
		t.Fatalf("T07: %+v", r)
	}
	if strings.Contains(string(r.ResponseBody), "500") {
		t.Fatal("refusal must not leak provider details")
	}
	mod.fn = func([]moderation.Item) (moderation.Verdict, error) { return moderation.Verdict{}, moderation.ErrBusy }
	if r := intercept(t, a, bizKey, "openai", "gpt-image-1", chat("hello")); r.StatusCode != 429 || r.ResponseHeaders.Get("Retry-After") == "" {
		t.Fatalf("busy: %+v", r)
	}
}

func TestPanicInsideInterceptionIsRefusedNotCrashed(t *testing.T) {
	mod := &fakeModerator{fn: func([]moderation.Item) (moderation.Verdict, error) { panic("boom") }}
	a, _ := newTestApp(t, mod, "")
	setupPolicy(t, a)
	r := intercept(t, a, bizKey, "openai", "gpt-image-1", chat("hello"))
	if !r.Terminate || r.StatusCode != 503 {
		t.Fatalf("panic must become a 503 refusal: %+v", r)
	}
	// The plugin keeps working afterwards.
	mod.fn = flagOn("FLAGME", "x")
	if r := intercept(t, a, bizKey, "openai", "gpt-image-1", chat("hello")); r.Terminate {
		t.Fatalf("plugin must recover after a panic: %+v", r)
	}
}

func TestUnparseableInterceptRequestIsRefused(t *testing.T) {
	a, _ := newTestApp(t, &fakeModerator{fn: flagOn("x", "y")}, "")
	var env Envelope
	_ = json.Unmarshal(a.HandleMethod(MethodRequestInterceptBefore, []byte("garbage")), &env)
	var r InterceptResponse
	_ = json.Unmarshal(env.Result, &r)
	if !env.OK || !r.Terminate || r.StatusCode != 503 {
		t.Fatalf("got %+v %+v", env, r)
	}
}

func TestBrokenConfigFailsClosedButStaysRegistered(t *testing.T) {
	a := NewApp()
	a.logger = nil
	t.Cleanup(a.Shutdown)
	env := call(t, a, MethodPluginRegister, LifecycleRequest{ConfigYAML: []byte("enabled: true\nopenai:\n  timeout_ms: -5\n")})
	if !env.OK {
		t.Fatal("registration must succeed so the plugin keeps intercepting")
	}
	r := intercept(t, a, otherKey, "openai", "anything", chat("hi"))
	if !r.Terminate || r.StatusCode != 503 {
		t.Fatalf("broken config must refuse: %+v", r)
	}
	code, out := mgmt(t, a, http.MethodGet, "/status", nil)
	if code != 200 || out["healthy"] != false || out["error"] == "" {
		t.Fatalf("status must expose the error: %v", out)
	}
}

func TestCorruptStateFileFailsClosed(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	_ = os.WriteFile(statePath, []byte(`{"rules":[{"id":"x","models":[]}]}`), 0o600)
	a := NewApp()
	a.logger = nil
	t.Cleanup(a.Shutdown)
	call(t, a, MethodPluginRegister, LifecycleRequest{ConfigYAML: []byte(fmt.Sprintf("state_file: %q\naudit_file: \"\"\n", filepath.ToSlash(statePath)))})
	if r := intercept(t, a, bizKey, "openai", "gpt-image-1", chat("hi")); r.StatusCode != 503 {
		t.Fatalf("corrupt state must fail closed: %+v", r)
	}
}

func TestDisabledPassesThrough(t *testing.T) {
	mod := &fakeModerator{fn: flagOn("FLAGME", "x")}
	a, _ := newTestApp(t, mod, "")
	setupPolicy(t, a)
	cfg := a.rt.Load().cfg
	call(t, a, MethodPluginReconfigure, LifecycleRequest{ConfigYAML: []byte(fmt.Sprintf("enabled: false\nstate_file: %q\naudit_file: \"\"\n", filepath.ToSlash(cfg.StateFile)))})
	if r := intercept(t, a, bizKey, "openai", "gpt-image-1", chat("FLAGME")); r.Terminate {
		t.Fatal("enabled=false disables moderation (documented)")
	}
}

func TestStateConflictAndValidation(t *testing.T) {
	a, _ := newTestApp(t, &fakeModerator{fn: flagOn("x", "y")}, "")
	setupPolicy(t, a)
	if code, _ := mgmt(t, a, http.MethodPut, "/state", policy.State{Revision: 0}); code != http.StatusConflict {
		t.Fatalf("stale revision must conflict, got %d", code)
	}
	_, st := mgmt(t, a, http.MethodGet, "/state", nil)
	rev := int64(st["revision"].(float64))
	bad := policy.State{Revision: rev, Rules: []policy.Rule{{ID: "r", Enabled: true, CheckText: true}}}
	if code, _ := mgmt(t, a, http.MethodPut, "/state", bad); code != http.StatusBadRequest {
		t.Fatalf("invalid state must be rejected, got %d", code)
	}
	// Previous policy still enforced.
	if r := intercept(t, a, bizKey, "openai", "gpt-image-1", chat("SYNTHETICBANNED")); r.StatusCode != 403 {
		t.Fatalf("old policy must remain active: %+v", r)
	}
	if code, _ := mgmt(t, a, http.MethodPut, "/state", map[string]any{"revision": rev, "bogus": 1}); code != http.StatusBadRequest {
		t.Fatal("unknown fields must be rejected")
	}
}

func TestKeySyncStoresNoRawKeys(t *testing.T) {
	a, dir := newTestApp(t, &fakeModerator{fn: flagOn("x", "y")}, "")
	setupPolicy(t, a)
	raw, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if strings.Contains(string(raw), bizKey) || strings.Contains(string(raw), otherKey) {
		t.Fatal("state file must not contain raw keys")
	}
	// Removing a key keeps its bindings and marks it missing.
	_, out := mgmt(t, a, http.MethodPost, "/keys/sync", map[string]any{"keys": []string{otherKey}})
	if out["missing"].(float64) != 1 {
		t.Fatalf("sync: %v", out)
	}
	if r := intercept(t, a, bizKey, "openai", "gpt-image-1", chat("SYNTHETICBANNED")); r.StatusCode != 403 {
		t.Fatal("bindings of a missing key must stay enforced")
	}
}

func TestSimulateDoesNotCallProviderByDefault(t *testing.T) {
	mod := &fakeModerator{fn: flagOn("FLAGME", "x")}
	a, _ := newTestApp(t, mod, "")
	setupPolicy(t, a)
	code, out := mgmt(t, a, http.MethodPost, "/simulate", map[string]any{
		"key": bizKey, "model": "gpt-image-1", "format": "openai", "body": json.RawMessage(chat("FLAGME"))})
	if code != 200 || out["outcome"] != "allow" || out["forwarded"] != false || mod.calls.Load() != 0 {
		t.Fatalf("dry run: %v calls=%d", out, mod.calls.Load())
	}
	_, out = mgmt(t, a, http.MethodPost, "/simulate", map[string]any{
		"key": bizKey, "model": "gpt-image-1", "format": "openai", "body": json.RawMessage(chat("FLAGME")), "call_provider": true})
	if out["outcome"] != "block" {
		t.Fatalf("provider run: %v", out)
	}
	_, out = mgmt(t, a, http.MethodPost, "/simulate", map[string]any{
		"key": otherKey, "model": "gpt-image-1", "format": "openai", "body": json.RawMessage(chat("FLAGME"))})
	if out["outcome"] != "skip" {
		t.Fatalf("unbound: %v", out)
	}
}

func TestLogOnlyCategoryAndOnErrorAllow(t *testing.T) {
	mod := &fakeModerator{fn: flagOn("FLAGME", "violence")}
	a, _ := newTestApp(t, mod, "")
	setupPolicy(t, a)
	_, st := mgmt(t, a, http.MethodGet, "/state", nil)
	var state policy.State
	raw, _ := json.Marshal(st)
	_ = json.Unmarshal(raw, &state)
	state.Rules[0].CategoryActions = map[string]string{"violence": "log"}
	state.Rules[0].OnError = "allow"
	if code, out := mgmt(t, a, http.MethodPut, "/state", state); code != 200 {
		t.Fatalf("%v", out)
	}
	if r := intercept(t, a, bizKey, "openai", "gpt-image-1", chat("FLAGME")); r.Terminate {
		t.Fatal("log-only category must not block")
	}
	mod.fn = func([]moderation.Item) (moderation.Verdict, error) { return moderation.Verdict{}, errors.New("down") }
	if r := intercept(t, a, bizKey, "openai", "gpt-image-1", chat("x")); r.Terminate {
		t.Fatal("on_error=allow must pass")
	}
	evs := a.events.snapshot(1)
	if len(evs) != 1 || evs[0].Reason != "provider_error_allowed" {
		t.Fatalf("event: %+v", evs)
	}
}

func TestUnknownMethodAndManagementRoutes(t *testing.T) {
	a, _ := newTestApp(t, &fakeModerator{fn: flagOn("x", "y")}, "")
	if env := call(t, a, "nope", nil); env.OK {
		t.Fatal("unknown method must error")
	}
	if code, _ := mgmt(t, a, http.MethodGet, "/../../etc", nil); code != 404 {
		t.Fatal("unknown route must 404")
	}
	var reg ManagementRegistration
	_ = json.Unmarshal(call(t, a, MethodManagementRegister, nil).Result, &reg)
	for _, r := range reg.Routes {
		if !strings.HasPrefix(r.Path, "/v0/management/plugins/"+PluginID+"/") {
			t.Fatalf("route outside the management namespace: %s", r.Path)
		}
	}
}

func TestUIResourceRoute(t *testing.T) {
	a, _ := newTestApp(t, &fakeModerator{fn: flagOn("x", "y")}, "")
	var reg ManagementRegistration
	_ = json.Unmarshal(call(t, a, MethodManagementRegister, nil).Result, &reg)
	if len(reg.Resources) != 1 || reg.Resources[0].Path != resourceUIPath || reg.Resources[0].Menu == "" {
		t.Fatalf("resources: %+v", reg.Resources)
	}
	env := call(t, a, MethodManagementHandle, ManagementRequest{Method: http.MethodGet, Path: resourceUIPath})
	var resp ManagementResponse
	_ = json.Unmarshal(env.Result, &resp)
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Headers.Get("Content-Type"), "text/html") {
		t.Fatalf("ui: %d %v", resp.StatusCode, resp.Headers)
	}
	csp := resp.Headers.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "connect-src 'self'") {
		t.Fatalf("csp: %q", csp)
	}
	body := string(resp.Body)
	if !strings.Contains(body, "/v0/management/plugins/cpa-moderation") || strings.Contains(body, "innerHTML") {
		t.Fatal("UI must call the plugin API and must not use innerHTML")
	}
	env = call(t, a, MethodManagementHandle, ManagementRequest{Method: http.MethodPost, Path: resourceUIPath})
	_ = json.Unmarshal(env.Result, &resp)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST to UI must be rejected, got %d", resp.StatusCode)
	}
}

func TestModelsEndpoint(t *testing.T) {
	a, _ := newTestApp(t, &fakeModerator{fn: flagOn("x", "y")}, "")
	if code, _ := mgmt(t, a, http.MethodGet, "/models", nil); code != http.StatusServiceUnavailable {
		t.Fatalf("without host caller: %d", code)
	}
	a.SetHostCaller(func(method string, _ []byte) ([]byte, error) {
		if method != "host.auth.models" {
			return nil, fmt.Errorf("unexpected %s", method)
		}
		return []byte(`{"ok":true,"result":{"credentials":[
			{"id":"a","provider":"openai-compatibility","models":["gpt-6-mini","friendly-alias"]},
			{"id":"b","provider":"claude","models":["claude-mock","gpt-6-mini"]}]}}`), nil
	})
	code, out := mgmt(t, a, http.MethodGet, "/models", nil)
	models, _ := out["models"].([]any)
	if code != 200 || len(models) != 3 {
		t.Fatalf("models: %d %v", code, out)
	}
	first := models[1].(map[string]any) // sorted: claude-mock, friendly-alias, gpt-6-mini
	if first["id"] != "friendly-alias" {
		t.Fatalf("not sorted: %v", models)
	}
	last := models[2].(map[string]any)
	if len(last["providers"].([]any)) != 2 {
		t.Fatalf("providers not merged: %v", last)
	}
	a.SetHostCaller(func(string, []byte) ([]byte, error) {
		return []byte(`{"ok":false,"error":{"code":"x","message":"boom"}}`), nil
	})
	if code, out := mgmt(t, a, http.MethodGet, "/models", nil); code != http.StatusBadGateway || !strings.Contains(fmt.Sprint(out), "boom") {
		t.Fatalf("host error must surface, got %d %v", code, out)
	}
}

func TestUnknownConfigFieldWarnsButKeepsWorking(t *testing.T) {
	mod := &fakeModerator{fn: flagOn("FLAGME", "x")}
	a, _ := newTestApp(t, mod, "some_future_field: 1\nopenai:\n  legacy_option: true\n")
	setupPolicy(t, a)
	if r := intercept(t, a, bizKey, "openai", "gpt-image-1", chat("FLAGME")); r.StatusCode != 403 {
		t.Fatalf("plugin must keep moderating with unknown fields: %+v", r)
	}
	_, out := mgmt(t, a, http.MethodGet, "/status", nil)
	ws, _ := out["warnings"].([]any)
	if out["healthy"] != true || len(ws) != 2 {
		t.Fatalf("unknown fields must be reported as warnings: %v", out)
	}
	_, st := mgmt(t, a, http.MethodGet, "/state", nil)
	raw, _ := json.Marshal(st)
	var state policy.State
	_ = json.Unmarshal(raw, &state)
	if code, _ := mgmt(t, a, http.MethodPut, "/state", state); code != 200 {
		t.Fatal("state update failed")
	}
	_, out = mgmt(t, a, http.MethodGet, "/status", nil)
	if ws, _ := out["warnings"].([]any); len(ws) != 2 {
		t.Fatalf("warnings lost after state update: %v", out)
	}
}

func TestShutdownMethodAndLogsViaHost(t *testing.T) {
	a, _ := newTestApp(t, &fakeModerator{fn: flagOn("x", "y")}, "")
	var logged []string
	a.SetHostCaller(func(method string, payload []byte) ([]byte, error) {
		if method == "host.log" {
			logged = append(logged, string(payload))
		}
		return []byte(`{"ok":true,"result":{}}`), nil
	})
	setupPolicy(t, a) // a state update writes a log line
	if len(logged) == 0 || !strings.Contains(logged[len(logged)-1], "[cpa-moderation]") {
		t.Fatalf("logs must go through host.log: %v", logged)
	}
	if env := call(t, a, MethodPluginShutdown, struct{}{}); !env.OK {
		t.Fatalf("plugin.shutdown must succeed: %+v", env.Error)
	}
}

func TestRegistrationDeclaresKnownFieldTypes(t *testing.T) {
	a, _ := newTestApp(t, &fakeModerator{fn: flagOn("x", "y")}, "")
	var reg Registration
	_ = json.Unmarshal(call(t, a, MethodPluginRegister, LifecycleRequest{}).Result, &reg)
	for _, f := range reg.Metadata.ConfigFields {
		if f.Name == "remote_images" && (f.Type != "enum" || len(f.EnumValues) != 2) {
			t.Fatalf("remote_images must be an enum: %+v", f)
		}
		switch f.Type {
		case "string", "number", "integer", "boolean", "enum", "array", "object":
		default:
			t.Fatalf("field %s has a type the host does not know: %s", f.Name, f.Type)
		}
	}
}

func TestConfigFieldDefaultsUseYAMLKeys(t *testing.T) {
	a, _ := newTestApp(t, &fakeModerator{fn: flagOn("x", "y")}, "")
	raw := call(t, a, MethodPluginRegister, LifecycleRequest{}).Result
	if strings.Contains(string(raw), "APIKeyEnv") || !strings.Contains(string(raw), `"api_key_env"`) {
		t.Fatalf("defaults must be rendered with YAML keys so the host UI can write them back: %s", raw)
	}
	// Round trip: the host may write the advertised defaults back as config.
	var reg struct {
		Metadata struct {
			ConfigFields []struct {
				Name    string `json:"Name"`
				Default any    `json:"Default"`
			} `json:"ConfigFields"`
		} `json:"metadata"`
	}
	_ = json.Unmarshal(raw, &reg)
	cfg := map[string]any{}
	for _, f := range reg.Metadata.ConfigFields {
		cfg[f.Name] = f.Default
	}
	cfg["state_file"] = a.rt.Load().cfg.StateFile
	yml, _ := json.Marshal(cfg) // JSON is valid YAML
	b := NewApp()
	b.logger = nil
	t.Cleanup(b.Shutdown)
	call(t, b, MethodPluginRegister, LifecycleRequest{ConfigYAML: yml})
	if rt := b.rt.Load(); rt.broken != nil || len(rt.warnings) != 0 {
		t.Fatalf("advertised defaults must load cleanly: broken=%v warnings=%v", rt.broken, rt.warnings)
	}
}
