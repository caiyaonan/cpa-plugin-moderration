package plugin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"cpa-moderation/internal/engine"
	"cpa-moderation/internal/moderation"
	"cpa-moderation/internal/policy"
)

const (
	managementBase = "/v0/management/plugins/" + PluginID
	resourceBase   = "/v0/resource/plugins/" + PluginID
	resourceUIPath = resourceBase + "/ui"
)

type endpoint struct {
	method, path, description string
	handle                    func(*App, ManagementRequest) ManagementResponse
}

var endpoints = []endpoint{
	{http.MethodGet, "/status", "View moderation plugin status", (*App).status},
	{http.MethodGet, "/state", "View moderation rules, wordlists and key bindings", (*App).getState},
	{http.MethodPut, "/state", "Replace moderation rules, wordlists and key bindings", (*App).putState},
	{http.MethodPost, "/keys/sync", "Sync API keys from CLIProxyAPI (stores hashes only)", (*App).syncKeys},
	{http.MethodPost, "/simulate", "Evaluate a request against the policy without forwarding it", (*App).simulate},
	{http.MethodPost, "/provider/test", "Send a fixed harmless text to the moderation API", (*App).testProvider},
	{http.MethodGet, "/events", "List recent moderation events", (*App).listEvents},
	{http.MethodGet, "/models", "List model names served by CLIProxyAPI credentials", (*App).listModels},
}

func managementRegistration() ManagementRegistration {
	reg := ManagementRegistration{
		Resources: []ResourceRoute{{Path: resourceUIPath, Menu: MenuLabel, Description: "Moderation rules, key bindings, wordlists and audit events"}},
	}
	for _, e := range endpoints {
		reg.Routes = append(reg.Routes, ManagementRoute{Method: e.method, Path: managementBase + e.path, Description: e.description})
	}
	return reg
}

func (a *App) handleManagement(raw []byte) ManagementResponse {
	var req ManagementRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return jsonError(http.StatusBadRequest, "invalid_request", "cannot parse management request")
	}
	path := strings.TrimRight(req.Path, "/")
	if path == resourceUIPath {
		if req.Method != http.MethodGet {
			return jsonError(http.StatusMethodNotAllowed, "method_not_allowed", "only GET is allowed")
		}
		return uiResponse()
	}
	suffix := strings.TrimPrefix(path, managementBase)
	if suffix == path {
		return jsonError(http.StatusNotFound, "not_found", "route not found")
	}
	for _, e := range endpoints {
		if e.method == req.Method && e.path == suffix {
			return e.handle(a, req)
		}
	}
	return jsonError(http.StatusNotFound, "not_found", "route not found")
}

func (a *App) status(ManagementRequest) ManagementResponse {
	rt := a.rt.Load()
	out := map[string]any{
		"plugin":  PluginID,
		"version": Version,
		"enabled": rt.cfg.Enabled,
		"model":   rt.cfg.OpenAI.Model,
		"counters": map[string]int64{
			"skipped": a.counters.skip.Load(),
			"allowed": a.counters.allow.Load(),
			"blocked": a.counters.block.Load(),
			"errors":  a.counters.errors.Load(),
		},
	}
	if rt.broken != nil {
		out["healthy"] = false
		out["error"] = rt.broken.Error()
	} else {
		out["healthy"] = true
	}
	if len(rt.warnings) > 0 {
		out["warnings"] = rt.warnings
	}
	a.mu.Lock()
	client, store := a.client, a.store
	a.mu.Unlock()
	if client != nil {
		out["api_key_configured"] = client.KeyConfigured()
		out["api_key_env"] = rt.cfg.OpenAI.APIKeyEnv
	}
	if store != nil {
		st := store.Current()
		bound := 0
		for _, k := range st.Keys {
			if len(k.RuleIDs) > 0 {
				bound++
			}
		}
		out["revision"] = st.Revision
		out["rules"] = len(st.Rules)
		out["keys"] = len(st.Keys)
		out["bound_keys"] = bound
	}
	return jsonOK(out)
}

func (a *App) getState(ManagementRequest) ManagementResponse {
	store := a.currentStore()
	if store == nil {
		return jsonError(http.StatusServiceUnavailable, "not_ready", "state is unavailable: "+a.brokenText())
	}
	return jsonOK(store.Current())
}

func (a *App) putState(req ManagementRequest) ManagementResponse {
	var in policy.State
	if err := decodeStrict(req.Body, &in); err != nil {
		return jsonError(http.StatusBadRequest, "invalid", err.Error())
	}
	return a.updateState(in.Revision, func(s *policy.State) error {
		s.Rules, s.Wordlists, s.Keys = in.Rules, in.Wordlists, in.Keys
		return nil
	})
}

func (a *App) syncKeys(req ManagementRequest) ManagementResponse {
	var in struct {
		Keys     []string `json:"keys"`
		Revision *int64   `json:"revision"`
	}
	if err := decodeStrict(req.Body, &in); err != nil {
		return jsonError(http.StatusBadRequest, "invalid", err.Error())
	}
	rev := int64(-1)
	if in.Revision != nil {
		rev = *in.Revision
	}
	added, missing := 0, 0
	resp := a.updateState(rev, func(s *policy.State) error {
		live := map[string]string{}
		for _, k := range in.Keys {
			if scope := policy.CallerScope(k); scope != "" {
				live[scope] = policy.PreviewKey(k)
			}
		}
		seen := map[string]bool{}
		for i := range s.Keys {
			k := &s.Keys[i]
			seen[k.Scope] = true
			if preview, ok := live[k.Scope]; ok {
				k.Preview, k.Missing = preview, false
			} else {
				// Keep bindings of keys that disappeared so re-adding a key restores its policy.
				k.Missing = true
				missing++
			}
		}
		for scope, preview := range live {
			if !seen[scope] {
				s.Keys = append(s.Keys, policy.Key{Scope: scope, Preview: preview, RuleIDs: []string{}})
				added++
			}
		}
		return nil
	})
	if resp.StatusCode != http.StatusOK {
		return resp
	}
	var st policy.State
	_ = json.Unmarshal(resp.Body, &st)
	return jsonOK(map[string]any{"added": added, "missing": missing, "revision": st.Revision, "keys": st.Keys})
}

func (a *App) updateState(revision int64, fn func(*policy.State) error) ManagementResponse {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.store == nil {
		return jsonError(http.StatusServiceUnavailable, "not_ready", "state is unavailable: "+a.brokenText())
	}
	next, err := a.store.Update(revision, fn)
	if err != nil {
		if errors.Is(err, policy.ErrConflict) {
			return jsonError(http.StatusConflict, "conflict", err.Error())
		}
		return jsonError(http.StatusBadRequest, "invalid", err.Error())
	}
	rt := a.rt.Load()
	if rt.broken == nil && rt.engine != nil {
		if err := a.install(rt.cfg, next, rt.engine.Moderator); err != nil {
			// Saved but not loadable should be impossible after Validate; fail closed.
			a.setBroken(rt.cfg, err)
			return jsonError(http.StatusInternalServerError, "install_failed", err.Error())
		}
	}
	a.logf("state updated to revision %d", next.Revision)
	return jsonOK(next)
}

func (a *App) simulate(req ManagementRequest) ManagementResponse {
	var in struct {
		Key          string          `json:"key"`
		Scope        string          `json:"scope"`
		Model        string          `json:"model"`
		Format       string          `json:"format"`
		ContentType  string          `json:"content_type"`
		Body         json.RawMessage `json:"body"`
		BodyBase64   string          `json:"body_base64"`
		CallProvider bool            `json:"call_provider"`
	}
	if err := decodeStrict(req.Body, &in); err != nil {
		return jsonError(http.StatusBadRequest, "invalid", err.Error())
	}
	rt := a.rt.Load()
	if rt.broken != nil {
		return jsonError(http.StatusServiceUnavailable, "not_ready", rt.broken.Error())
	}
	scope := strings.ToLower(strings.TrimSpace(in.Scope))
	if in.Key != "" {
		scope = policy.CallerScope(in.Key)
	}
	body := []byte(in.Body)
	if in.BodyBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(in.BodyBase64)
		if err != nil {
			return jsonError(http.StatusBadRequest, "invalid", "body_base64 is not valid base64")
		}
		body = decoded
	}
	if in.ContentType == "" {
		in.ContentType = "application/json"
	}
	eng := *rt.engine
	if !in.CallProvider {
		eng.Moderator = dryRunModerator{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(rt.cfg.OpenAI.TimeoutMS)*3*time.Millisecond)
	defer cancel()
	d := eng.Evaluate(ctx, engine.Request{Scope: scope, Model: in.Model, RequestedModel: in.Model,
		Format: in.Format, ContentType: in.ContentType, Body: body})
	return jsonOK(map[string]any{
		"forwarded":         false,
		"provider_called":   in.CallProvider,
		"outcome":           d.Outcome,
		"status":            d.Status,
		"code":              d.Code,
		"rules":             d.Rules,
		"reason":            d.Reason,
		"categories":        d.Categories,
		"logged_categories": d.LoggedCategories,
		"texts":             d.Texts,
		"images":            d.Images,
		"notes":             d.Notes,
		"detail":            d.Detail,
		"duration_ms":       float64(d.Duration.Microseconds()) / 1000,
	})
}

// dryRunModerator lets simulations exercise matching, extraction and wordlists
// without sending content to the moderation API.
type dryRunModerator struct{}

func (dryRunModerator) Moderate(context.Context, []moderation.Item) (moderation.Verdict, error) {
	return moderation.Verdict{}, nil
}

func (a *App) testProvider(ManagementRequest) ManagementResponse {
	rt := a.rt.Load()
	if rt.broken != nil || rt.engine == nil {
		return jsonError(http.StatusServiceUnavailable, "not_ready", a.brokenText())
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(rt.cfg.OpenAI.TimeoutMS)*time.Millisecond)
	defer cancel()
	// A unique suffix avoids answering from the pass cache.
	text := "A landscape with mountains and a lake. " + strconv.FormatInt(start.UnixNano(), 10)
	v, err := rt.engine.Moderator.Moderate(ctx, []moderation.Item{{Text: text}})
	out := map[string]any{"latency_ms": time.Since(start).Milliseconds(), "model": rt.cfg.OpenAI.Model}
	if err != nil {
		out["ok"] = false
		out["error"] = err.Error()
		return jsonResponse(http.StatusBadGateway, out)
	}
	out["ok"] = !v.Flagged
	out["flagged"] = v.Flagged
	return jsonOK(out)
}

func (a *App) listEvents(req ManagementRequest) ManagementResponse {
	limit, _ := strconv.Atoi(req.Query.Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	outcome := req.Query.Get("outcome")
	all := a.events.snapshot(0)
	out := make([]Event, 0, limit)
	for _, e := range all {
		if outcome != "" && e.Outcome != outcome {
			continue
		}
		out = append(out, e)
		if len(out) >= limit {
			break
		}
	}
	return jsonOK(map[string]any{"events": out})
}

type modelEntry struct {
	ID        string   `json:"id"`
	Providers []string `json:"providers"`
}

func (a *App) listModels(ManagementRequest) ManagementResponse {
	hc := a.host()
	if hc == nil {
		return jsonError(http.StatusServiceUnavailable, "host_unavailable", "host callbacks are not available")
	}
	raw, err := hc("host.auth.models", []byte("{}"))
	if err != nil {
		return jsonError(http.StatusBadGateway, "host_error", "read models from CLIProxyAPI: "+err.Error())
	}
	var env struct {
		OK     bool `json:"ok"`
		Result struct {
			Credentials []struct {
				Provider string   `json:"provider"`
				Models   []string `json:"models"`
			} `json:"credentials"`
		} `json:"result"`
		Error *EnvelopeError `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil || !env.OK {
		msg := "invalid host response"
		if env.Error != nil {
			msg = env.Error.Message
		}
		return jsonError(http.StatusBadGateway, "host_error", "read models from CLIProxyAPI: "+msg)
	}
	byID := map[string]map[string]bool{}
	for _, c := range env.Result.Credentials {
		for _, m := range c.Models {
			if byID[m] == nil {
				byID[m] = map[string]bool{}
			}
			if c.Provider != "" {
				byID[m][c.Provider] = true
			}
		}
	}
	out := make([]modelEntry, 0, len(byID))
	for id, providers := range byID {
		e := modelEntry{ID: id, Providers: []string{}}
		for p := range providers {
			e.Providers = append(e.Providers, p)
		}
		sort.Strings(e.Providers)
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return jsonOK(map[string]any{"models": out})
}

func (a *App) currentStore() *policy.Store {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.store
}

func (a *App) brokenText() string {
	if rt := a.rt.Load(); rt.broken != nil {
		return rt.broken.Error()
	}
	return "not configured"
}

func decodeStrict(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("invalid request body: " + err.Error())
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("request body must contain exactly one JSON value")
	}
	return nil
}

func jsonOK(v any) ManagementResponse { return jsonResponse(http.StatusOK, v) }

func jsonError(status int, code, message string) ManagementResponse {
	return jsonResponse(status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func jsonResponse(status int, v any) ManagementResponse {
	body, err := json.Marshal(v)
	if err != nil {
		status = http.StatusInternalServerError
		body = []byte(`{"error":{"code":"encode_error","message":"cannot encode response"}}`)
	}
	return ManagementResponse{
		StatusCode: status,
		Headers: http.Header{
			"Content-Type":           {"application/json; charset=utf-8"},
			"Cache-Control":          {"no-store"},
			"X-Content-Type-Options": {"nosniff"},
		},
		Body: body,
	}
}
