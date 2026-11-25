package plugin

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"cpa-moderation/internal/engine"
)

const sourcePluginCallback = "plugin_host_model_callback"

func (a *App) interceptBefore(raw []byte) InterceptResponse {
	var req InterceptRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		// Without a parsed request we cannot tell whether a rule applies: refuse.
		a.counters.inc(engine.OutcomeError)
		a.logf("cannot parse intercept request: %v", err)
		return refusal("", "", http.StatusServiceUnavailable, engine.CodeUnavailable)
	}
	rt := a.rt.Load()
	if rt.broken != nil {
		a.counters.inc(engine.OutcomeError)
		a.recordEvent(req, engine.Decision{Outcome: engine.OutcomeError, Status: http.StatusServiceUnavailable,
			Code: engine.CodeUnavailable, Reason: "plugin_misconfigured", Detail: rt.broken.Error()})
		return refusal(req.SourceFormat, req.RequestID, http.StatusServiceUnavailable, engine.CodeUnavailable)
	}
	if !rt.cfg.Enabled {
		return InterceptResponse{}
	}
	scope := strings.TrimSpace(req.CallerScope)
	if scope == "" {
		scope = metaString(req.Metadata, "caller_scope")
	}
	timeout := time.Duration(rt.cfg.OpenAI.TimeoutMS)*time.Millisecond*3 + time.Duration(rt.cfg.OpenAI.QueueTimeoutMS)*time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	d := rt.engine.Evaluate(ctx, engine.Request{
		Scope:          scope,
		Model:          req.Model,
		RequestedModel: req.RequestedModel,
		Format:         req.SourceFormat,
		ContentType:    req.Headers.Get("Content-Type"),
		Body:           req.Body,
	})
	a.counters.inc(d.Outcome)
	if d.Outcome == engine.OutcomeSkip {
		return InterceptResponse{}
	}
	a.recordEvent(req, d)
	if d.Outcome == engine.OutcomeAllow {
		return InterceptResponse{}
	}
	return refusal(req.SourceFormat, req.RequestID, d.Status, d.Code)
}

// internalRefusal is used when interception panicked.
func internalRefusal(raw []byte) InterceptResponse {
	var req struct {
		RequestID    string `json:"RequestID"`
		SourceFormat string `json:"SourceFormat"`
	}
	_ = json.Unmarshal(raw, &req)
	return refusal(req.SourceFormat, req.RequestID, http.StatusServiceUnavailable, engine.CodeUnavailable)
}

var messages = map[string]string{
	engine.CodeViolation:   "Request rejected by content policy.",
	engine.CodeInvalid:     "Request content could not be moderated.",
	engine.CodeTooLarge:    "Request content is too large to moderate.",
	engine.CodeUnavailable: "Content moderation is temporarily unavailable. Please try again later.",
	engine.CodeRateLimited: "Content moderation is busy. Please retry shortly.",
}

// refusal renders an error in the client's API format. It never includes
// request content, matched words, scores or keys.
func refusal(sourceFormat, requestID string, status int, code string) InterceptResponse {
	msg := messages[code]
	if msg == "" {
		msg = messages[engine.CodeUnavailable]
	}
	if requestID != "" {
		msg += " (request_id: " + requestID + ")"
	}
	var payload any
	switch f := strings.ToLower(sourceFormat); {
	case strings.Contains(f, "claude") || strings.Contains(f, "anthropic"):
		payload = map[string]any{"type": "error", "error": map[string]any{"type": anthropicType(status), "message": msg}}
	case strings.HasPrefix(f, "gemini") || f == "aistudio":
		payload = map[string]any{"error": map[string]any{"code": status, "message": msg, "status": googleStatus(status)}}
	default:
		payload = map[string]any{"error": map[string]any{"message": msg, "type": openAIType(status), "code": code, "param": nil}}
	}
	body, _ := json.Marshal(payload)
	headers := http.Header{"Content-Type": {"application/json; charset=utf-8"}}
	if status == http.StatusTooManyRequests {
		headers.Set("Retry-After", strconv.Itoa(1))
	}
	return InterceptResponse{Terminate: true, StatusCode: status, ResponseHeaders: headers, ResponseBody: body}
}

func openAIType(status int) string {
	switch status {
	case http.StatusTooManyRequests:
		return "rate_limit_error"
	case http.StatusServiceUnavailable:
		return "server_error"
	default:
		return "invalid_request_error"
	}
}

func anthropicType(status int) string {
	switch status {
	case http.StatusForbidden:
		return "permission_error"
	case http.StatusRequestEntityTooLarge:
		return "request_too_large"
	case http.StatusTooManyRequests:
		return "rate_limit_error"
	case http.StatusServiceUnavailable:
		return "api_error"
	default:
		return "invalid_request_error"
	}
}

func googleStatus(status int) string {
	switch status {
	case http.StatusForbidden:
		return "PERMISSION_DENIED"
	case http.StatusTooManyRequests:
		return "RESOURCE_EXHAUSTED"
	case http.StatusServiceUnavailable:
		return "UNAVAILABLE"
	default:
		return "INVALID_ARGUMENT"
	}
}

func metaString(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return strings.TrimSpace(s)
}
