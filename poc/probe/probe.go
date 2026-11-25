package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	abiVersion    = 1
	schemaVersion = 10
	pluginName    = "cpa-mod-probe"
)

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

type interceptRequest struct {
	RequestID      string              `json:"RequestID"`
	TraceID        string              `json:"TraceID"`
	SourceFormat   string              `json:"SourceFormat"`
	ToFormat       string              `json:"ToFormat"`
	Model          string              `json:"Model"`
	RequestedModel string              `json:"RequestedModel"`
	Stream         bool                `json:"Stream"`
	Headers        map[string][]string `json:"Headers"`
	Body           []byte              `json:"Body"`
	CallerScope    string              `json:"CallerScope"`
	Metadata       map[string]any      `json:"Metadata"`
}

type interceptResponse struct {
	Terminate       bool                `json:"Terminate,omitempty"`
	StatusCode      int                 `json:"StatusCode,omitempty"`
	ResponseHeaders map[string][]string `json:"ResponseHeaders,omitempty"`
	ResponseBody    []byte              `json:"ResponseBody,omitempty"`
}

type probeConfig struct {
	LogFile string `yaml:"log_file"`
}

var (
	mu        sync.Mutex
	logFile   *os.File
	callCount = map[string]int{}
)

func handleMethod(method string, req []byte) ([]byte, bool) {
	switch method {
	case "plugin.register", "plugin.reconfigure":
		if err := configure(req); err != nil {
			return errorEnvelope("config_error", err.Error(), 500), true
		}
		return okEnvelope(map[string]any{
			"schema_version": schemaVersion,
			"metadata": map[string]any{
				"Name": pluginName, "Version": "0.0.1", "Author": "poc",
				"GitHubRepository": "https://example.invalid/cpa-mod-probe", "Logo": "", "ConfigFields": []any{},
			},
			"capabilities": map[string]any{
				"request_interceptor":      true,
				"request_lifecycle_plugin": true,
			},
		}), false
	case "request.intercept_before", "request.intercept_after":
		return intercept(method, req)
	case "request.complete":
		record(map[string]any{"method": method, "raw": json.RawMessage(req)})
		return okEnvelope(struct{}{}), false
	default:
		return errorEnvelope("unknown_method", "unsupported: "+method, 404), false
	}
}

func intercept(method string, raw []byte) ([]byte, bool) {
	var req interceptRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		record(map[string]any{"method": method, "decode_error": err.Error()})
		return errorEnvelope("decode", err.Error(), 400), true
	}
	mu.Lock()
	callCount[method+"|"+req.RequestID]++
	n := callCount[method+"|"+req.RequestID]
	mu.Unlock()

	headerNames := make([]string, 0, len(req.Headers))
	for k := range req.Headers {
		headerNames = append(headerNames, k)
	}
	meta := map[string]any{}
	for k, v := range req.Metadata {
		switch v.(type) {
		case string, bool, float64, nil:
			meta[k] = v
		default:
			meta[k] = fmt.Sprintf("<%T>", v)
		}
	}
	head := req.Body
	if len(head) > 600 {
		head = head[:600]
	}
	record(map[string]any{
		"method":          method,
		"call_n":          n,
		"request_id":      req.RequestID,
		"trace_id":        req.TraceID,
		"source_format":   req.SourceFormat,
		"to_format":       req.ToFormat,
		"model":           req.Model,
		"requested_model": req.RequestedModel,
		"stream":          req.Stream,
		"caller_scope":    req.CallerScope,
		"metadata":        meta,
		"header_names":    headerNames,
		"content_type":    strings.Join(req.Headers["Content-Type"], ","),
		"body_len":        len(req.Body),
		"body_is_json":    json.Valid(req.Body),
		"body_head":       string(head),
	})

	if method != "request.intercept_before" {
		return okEnvelope(interceptResponse{}), false
	}
	switch {
	case bytes.Contains(req.Body, []byte("PROBE_PANIC")):
		panic("probe panic requested")
	case bytes.Contains(req.Body, []byte("PROBE_ERROR")):
		return errorEnvelope("probe_error", "probe error requested", 500), true
	case bytes.Contains(req.Body, []byte("PROBE_BLOCK")):
		body, _ := json.Marshal(map[string]any{"error": map[string]any{
			"message": "Request rejected by content policy. request_id=" + req.RequestID,
			"type":    "invalid_request_error", "code": "content_policy_violation",
		}})
		return okEnvelope(interceptResponse{
			Terminate:       true,
			StatusCode:      http.StatusForbidden,
			ResponseHeaders: map[string][]string{"Content-Type": {"application/json; charset=utf-8"}},
			ResponseBody:    body,
		}), false
	}
	// Empty response: headers and body stay unchanged.
	return okEnvelope(interceptResponse{}), false
}

func configure(raw []byte) error {
	var lc struct {
		ConfigYAML    []byte `json:"config_yaml"`
		SchemaVersion uint32 `json:"schema_version"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &lc); err != nil {
			return err
		}
	}
	cfg := probeConfig{LogFile: "probe.jsonl"}
	if len(lc.ConfigYAML) > 0 {
		if err := yaml.Unmarshal(lc.ConfigYAML, &cfg); err != nil {
			return err
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if logFile != nil {
		logFile.Close()
	}
	f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	logFile = f
	line, _ := json.Marshal(map[string]any{"ts": time.Now().Format(time.RFC3339Nano), "method": "configure", "host_schema_version": lc.SchemaVersion, "config_yaml": string(lc.ConfigYAML)})
	logFile.Write(append(line, '\n'))
	return nil
}

func record(v map[string]any) {
	v["ts"] = time.Now().Format(time.RFC3339Nano)
	line, _ := json.Marshal(v)
	mu.Lock()
	defer mu.Unlock()
	if logFile != nil {
		logFile.Write(append(line, '\n'))
	}
}

func closeLog() {
	mu.Lock()
	defer mu.Unlock()
	if logFile != nil {
		logFile.Close()
		logFile = nil
	}
}

func okEnvelope(v any) []byte {
	raw, _ := json.Marshal(v)
	out, _ := json.Marshal(envelope{OK: true, Result: raw})
	return out
}

func errorEnvelope(code, msg string, status int) []byte {
	out, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: msg, HTTPStatus: status}})
	return out
}
