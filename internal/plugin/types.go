package plugin

import (
	"encoding/json"
	"net/http"
	"net/url"
)

const (
	ABIVersion    uint32 = 1
	SchemaVersion uint32 = 10

	// PluginID is the library file name, the plugins.configs key and the route segment.
	PluginID         = "cpa-moderation"
	Version          = "0.1.2"
	GitHubRepository = "https://github.com/caiyaonan/cpa-plugin-moderration"
	MenuLabel        = "CPA Moderation"
)

const (
	MethodPluginRegister         = "plugin.register"
	MethodPluginReconfigure      = "plugin.reconfigure"
	MethodPluginShutdown         = "plugin.shutdown"
	MethodRequestInterceptBefore = "request.intercept_before"
	MethodRequestInterceptAfter  = "request.intercept_after"
	MethodRequestComplete        = "request.complete"
	MethodManagementRegister     = "management.register"
	MethodManagementHandle       = "management.handle"
)

type Envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *EnvelopeError  `json:"error,omitempty"`
}

type EnvelopeError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

type LifecycleRequest struct {
	ConfigYAML    []byte `json:"config_yaml"`
	SchemaVersion uint32 `json:"schema_version"`
}

type Registration struct {
	SchemaVersion uint32       `json:"schema_version"`
	Metadata      Metadata     `json:"metadata"`
	Capabilities  Capabilities `json:"capabilities"`
}

type Metadata struct {
	Name             string        `json:"Name"`
	Version          string        `json:"Version"`
	Author           string        `json:"Author"`
	GitHubRepository string        `json:"GitHubRepository"`
	Logo             string        `json:"Logo"`
	ConfigFields     []ConfigField `json:"ConfigFields"`
}

type ConfigField struct {
	Name        string   `json:"Name"`
	Type        string   `json:"Type"`
	Default     any      `json:"Default"`
	EnumValues  []string `json:"EnumValues,omitempty"`
	Description string   `json:"Description"`
}

type Capabilities struct {
	RequestInterceptor bool `json:"request_interceptor"`
	// After-auth calls repeat on every retry and are not used; skip their body copy.
	RequestInterceptorOmitBodyAfter bool `json:"request_interceptor_omit_body_after,omitempty"`
	ManagementAPI                   bool `json:"management_api"`
}

type InterceptRequest struct {
	RequestID      string         `json:"RequestID"`
	TraceID        string         `json:"TraceID"`
	SourceFormat   string         `json:"SourceFormat"`
	ToFormat       string         `json:"ToFormat"`
	Model          string         `json:"Model"`
	RequestedModel string         `json:"RequestedModel"`
	Stream         bool           `json:"Stream"`
	Headers        http.Header    `json:"Headers"`
	Body           []byte         `json:"Body"`
	CallerScope    string         `json:"CallerScope"`
	Metadata       map[string]any `json:"Metadata"`
}

// InterceptResponse is empty to leave the request untouched. The plugin never
// returns Body/BodyEdits/Headers: moderation must not modify requests.
type InterceptResponse struct {
	Terminate       bool        `json:"Terminate,omitempty"`
	StatusCode      int         `json:"StatusCode,omitempty"`
	ResponseHeaders http.Header `json:"ResponseHeaders,omitempty"`
	ResponseBody    []byte      `json:"ResponseBody,omitempty"`
}

type ManagementRegistration struct {
	Routes    []ManagementRoute `json:"routes,omitempty"`
	Resources []ResourceRoute   `json:"resources,omitempty"`
}

type ManagementRoute struct {
	Method      string `json:"Method"`
	Path        string `json:"Path"`
	Description string `json:"Description,omitempty"`
}

type ResourceRoute struct {
	Path        string `json:"Path"`
	Menu        string `json:"Menu,omitempty"`
	Description string `json:"Description,omitempty"`
}

type ManagementRequest struct {
	Method  string      `json:"Method"`
	Path    string      `json:"Path"`
	Headers http.Header `json:"Headers"`
	Query   url.Values  `json:"Query"`
	Body    []byte      `json:"Body"`
}

type ManagementResponse struct {
	StatusCode int         `json:"StatusCode,omitempty"`
	Headers    http.Header `json:"Headers,omitempty"`
	Body       []byte      `json:"Body,omitempty"`
}

func okEnvelope(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		return errorEnvelope("encode_error", err.Error(), http.StatusInternalServerError)
	}
	out, _ := json.Marshal(Envelope{OK: true, Result: raw})
	return out
}

func errorEnvelope(code, message string, status int) []byte {
	out, _ := json.Marshal(Envelope{OK: false, Error: &EnvelopeError{Code: code, Message: message, HTTPStatus: status}})
	return out
}
