// Package plugin adapts the moderation engine to the CLIProxyAPI plugin RPC.
package plugin

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"cpa-moderation/internal/config"
	"cpa-moderation/internal/engine"
	"cpa-moderation/internal/extract"
	"cpa-moderation/internal/moderation"
	"cpa-moderation/internal/policy"
	"cpa-moderation/internal/rules"
)

// runtimeState is immutable and swapped atomically.
type runtimeState struct {
	cfg      config.Config
	warnings []string
	broken   error // non-nil: fail closed for every request
	engine   *engine.Engine
	snap     *policy.Snapshot
}

type App struct {
	rt       atomic.Pointer[runtimeState]
	mu       sync.Mutex // serializes configure and state writes
	store    *policy.Store
	client   *moderation.Client
	events   *eventLog
	counters counters
	logger   *log.Logger
	hostCall atomic.Pointer[HostCaller] // lock-free: logf runs while a.mu is held
	// newModerator is replaceable in tests.
	newModerator func(config.Config) (engine.Moderator, *moderation.Client, error)
}

func NewApp() *App {
	a := &App{
		events: newEventLog(1000, "", 0),
		logger: log.New(log.Writer(), "[cpa-moderation] ", log.LstdFlags),
	}
	a.newModerator = defaultModerator
	a.rt.Store(&runtimeState{broken: fmt.Errorf("plugin is not configured yet")})
	return a
}

// HostCaller sends a host callback and returns the raw response envelope.
type HostCaller func(method string, payload []byte) ([]byte, error)

func (a *App) SetHostCaller(c HostCaller) {
	if c == nil {
		a.hostCall.Store(nil)
		return
	}
	a.hostCall.Store(&c)
}

func (a *App) host() HostCaller {
	if p := a.hostCall.Load(); p != nil {
		return *p
	}
	return nil
}

func defaultModerator(cfg config.Config) (engine.Moderator, *moderation.Client, error) {
	c, err := moderation.New(moderation.Options{
		BaseURL:          cfg.OpenAI.BaseURL,
		APIKeyEnv:        cfg.OpenAI.APIKeyEnv,
		Model:            cfg.OpenAI.Model,
		ProxyURL:         cfg.OpenAI.ProxyURL,
		Timeout:          time.Duration(cfg.OpenAI.TimeoutMS) * time.Millisecond,
		MaxInflight:      cfg.OpenAI.MaxInflight,
		QueueTimeout:     time.Duration(cfg.OpenAI.QueueTimeoutMS) * time.Millisecond,
		TextsPerRequest:  cfg.OpenAI.TextsPerRequest,
		ImagesPerRequest: cfg.OpenAI.ImagesPerRequest,
		ChunkChars:       cfg.OpenAI.ChunkChars,
		ChunkOverlap:     cfg.OpenAI.ChunkOverlap,
		CacheTTL:         time.Duration(cfg.OpenAI.CacheTTLSeconds) * time.Second,
		CacheMaxEntries:  cfg.OpenAI.CacheMaxEntries,
	})
	return c, c, err
}

// HandleMethod is the single entry point from the C ABI. It never panics:
// a panic would crash the whole CLIProxyAPI process (see docs/compatibility.md).
// Interception failures are converted into refusals so the host cannot fail open.
func (a *App) HandleMethod(method string, req []byte) (resp []byte) {
	defer func() {
		if r := recover(); r != nil {
			a.logf("panic in %s: %v\n%s", method, r, debug.Stack())
			if method == MethodRequestInterceptBefore {
				resp = okEnvelope(internalRefusal(req))
				a.counters.inc(engine.OutcomeError)
				return
			}
			resp = errorEnvelope("plugin_panic", "internal plugin error", http.StatusInternalServerError)
		}
	}()
	switch method {
	case MethodPluginRegister, MethodPluginReconfigure:
		a.configure(req)
		return okEnvelope(a.registration())
	case MethodRequestInterceptBefore:
		return okEnvelope(a.interceptBefore(req))
	case MethodRequestInterceptAfter:
		return okEnvelope(InterceptResponse{})
	case MethodRequestComplete, MethodPluginShutdown:
		if method == MethodPluginShutdown {
			a.Shutdown()
		}
		return okEnvelope(struct{}{})
	case MethodManagementRegister:
		return okEnvelope(managementRegistration())
	case MethodManagementHandle:
		return okEnvelope(a.handleManagement(req))
	default:
		return errorEnvelope("unknown_method", "unsupported plugin method: "+method, http.StatusNotFound)
	}
}

func (a *App) Shutdown() { a.events.close() }

// configure always registers the plugin. A bad configuration puts the plugin
// into fail-closed mode instead of unregistering it (which would fail open).
func (a *App) configure(raw []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var lc LifecycleRequest
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &lc); err != nil {
			a.setBroken(config.Default(), fmt.Errorf("parse lifecycle request: %w", err))
			return
		}
	}
	cfg, warnings, err := config.Decode(lc.ConfigYAML)
	for _, w := range warnings {
		a.logf("%s", w)
	}
	if err != nil {
		a.setBroken(config.Default(), err)
		return
	}
	store, state, err := policy.Open(cfg.StateFile)
	if err != nil {
		a.setBroken(cfg, err)
		return
	}
	mod, client, err := a.newModerator(cfg)
	if err != nil {
		a.setBroken(cfg, err)
		return
	}
	a.store = store
	a.client = client
	a.events.reconfigure(cfg.EventBuffer, cfg.AuditFile, cfg.AuditMaxMB)
	if err := a.install(cfg, state, mod); err != nil {
		a.setBroken(cfg, err)
		return
	}
	if len(warnings) > 0 {
		rt := *a.rt.Load()
		rt.warnings = warnings
		a.rt.Store(&rt)
	}
	a.logf("configured: enabled=%v rules=%d keys=%d revision=%d", cfg.Enabled, len(state.Rules), len(state.Keys), state.Revision)
}

// install builds and publishes a new runtime state. Caller holds a.mu.
func (a *App) install(cfg config.Config, state policy.State, mod engine.Moderator) error {
	lists := make([]rules.List, 0, len(state.Wordlists))
	for _, w := range state.Wordlists {
		lists = append(lists, rules.List{ID: w.ID, Keywords: w.Keywords, Regex: w.Regex})
	}
	matcher, err := rules.Compile(lists)
	if err != nil {
		return err
	}
	snap := policy.NewSnapshot(state)
	var warnings []string
	if prev := a.rt.Load(); prev != nil {
		warnings = prev.warnings
	}
	a.rt.Store(&runtimeState{
		cfg:      cfg,
		warnings: warnings,
		snap:     snap,
		engine: &engine.Engine{
			Snapshot:  snap,
			Matcher:   matcher,
			Moderator: mod,
			Limits: extract.Limits{
				MaxBodyBytes:  cfg.Limits.MaxBodyBytes,
				MaxTextBytes:  cfg.Limits.MaxTextBytes,
				MaxImages:     cfg.Limits.MaxImages,
				MaxImageBytes: cfg.Limits.MaxImageBytes,
			},
			RemoteImages: cfg.RemoteImages,
		},
	})
	return nil
}

func (a *App) setBroken(cfg config.Config, err error) {
	a.logf("configuration failed, refusing moderated traffic until fixed: %v", err)
	a.rt.Store(&runtimeState{cfg: cfg, broken: err})
}

func (a *App) registration() Registration {
	d := config.Default()
	return Registration{
		SchemaVersion: SchemaVersion,
		Metadata: Metadata{
			Name:             PluginID,
			Version:          Version,
			Author:           PluginID,
			GitHubRepository: GitHubRepository,
			ConfigFields: []ConfigField{
				{Name: "state_file", Type: "string", Default: d.StateFile, Description: "Rules, wordlists and key bindings (JSON)"},
				{Name: "openai", Type: "object", Default: d.OpenAI, Description: "Moderation API: base_url, api_key_env, model, proxy_url, timeouts, concurrency, cache"},
				{Name: "limits", Type: "object", Default: d.Limits, Description: "Maximum body, text and image sizes for moderated requests"},
				{Name: "remote_images", Type: "enum", EnumValues: []string{"pass", "deny"}, Default: d.RemoteImages, Description: "pass: send image URLs to the moderation API; deny: reject them"},
				{Name: "audit_max_mb", Type: "integer", Default: d.AuditMaxMB, Description: "Rotate the audit file at this size (one backup kept)"},
				{Name: "event_buffer", Type: "integer", Default: d.EventBuffer, Description: "Recent events kept in memory for the admin page"},
				{Name: "debug", Type: "boolean", Default: d.Debug, Description: "Reserved for verbose diagnostics"},
				{Name: "audit_file", Type: "string", Default: d.AuditFile, Description: "Audit log (JSON lines, no content); empty disables"},
			},
		},
		Capabilities: Capabilities{
			RequestInterceptor:              true,
			RequestInterceptorOmitBodyAfter: true,
			ManagementAPI:                   true,
		},
	}
}

// logf writes through host.log when available so plugin messages land in the
// CLIProxyAPI log with its formatting; otherwise it falls back to stderr.
// Messages never contain request content, keys or credentials.
func (a *App) logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if hc := a.host(); hc != nil {
		payload, _ := json.Marshal(map[string]any{"level": "info", "message": "[cpa-moderation] " + msg})
		if _, err := hc("host.log", payload); err == nil {
			return
		}
	}
	if a.logger != nil {
		a.logger.Print(msg)
	}
}

type counters struct {
	skip, allow, block, errors atomic.Int64
}

func (c *counters) inc(o engine.Outcome) {
	switch o {
	case engine.OutcomeSkip:
		c.skip.Add(1)
	case engine.OutcomeAllow:
		c.allow.Add(1)
	case engine.OutcomeBlock:
		c.block.Add(1)
	default:
		c.errors.Add(1)
	}
}
