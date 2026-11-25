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
		APIKey:           cfg.OpenAI.APIKey,
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
			// Flat scalar fields only: host management UIs render object fields as raw
			// JSON. Defaults are stated in the descriptions; leaving a field empty keeps
			// the default (or the value from the nested openai:/limits: YAML, still accepted).
			ConfigFields: []ConfigField{
				{Name: "api_key", Type: "string", Description: "OpenAI API Key（platform.openai.com 创建）。填写后优先于环境变量；留空则读取 api_key_env 指定的环境变量。注意：管理面板会以明文显示此值"},
				{Name: "api_key_env", Type: "string", Description: "api_key 为空时读取的环境变量名。默认 " + d.OpenAI.APIKeyEnv},
				{Name: "moderation_model", Type: "string", Description: "审核模型。默认 " + d.OpenAI.Model},
				{Name: "proxy_url", Type: "string", Description: "访问审核接口使用的代理，例如 http://127.0.0.1:7890 或 socks5://…。留空直连"},
				{Name: "api_base_url", Type: "string", Description: "审核接口地址。默认 " + d.OpenAI.BaseURL},
				{Name: "timeout_ms", Type: "integer", Description: fmt.Sprintf("单次审核请求超时（毫秒），超时按审核服务不可用处理。默认 %d", d.OpenAI.TimeoutMS)},
				{Name: "max_concurrency", Type: "integer", Description: fmt.Sprintf("同时进行的审核请求上限，排不上队返回 429。默认 %d", d.OpenAI.MaxInflight)},
				{Name: "remote_images", Type: "enum", EnumValues: []string{"pass", "deny"}, Default: d.RemoteImages, Description: "请求中的 http(s) 图片链接：pass 交给审核接口去拉取（插件不下载），deny 直接拒绝。默认 pass"},
				{Name: "max_body_bytes", Type: "integer", Description: fmt.Sprintf("受审核请求的最大请求体字节数，超出返回 413。默认 %d（32MB）", d.Limits.MaxBodyBytes)},
				{Name: "max_text_bytes", Type: "integer", Description: fmt.Sprintf("单个请求待审核文本的最大字节数。默认 %d（256KB）", d.Limits.MaxTextBytes)},
				{Name: "max_images", Type: "integer", Description: fmt.Sprintf("单个请求最多图片数。默认 %d", d.Limits.MaxImages)},
				{Name: "max_image_bytes", Type: "integer", Description: fmt.Sprintf("单张图片最大字节数。默认 %d（10MB）", d.Limits.MaxImageBytes)},
				{Name: "state_file", Type: "string", Description: "规则、词库和 Key 绑定的保存位置。默认 " + d.StateFile},
				{Name: "audit_file", Type: "string", Description: "审计日志文件（JSON 行，不含请求原文）。默认 " + d.AuditFile},
				{Name: "audit_max_mb", Type: "integer", Description: fmt.Sprintf("审计日志达到此大小时轮转（保留 1 份备份）。默认 %d", d.AuditMaxMB)},
				{Name: "event_buffer", Type: "integer", Description: fmt.Sprintf("管理页「审核记录」在内存中保留的条数。默认 %d", d.EventBuffer)},
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
