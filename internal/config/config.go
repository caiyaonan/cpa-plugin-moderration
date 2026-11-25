// Package config decodes the static plugin configuration that CLIProxyAPI
// passes from plugins.configs.cpa-moderation.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// Enabled, Priority and Store are owned by the host (plugins.configs.<id>);
	// Store is written by plugin-store installs to pin the installed version.
	Enabled   bool      `yaml:"enabled" json:"enabled"`
	Priority  int       `yaml:"priority" json:"priority"`
	Store     yaml.Node `yaml:"store,omitempty" json:"-"`
	StateFile string    `yaml:"state_file" json:"state_file"`
	OpenAI    OpenAI    `yaml:"openai" json:"openai"`
	Limits    Limits    `yaml:"limits" json:"limits"`
	// RemoteImages controls http(s) image URLs: "pass" forwards the URL to the
	// moderation API (OpenAI fetches it; the plugin never downloads), "deny" rejects.
	RemoteImages string `yaml:"remote_images" json:"remote_images"`
	EventBuffer  int    `yaml:"event_buffer" json:"event_buffer"`
	// AuditFile receives one JSON line per moderated request (no content).
	// Empty disables the file; the in-memory event buffer is always kept.
	AuditFile  string `yaml:"audit_file" json:"audit_file"`
	AuditMaxMB int    `yaml:"audit_max_mb" json:"audit_max_mb"`
	Debug      bool   `yaml:"debug" json:"debug"`
}

type OpenAI struct {
	BaseURL          string `yaml:"base_url" json:"base_url"`
	APIKeyEnv        string `yaml:"api_key_env" json:"api_key_env"`
	Model            string `yaml:"model" json:"model"`
	ProxyURL         string `yaml:"proxy_url" json:"proxy_url"`
	TimeoutMS        int    `yaml:"timeout_ms" json:"timeout_ms"`
	MaxInflight      int    `yaml:"max_inflight" json:"max_inflight"`
	QueueTimeoutMS   int    `yaml:"queue_timeout_ms" json:"queue_timeout_ms"`
	TextsPerRequest  int    `yaml:"texts_per_request" json:"texts_per_request"`
	ImagesPerRequest int    `yaml:"images_per_request" json:"images_per_request"`
	ChunkChars       int    `yaml:"chunk_chars" json:"chunk_chars"`
	ChunkOverlap     int    `yaml:"chunk_overlap" json:"chunk_overlap"`
	CacheTTLSeconds  int    `yaml:"cache_ttl_seconds" json:"cache_ttl_seconds"`
	CacheMaxEntries  int    `yaml:"cache_max_entries" json:"cache_max_entries"`
}

type Limits struct {
	MaxBodyBytes  int `yaml:"max_body_bytes" json:"max_body_bytes"`
	MaxTextBytes  int `yaml:"max_text_bytes" json:"max_text_bytes"`
	MaxImages     int `yaml:"max_images" json:"max_images"`
	MaxImageBytes int `yaml:"max_image_bytes" json:"max_image_bytes"`
}

func Default() Config {
	return Config{
		Enabled:   true,
		StateFile: "plugins/cpa-moderation-state-v1.json",
		OpenAI: OpenAI{
			BaseURL:          "https://api.openai.com/v1",
			APIKeyEnv:        "OPENAI_MODERATION_API_KEY",
			Model:            "omni-moderation-latest",
			TimeoutMS:        8000,
			MaxInflight:      16,
			QueueTimeoutMS:   250,
			TextsPerRequest:  16,
			ImagesPerRequest: 1,
			ChunkChars:       8000,
			ChunkOverlap:     200,
			CacheTTLSeconds:  600,
			CacheMaxEntries:  10000,
		},
		Limits: Limits{
			MaxBodyBytes:  32 << 20,
			MaxTextBytes:  256 << 10,
			MaxImages:     8,
			MaxImageBytes: 10 << 20,
		},
		RemoteImages: "pass",
		EventBuffer:  1000,
		AuditFile:    "plugins/cpa-moderation-audit.jsonl",
		AuditMaxMB:   50,
	}
}

// Decode parses the plugin YAML. Unknown fields do not fail the load (the
// plugin guide requires accepting configs written for other versions, and the
// host management API may add fields); they are returned as warnings so a typo
// is still visible. Wrong types and invalid values are errors.
func Decode(raw []byte) (Config, []string, error) {
	cfg := Default()
	var warnings []string
	if len(bytes.TrimSpace(raw)) > 0 {
		strict := yaml.NewDecoder(bytes.NewReader(raw))
		strict.KnownFields(true)
		err := strict.Decode(&cfg)
		if err != nil && !errors.Is(err, io.EOF) {
			var te *yaml.TypeError
			if !errors.As(err, &te) || !onlyUnknownFields(te) {
				return Config{}, nil, fmt.Errorf("parse plugin config: %w", err)
			}
			cfg = Default()
			if err := yaml.Unmarshal(raw, &cfg); err != nil {
				return Config{}, nil, fmt.Errorf("parse plugin config: %w", err)
			}
			for _, msg := range te.Errors {
				warnings = append(warnings, "ignored unknown config field: "+msg)
			}
		}
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, nil, err
	}
	return cfg, warnings, nil
}

func onlyUnknownFields(te *yaml.TypeError) bool {
	for _, msg := range te.Errors {
		if !strings.Contains(msg, "not found in type") {
			return false
		}
	}
	return len(te.Errors) > 0
}

func (c Config) Validate() error {
	var errs []string
	add := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }
	if strings.TrimSpace(c.StateFile) == "" {
		add("state_file is required")
	}
	u, err := url.Parse(c.OpenAI.BaseURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		add("openai.base_url must be an absolute http(s) URL")
	}
	if c.OpenAI.ProxyURL != "" {
		if p, err := url.Parse(c.OpenAI.ProxyURL); err != nil || p.Host == "" {
			add("openai.proxy_url is invalid")
		}
	}
	if strings.TrimSpace(c.OpenAI.APIKeyEnv) == "" {
		add("openai.api_key_env is required")
	}
	if strings.TrimSpace(c.OpenAI.Model) == "" {
		add("openai.model is required")
	}
	positive := map[string]int{
		"openai.timeout_ms":         c.OpenAI.TimeoutMS,
		"openai.max_inflight":       c.OpenAI.MaxInflight,
		"openai.texts_per_request":  c.OpenAI.TextsPerRequest,
		"openai.images_per_request": c.OpenAI.ImagesPerRequest,
		"openai.chunk_chars":        c.OpenAI.ChunkChars,
		"limits.max_body_bytes":     c.Limits.MaxBodyBytes,
		"limits.max_text_bytes":     c.Limits.MaxTextBytes,
		"limits.max_images":         c.Limits.MaxImages,
		"limits.max_image_bytes":    c.Limits.MaxImageBytes,
		"event_buffer":              c.EventBuffer,
		"audit_max_mb":              c.AuditMaxMB,
	}
	for name, v := range positive {
		if v <= 0 {
			add("%s must be greater than zero", name)
		}
	}
	nonNegative := map[string]int{
		"openai.queue_timeout_ms":  c.OpenAI.QueueTimeoutMS,
		"openai.chunk_overlap":     c.OpenAI.ChunkOverlap,
		"openai.cache_ttl_seconds": c.OpenAI.CacheTTLSeconds,
		"openai.cache_max_entries": c.OpenAI.CacheMaxEntries,
	}
	for name, v := range nonNegative {
		if v < 0 {
			add("%s must not be negative", name)
		}
	}
	if c.OpenAI.ChunkOverlap >= c.OpenAI.ChunkChars && c.OpenAI.ChunkChars > 0 {
		add("openai.chunk_overlap must be smaller than openai.chunk_chars")
	}
	if c.OpenAI.TimeoutMS > 60000 {
		add("openai.timeout_ms must not exceed 60000")
	}
	switch c.RemoteImages {
	case "pass", "deny":
	default:
		add("remote_images must be pass or deny")
	}
	if len(errs) > 0 {
		return fmt.Errorf("invalid plugin config: %s", strings.Join(errs, "; "))
	}
	return nil
}
