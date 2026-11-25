package config

import (
	"strings"
	"testing"
)

func TestHostOwnedKeysAreNotWarnings(t *testing.T) {
	// Shape written by CLIProxyAPI after a plugin-store install.
	raw := `
enabled: true
priority: 1
store:
  schema-version: 2
  id: cpa-moderation
  version: 0.1.0
  release-tag: v0.1.0
  install:
    type: direct
    artifacts:
      - goos: linux
        goarch: amd64
        url: https://example.com/a.zip
        sha256: abc
`
	cfg, warnings, err := Decode([]byte(raw))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("host-owned keys must load cleanly: err=%v warnings=%v", err, warnings)
	}
	if !cfg.Enabled || cfg.Priority != 1 {
		t.Fatalf("host keys not read: %+v", cfg)
	}
}

func TestUnknownFieldsWarnAndBadValuesFail(t *testing.T) {
	_, warnings, err := Decode([]byte("typo_field: 1\nopenai:\n  modle: x\n"))
	if err != nil || len(warnings) != 2 || !strings.Contains(warnings[0], "typo_field") {
		t.Fatalf("unknown fields must be warnings: %v %v", warnings, err)
	}
	for _, bad := range []string{"openai:\n  timeout_ms: -1\n", "remote_images: maybe\n", "openai:\n  base_url: ftp://x\n", "limits: 5\n"} {
		if _, _, err := Decode([]byte(bad)); err == nil {
			t.Errorf("%q must fail", bad)
		}
	}
}

func TestAPIKeyInConfig(t *testing.T) {
	cfg, warnings, err := Decode([]byte("openai:\n  api_key: sk-test-123\n"))
	if err != nil || len(warnings) != 0 || cfg.OpenAI.APIKey != "sk-test-123" {
		t.Fatalf("api_key must be a known field: %v %v %q", err, warnings, cfg.OpenAI.APIKey)
	}
	if _, _, err := Decode([]byte("openai:\n  api_key: \"sk bad\"\n")); err == nil {
		t.Fatal("api_key with whitespace must be rejected")
	}
	if _, _, err := Decode([]byte("openai:\n  api_key: sk-x\n  api_key_env: \"\"\n")); err != nil {
		t.Fatalf("api_key alone is enough: %v", err)
	}
	if _, _, err := Decode([]byte("openai:\n  api_key_env: \"\"\n")); err == nil {
		t.Fatal("neither api_key nor api_key_env must fail")
	}
}

func TestFlatFieldsOverrideNested(t *testing.T) {
	raw := `
api_key: sk-flat
moderation_model: omni-moderation-2024-09-26
proxy_url: http://127.0.0.1:7890
timeout_ms: 3000
max_concurrency: 4
max_images: 2
openai:
  api_key: sk-nested
  model: nested-model
  timeout_ms: 9000
  max_inflight: 8
limits:
  max_images: 5
  max_text_bytes: 1000
`
	cfg, warnings, err := Decode([]byte(raw))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("decode: %v %v", err, warnings)
	}
	o := cfg.OpenAI
	if o.APIKey != "sk-flat" || o.Model != "omni-moderation-2024-09-26" || o.ProxyURL != "http://127.0.0.1:7890" ||
		o.TimeoutMS != 3000 || o.MaxInflight != 4 || cfg.Limits.MaxImages != 2 {
		t.Fatalf("flat values must win: %+v %+v", o, cfg.Limits)
	}
	if cfg.Limits.MaxTextBytes != 1000 {
		t.Fatalf("nested value without a flat override must stay: %d", cfg.Limits.MaxTextBytes)
	}
}

func TestEmptyFlatFieldsKeepNestedAndDefaults(t *testing.T) {
	// A management UI clears a field by deleting it or writing null/empty.
	cfg, _, err := Decode([]byte("api_key: \"\"\ntimeout_ms: null\nopenai:\n  api_key: sk-nested\n"))
	if err != nil || cfg.OpenAI.APIKey != "sk-nested" || cfg.OpenAI.TimeoutMS != Default().OpenAI.TimeoutMS {
		t.Fatalf("empty flat must not override: %v %+v", err, cfg.OpenAI)
	}
	cfg, _, err = Decode([]byte("openai:\n  model: legacy\n"))
	if err != nil || cfg.OpenAI.Model != "legacy" {
		t.Fatalf("nested-only configs from v0.1.x must keep working: %v %q", err, cfg.OpenAI.Model)
	}
	if _, _, err := Decode([]byte("timeout_ms: -5\n")); err == nil {
		t.Fatal("invalid flat values must be rejected")
	}
	if _, _, err := Decode([]byte("api_key: \"sk with space\"\n")); err == nil {
		t.Fatal("api_key with whitespace must be rejected")
	}
}
