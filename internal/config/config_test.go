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
