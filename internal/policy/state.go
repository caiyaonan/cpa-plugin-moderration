// Package policy holds the admin-editable moderation rules, key bindings and
// wordlists, validates them, and resolves the effective policy for a request.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Known source formats reported by CLIProxyAPI in RequestInterceptRequest.SourceFormat.
var KnownFormats = []string{"openai", "openai-response", "openai-image", "claude", "gemini"}

var Roles = []string{"system", "user", "assistant", "tool"}

// DefaultRoles is used when a rule leaves include_roles empty. Assistant history
// is excluded by default because it was produced by the upstream model.
var DefaultRoles = []string{"system", "user", "tool"}

type State struct {
	Revision  int64      `json:"revision"`
	Rules     []Rule     `json:"rules"`
	Wordlists []Wordlist `json:"wordlists"`
	Keys      []Key      `json:"keys"`
}

type Rule struct {
	ID                 string            `json:"id"`
	Name               string            `json:"name"`
	Enabled            bool              `json:"enabled"`
	Models             []string          `json:"models"`
	Formats            []string          `json:"formats,omitempty"`
	CheckText          bool              `json:"check_text"`
	CheckImage         bool              `json:"check_image"`
	IncludeRoles       []string          `json:"include_roles,omitempty"`
	HistoryLastN       int               `json:"history_last_n,omitempty"`
	CategoryActions    map[string]string `json:"category_actions,omitempty"`
	Wordlists          []string          `json:"wordlists,omitempty"`
	UnsupportedContent string            `json:"unsupported_content"`
	OnError            string            `json:"on_error"`
}

type Wordlist struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Enabled  bool     `json:"enabled"`
	Keywords []string `json:"keywords"`
	Regex    []string `json:"regex"`
}

// Key never stores the raw API key: Scope is CLIProxyAPI's caller scope hash.
type Key struct {
	Scope   string   `json:"scope"`
	Preview string   `json:"preview"`
	Label   string   `json:"label,omitempty"`
	RuleIDs []string `json:"rule_ids"`
	Missing bool     `json:"missing,omitempty"`
}

// neverLogOnly lists categories that can never be downgraded to log-only.
var neverLogOnly = map[string]bool{"sexual/minors": true}

var (
	idPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	scopePattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

const (
	maxRules     = 500
	maxModels    = 200
	maxKeys      = 10000
	maxWordlists = 100
	maxWords     = 100000
	maxPattern   = 256
)

// callerScopeSalt must match CLIProxyAPI's session.CallerScope.
const callerScopeSalt = "cli-proxy-api:caller-scope:v1\x00"

func CallerScope(apiKey string) string {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(callerScopeSalt + apiKey))
	return hex.EncodeToString(sum[:])
}

func PreviewKey(key string) string {
	key = strings.TrimSpace(key)
	if len(key) <= 12 {
		return strings.Repeat("*", len(key))
	}
	return key[:6] + "…" + key[len(key)-4:]
}

// Normalize fills defaults in place; Validate must be called afterwards.
func (s *State) Normalize() {
	for i := range s.Rules {
		r := &s.Rules[i]
		r.ID = strings.TrimSpace(r.ID)
		r.Models = trimAll(r.Models)
		r.Formats = trimAll(r.Formats)
		r.IncludeRoles = trimAll(r.IncludeRoles)
		r.Wordlists = trimAll(r.Wordlists)
		if r.UnsupportedContent == "" {
			r.UnsupportedContent = "deny"
		}
		if r.OnError == "" {
			r.OnError = "deny"
		}
	}
	for i := range s.Wordlists {
		w := &s.Wordlists[i]
		w.ID = strings.TrimSpace(w.ID)
		w.Keywords = trimAll(w.Keywords)
		w.Regex = trimAll(w.Regex)
	}
	for i := range s.Keys {
		k := &s.Keys[i]
		k.Scope = strings.ToLower(strings.TrimSpace(k.Scope))
		k.RuleIDs = trimAll(k.RuleIDs)
	}
}

func (s *State) Validate() error {
	var errs []string
	add := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }
	if len(s.Rules) > maxRules {
		add("too many rules (max %d)", maxRules)
	}
	if len(s.Keys) > maxKeys {
		add("too many keys (max %d)", maxKeys)
	}
	if len(s.Wordlists) > maxWordlists {
		add("too many wordlists (max %d)", maxWordlists)
	}
	wordlists := map[string]bool{}
	words := 0
	for _, w := range s.Wordlists {
		if !idPattern.MatchString(w.ID) {
			add("wordlist id %q is invalid (lowercase letters, digits, . _ -)", w.ID)
		}
		if wordlists[w.ID] {
			add("duplicate wordlist id %q", w.ID)
		}
		wordlists[w.ID] = true
		words += len(w.Keywords) + len(w.Regex)
		for _, kw := range w.Keywords {
			if kw == "" {
				add("wordlist %q has an empty keyword", w.ID)
			}
			// U+FFFD means the client sent non-UTF-8 text (e.g. a GBK console);
			// such a keyword would silently never match.
			if strings.ContainsRune(kw, utf8.RuneError) {
				add("wordlist %q has a keyword that is not valid UTF-8 text", w.ID)
			}
		}
		for _, expr := range w.Regex {
			if len(expr) > maxPattern*4 {
				add("wordlist %q regex is too long", w.ID)
				continue
			}
			if _, err := regexp.Compile(expr); err != nil {
				add("wordlist %q regex %q: %v", w.ID, expr, err)
			}
		}
	}
	if words > maxWords {
		add("too many keywords and regex in total (max %d)", maxWords)
	}
	rules := map[string]bool{}
	for _, r := range s.Rules {
		if !idPattern.MatchString(r.ID) {
			add("rule id %q is invalid (lowercase letters, digits, . _ -)", r.ID)
		}
		if rules[r.ID] {
			add("duplicate rule id %q", r.ID)
		}
		rules[r.ID] = true
		if len(r.Models) == 0 {
			add("rule %q must list at least one model (use \"*\" to match every model)", r.ID)
		}
		if len(r.Models) > maxModels {
			add("rule %q has too many models (max %d)", r.ID, maxModels)
		}
		for _, m := range r.Models {
			if m == "" || len(m) > maxPattern {
				add("rule %q has an empty or too long model pattern", r.ID)
			}
		}
		for _, f := range r.Formats {
			if !contains(KnownFormats, f) {
				add("rule %q format %q is unknown (allowed: %s)", r.ID, f, strings.Join(KnownFormats, ", "))
			}
		}
		for _, role := range r.IncludeRoles {
			if !contains(Roles, role) {
				add("rule %q role %q is unknown (allowed: %s)", r.ID, role, strings.Join(Roles, ", "))
			}
		}
		if r.HistoryLastN < 0 || r.HistoryLastN > 10000 {
			add("rule %q history_last_n must be between 0 and 10000", r.ID)
		}
		if !r.CheckText && !r.CheckImage && len(r.Wordlists) == 0 {
			add("rule %q checks nothing: enable check_text, check_image or a wordlist", r.ID)
		}
		for cat, action := range r.CategoryActions {
			if strings.TrimSpace(cat) == "" || (action != "block" && action != "log") {
				add("rule %q category action %q=%q is invalid (block or log)", r.ID, cat, action)
			}
			if action == "log" && neverLogOnly[cat] {
				add("rule %q: category %q must always block", r.ID, cat)
			}
		}
		for _, w := range r.Wordlists {
			if !wordlists[w] {
				add("rule %q references unknown wordlist %q", r.ID, w)
			}
		}
		if r.UnsupportedContent != "deny" && r.UnsupportedContent != "allow" {
			add("rule %q unsupported_content must be deny or allow", r.ID)
		}
		if r.OnError != "deny" && r.OnError != "allow" {
			add("rule %q on_error must be deny or allow", r.ID)
		}
	}
	scopes := map[string]bool{}
	for _, k := range s.Keys {
		if !scopePattern.MatchString(k.Scope) {
			add("key scope %q is not a caller scope hash", k.Scope)
		}
		if scopes[k.Scope] {
			add("duplicate key scope %q", short(k.Scope))
		}
		scopes[k.Scope] = true
		for _, id := range k.RuleIDs {
			if !rules[id] {
				add("key %s references unknown rule %q", short(k.Scope), id)
			}
		}
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return fmt.Errorf("invalid moderation state: %s", strings.Join(errs, "; "))
	}
	return nil
}

func trimAll(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			if v == "" {
				out = append(out, v) // keep so Validate can report it
			}
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func short(scope string) string {
	if len(scope) > 12 {
		return scope[:12]
	}
	return scope
}
