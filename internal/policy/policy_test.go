package policy

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestGlob(t *testing.T) {
	cases := []struct {
		p, n string
		want bool
	}{
		{"gpt-image-*", "gpt-image-1", true},
		{"gpt-image-*", "gpt-image-", true},
		{"gpt-image-*", "GPT-image-1", false}, // case-sensitive
		{"gpt-6*", "gpt-6-mini", true},
		{"gpt-6*", "gpt-5", false},
		{"gpt-?", "gpt-5", true},
		{"gpt-?", "gpt-55", false},
		{"*", "", true},
		{"*mini", "gpt-6-mini", true},
		{"a*b*c", "aXXbYYc", true},
		{"a*b*c", "aXXbYY", false},
		{"模型*", "模型一", true},
		{"exact", "exact", true},
		{"exact", "exactly", false},
	}
	for _, c := range cases {
		if got := Glob(c.p, c.n); got != c.want {
			t.Errorf("Glob(%q,%q)=%v want %v", c.p, c.n, got, c.want)
		}
	}
}

func scopeOf(k string) string { return CallerScope(k) }

func baseState() State {
	return State{
		Rules: []Rule{
			{ID: "image", Enabled: true, Models: []string{"gpt-image-*", "gpt-6*"}, CheckText: true, CheckImage: true},
			{ID: "text-log", Enabled: true, Models: []string{"gpt-6*"}, CheckText: true, CategoryActions: map[string]string{"violence": "log"}, OnError: "allow", HistoryLastN: 4},
			{ID: "off", Enabled: false, Models: []string{"*"}, CheckText: true},
			{ID: "claude-only", Enabled: true, Models: []string{"*"}, Formats: []string{"claude"}, CheckText: true, Wordlists: []string{"w"}},
		},
		Wordlists: []Wordlist{{ID: "w", Enabled: true, Keywords: []string{"x"}}},
		Keys: []Key{
			{Scope: scopeOf("sk-a"), RuleIDs: []string{"image", "text-log", "off"}},
			{Scope: scopeOf("sk-b"), RuleIDs: []string{"claude-only"}},
			{Scope: scopeOf("sk-c"), RuleIDs: []string{}},
		},
	}
}

func TestValidateAcceptsBaseState(t *testing.T) {
	s := baseState()
	s.Normalize()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejects(t *testing.T) {
	mut := map[string]func(*State){
		"duplicate rule":    func(s *State) { s.Rules = append(s.Rules, s.Rules[0]) },
		"empty models":      func(s *State) { s.Rules[0].Models = nil },
		"bad id":            func(s *State) { s.Rules[0].ID = "Bad ID" },
		"unknown format":    func(s *State) { s.Rules[0].Formats = []string{"soap"} },
		"unknown role":      func(s *State) { s.Rules[0].IncludeRoles = []string{"robot"} },
		"checks nothing":    func(s *State) { s.Rules[0].CheckText, s.Rules[0].CheckImage = false, false },
		"bad action":        func(s *State) { s.Rules[0].CategoryActions = map[string]string{"x": "ignore"} },
		"bad on_error":      func(s *State) { s.Rules[0].OnError = "maybe" },
		"unknown wordlist":  func(s *State) { s.Rules[0].Wordlists = []string{"nope"} },
		"bad regex":         func(s *State) { s.Wordlists[0].Regex = []string{"("} },
		"bad scope":         func(s *State) { s.Keys[0].Scope = "sk-raw-key" },
		"unknown rule ref":  func(s *State) { s.Keys[0].RuleIDs = []string{"ghost"} },
		"negative history":  func(s *State) { s.Rules[0].HistoryLastN = -1 },
		"duplicate scope":   func(s *State) { s.Keys = append(s.Keys, s.Keys[0]) },
		"empty model entry": func(s *State) { s.Rules[0].Models = []string{"  "} },
	}
	for name, m := range mut {
		s := baseState()
		m(&s)
		s.Normalize()
		if err := s.Validate(); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func TestMatch(t *testing.T) {
	s := baseState()
	s.Normalize()
	snap := NewSnapshot(s)

	if eff := snap.Match(scopeOf("sk-a"), []string{"mock-chat"}, "openai"); eff != nil {
		t.Fatalf("unmatched model must not match, got %+v", eff)
	}
	if eff := snap.Match(scopeOf("sk-c"), []string{"gpt-image-1"}, "openai"); eff != nil {
		t.Fatal("key without rules must not match")
	}
	if eff := snap.Match(scopeOf("unknown"), []string{"gpt-image-1"}, "openai"); eff != nil {
		t.Fatal("unknown scope must not match")
	}
	if eff := snap.Match("", []string{"gpt-image-1"}, "openai"); eff != nil {
		t.Fatal("empty scope must not match")
	}

	eff := snap.Match(scopeOf("sk-a"), []string{"gpt-image-1"}, "openai-image")
	if eff == nil || strings.Join(eff.RuleIDs, ",") != "image" || !eff.CheckImage || !eff.DenyOnError {
		t.Fatalf("image rule: %+v", eff)
	}

	// Two rules match: stricter options win.
	eff = snap.Match(scopeOf("sk-a"), []string{"gpt-6-mini"}, "openai")
	if eff == nil || strings.Join(eff.RuleIDs, ",") != "image,text-log" {
		t.Fatalf("merged: %+v", eff)
	}
	if !eff.DenyOnError {
		t.Error("deny must win over allow for on_error")
	}
	if eff.HistoryLastN != 0 {
		t.Error("whole history must win over last-N")
	}
	if eff.LogOnly["violence"] {
		t.Error("log-only requires every matched rule to agree")
	}
	if !eff.CheckImage || !eff.CheckText {
		t.Error("checks must be OR-ed")
	}

	// Alias: either requested or routed model may match.
	if snap.Match(scopeOf("sk-a"), []string{"friendly-alias", "gpt-image-1"}, "openai") == nil {
		t.Error("routed model must also be considered")
	}

	// Format filter.
	if snap.Match(scopeOf("sk-b"), []string{"anything"}, "openai") != nil {
		t.Error("format filter ignored")
	}
	eff = snap.Match(scopeOf("sk-b"), []string{"anything"}, "claude")
	if eff == nil || len(eff.Wordlists) != 1 {
		t.Fatalf("claude rule: %+v", eff)
	}
}

func TestLogOnlyWhenSingleRule(t *testing.T) {
	s := baseState()
	s.Keys[0].RuleIDs = []string{"text-log"}
	s.Normalize()
	eff := NewSnapshot(s).Match(scopeOf("sk-a"), []string{"gpt-6"}, "openai")
	if eff == nil || !eff.LogOnly["violence"] || eff.DenyOnError || eff.HistoryLastN != 4 {
		t.Fatalf("%+v", eff)
	}
	if !eff.Roles["user"] || eff.Roles["assistant"] {
		t.Fatalf("default roles wrong: %+v", eff.Roles)
	}
}

func TestStoreRevisionAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, s, err := Open(path)
	if err != nil || s.Revision != 0 {
		t.Fatalf("open: %v %v", s, err)
	}
	next, err := st.Update(0, func(s *State) error { *s = baseState(); return nil })
	if err != nil || next.Revision != 1 {
		t.Fatalf("update: %v %v", next.Revision, err)
	}
	if _, err := st.Update(0, func(*State) error { return nil }); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	if _, err := st.Update(1, func(s *State) error { s.Rules[0].Models = nil; return nil }); err == nil {
		t.Fatal("invalid update must fail")
	}
	if st.Current().Revision != 1 || len(st.Current().Rules[0].Models) == 0 {
		t.Fatal("failed update must keep previous state")
	}
	_, reopened, err := Open(path)
	if err != nil || reopened.Revision != 1 || len(reopened.Rules) != 4 {
		t.Fatalf("reopen: %+v %v", reopened.Revision, err)
	}
}

func TestCallerScopeMatchesHost(t *testing.T) {
	// Observed in the PoC: scope of "sk-poc-image-business" reported by CPA v8.1.2.
	got := CallerScope("sk-poc-image-business")
	if got != "1e8abfd6f5ce12912bc91246d390a5730ca61656656fa3084c22bf0c1e612d3a" {
		t.Fatalf("caller scope drifted from host: %s", got)
	}
}

func TestRejectsMojibakeKeyword(t *testing.T) {
	s := baseState()
	s.Wordlists[0].Keywords = []string{"��"}
	s.Normalize()
	if err := s.Validate(); err == nil {
		t.Fatal("keywords with U+FFFD must be rejected")
	}
}

func TestMinorsCategoryCannotBeLogOnly(t *testing.T) {
	s := baseState()
	s.Rules[0].CategoryActions = map[string]string{"sexual/minors": "log"}
	s.Normalize()
	if err := s.Validate(); err == nil {
		t.Fatal("sexual/minors must always block")
	}
}

func TestThresholdsMergeStrictestAndValidate(t *testing.T) {
	s := baseState()
	s.Rules[0].CategoryThresholds = map[string]float64{"sexual": 0.4, "violence": 0.5}
	s.Rules[1].CategoryThresholds = map[string]float64{"sexual": 0.2}
	s.Normalize()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	eff := NewSnapshot(s).Match(scopeOf("sk-a"), []string{"gpt-6-mini"}, "openai")
	if eff.Thresholds["sexual"] != 0.2 || eff.Thresholds["violence"] != 0.5 {
		t.Fatalf("strictest threshold must win: %+v", eff.Thresholds)
	}
	for _, bad := range []float64{0, -0.1, 1.5} {
		s := baseState()
		s.Rules[0].CategoryThresholds = map[string]float64{"sexual": bad}
		s.Normalize()
		if err := s.Validate(); err == nil {
			t.Errorf("threshold %v must be rejected", bad)
		}
	}
}
