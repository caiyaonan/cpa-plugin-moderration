package policy

import "sort"

// Snapshot is an immutable, indexed view of a validated State. It is swapped
// atomically so request handling never takes a lock.
type Snapshot struct {
	state     State
	rules     map[string]Rule
	wordlists map[string]Wordlist
	bindings  map[string][]string
}

func NewSnapshot(s State) *Snapshot {
	snap := &Snapshot{
		state:     s,
		rules:     make(map[string]Rule, len(s.Rules)),
		wordlists: make(map[string]Wordlist, len(s.Wordlists)),
		bindings:  make(map[string][]string, len(s.Keys)),
	}
	for _, r := range s.Rules {
		snap.rules[r.ID] = r
	}
	for _, w := range s.Wordlists {
		snap.wordlists[w.ID] = w
	}
	for _, k := range s.Keys {
		if len(k.RuleIDs) > 0 {
			snap.bindings[k.Scope] = k.RuleIDs
		}
	}
	return snap
}

func (s *Snapshot) State() State { return s.state }

// Effective is the merged policy of every rule that matched a request. Merging
// always picks the stricter option so that no rule can weaken another.
type Effective struct {
	RuleIDs         []string
	CheckText       bool
	CheckImage      bool
	Roles           map[string]bool
	HistoryLastN    int // 0 = whole history
	LogOnly         map[string]bool
	Thresholds      map[string]float64 // lowest (strictest) threshold per category
	Wordlists       []Wordlist
	DenyUnsupported bool
	DenyOnError     bool
}

// Match returns nil when the caller scope has no enabled rule matching any of
// the given model names and the source format.
func (s *Snapshot) Match(scope string, models []string, format string) *Effective {
	if s == nil || scope == "" {
		return nil
	}
	ids := s.bindings[scope]
	if len(ids) == 0 {
		return nil
	}
	var matched []Rule
	for _, id := range ids {
		r, ok := s.rules[id]
		if !ok || !r.Enabled {
			continue
		}
		if len(r.Formats) > 0 && !contains(r.Formats, format) {
			continue
		}
		if matchAnyModel(r.Models, models) {
			matched = append(matched, r)
		}
	}
	if len(matched) == 0 {
		return nil
	}
	return s.merge(matched)
}

func matchAnyModel(patterns, models []string) bool {
	for _, m := range models {
		if m == "" {
			continue
		}
		for _, p := range patterns {
			if Glob(p, m) {
				return true
			}
		}
	}
	return false
}

func (s *Snapshot) merge(rules []Rule) *Effective {
	eff := &Effective{Roles: map[string]bool{}, Thresholds: map[string]float64{}}
	logVotes := map[string]int{}
	wl := map[string]bool{}
	wholeHistory := false
	for _, r := range rules {
		eff.RuleIDs = append(eff.RuleIDs, r.ID)
		eff.CheckText = eff.CheckText || r.CheckText
		eff.CheckImage = eff.CheckImage || r.CheckImage
		roles := r.IncludeRoles
		if len(roles) == 0 {
			roles = DefaultRoles
		}
		for _, role := range roles {
			eff.Roles[role] = true
		}
		if r.HistoryLastN == 0 {
			wholeHistory = true
		} else if r.HistoryLastN > eff.HistoryLastN {
			eff.HistoryLastN = r.HistoryLastN
		}
		for cat, action := range r.CategoryActions {
			if action == "log" {
				logVotes[cat]++
			}
		}
		for cat, th := range r.CategoryThresholds {
			if cur, ok := eff.Thresholds[cat]; !ok || th < cur {
				eff.Thresholds[cat] = th
			}
		}
		for _, id := range r.Wordlists {
			if w, ok := s.wordlists[id]; ok && w.Enabled && !wl[id] {
				wl[id] = true
				eff.Wordlists = append(eff.Wordlists, w)
			}
		}
		eff.DenyUnsupported = eff.DenyUnsupported || r.UnsupportedContent != "allow"
		eff.DenyOnError = eff.DenyOnError || r.OnError != "allow"
	}
	if wholeHistory {
		eff.HistoryLastN = 0
	}
	// A category is log-only only when every matched rule says so.
	eff.LogOnly = map[string]bool{}
	for cat, votes := range logVotes {
		if votes == len(rules) {
			eff.LogOnly[cat] = true
		}
	}
	sort.Strings(eff.RuleIDs)
	return eff
}
