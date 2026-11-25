// Package rules implements the local wordlist engine: Unicode-normalized
// keyword matching with an Aho-Corasick automaton plus RE2 regular expressions.
package rules

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// Normalize prepares text for local matching only (never for forwarding):
// NFKC folds full-width and compatibility forms, case is folded, and invisible
// format characters (zero-width joiners etc.) are removed.
func Normalize(s string) string {
	s = norm.NFKC.String(s)
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.Is(unicode.Cf, r) {
			continue
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

// Hit identifies a match without revealing the matched word.
type Hit struct {
	Wordlist string
	Kind     string // "keyword" or "regex"
	Index    int
}

func (h Hit) RuleRef() string { return fmt.Sprintf("%s/%s#%d", h.Wordlist, h.Kind, h.Index) }

type List struct {
	ID       string
	Keywords []string
	Regex    []string
}

// Matcher is immutable after Compile and safe for concurrent use.
type Matcher struct {
	ac      *automaton
	regexes []compiledRegex
}

type compiledRegex struct {
	hit Hit
	re  *regexp.Regexp
}

func Compile(lists []List) (*Matcher, error) {
	m := &Matcher{ac: newAutomaton()}
	for _, l := range lists {
		for i, kw := range l.Keywords {
			n := Normalize(kw)
			if n == "" {
				continue
			}
			m.ac.add(n, Hit{Wordlist: l.ID, Kind: "keyword", Index: i})
		}
		for i, expr := range l.Regex {
			re, err := regexp.Compile(expr)
			if err != nil {
				return nil, fmt.Errorf("wordlist %s regex %d: %w", l.ID, i, err)
			}
			m.regexes = append(m.regexes, compiledRegex{hit: Hit{Wordlist: l.ID, Kind: "regex", Index: i}, re: re})
		}
	}
	m.ac.build()
	return m, nil
}

// Match returns the first hit restricted to the allowed wordlists (nil = all).
// Regexes run against the normalized text.
func (m *Matcher) Match(text string, allowed map[string]bool) (Hit, bool) {
	if m == nil {
		return Hit{}, false
	}
	n := Normalize(text)
	if h, ok := m.ac.find(n, allowed); ok {
		return h, true
	}
	for _, cr := range m.regexes {
		if allowed != nil && !allowed[cr.hit.Wordlist] {
			continue
		}
		if cr.re.MatchString(n) {
			return cr.hit, true
		}
	}
	return Hit{}, false
}

// ---------------- Aho-Corasick over runes ----------------

type node struct {
	next map[rune]int
	fail int
	out  []Hit // hits ending here, including those inherited via fail links
}

type automaton struct {
	nodes []node
}

func newAutomaton() *automaton {
	return &automaton{nodes: []node{{next: map[rune]int{}}}}
}

func (a *automaton) add(word string, h Hit) {
	cur := 0
	for _, r := range word {
		nxt, ok := a.nodes[cur].next[r]
		if !ok {
			a.nodes = append(a.nodes, node{next: map[rune]int{}})
			nxt = len(a.nodes) - 1
			a.nodes[cur].next[r] = nxt
		}
		cur = nxt
	}
	a.nodes[cur].out = append(a.nodes[cur].out, h)
}

func (a *automaton) build() {
	queue := make([]int, 0, len(a.nodes))
	for _, child := range a.nodes[0].next {
		a.nodes[child].fail = 0
		queue = append(queue, child)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for r, child := range a.nodes[cur].next {
			f := a.nodes[cur].fail
			for f != 0 {
				if _, ok := a.nodes[f].next[r]; ok {
					break
				}
				f = a.nodes[f].fail
			}
			if nxt, ok := a.nodes[f].next[r]; ok && nxt != child {
				a.nodes[child].fail = nxt
			} else {
				a.nodes[child].fail = 0
			}
			a.nodes[child].out = append(a.nodes[child].out, a.nodes[a.nodes[child].fail].out...)
			queue = append(queue, child)
		}
	}
}

func (a *automaton) find(text string, allowed map[string]bool) (Hit, bool) {
	cur := 0
	for _, r := range text {
		for cur != 0 {
			if _, ok := a.nodes[cur].next[r]; ok {
				break
			}
			cur = a.nodes[cur].fail
		}
		if nxt, ok := a.nodes[cur].next[r]; ok {
			cur = nxt
		}
		for _, h := range a.nodes[cur].out {
			if allowed == nil || allowed[h.Wordlist] {
				return h, true
			}
		}
	}
	return Hit{}, false
}
