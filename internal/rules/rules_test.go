package rules

import (
	"fmt"
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	if got := Normalize("ＢＡＤ​word"); got != "badword" {
		t.Fatalf("got %q", got)
	}
}

func TestMatcher(t *testing.T) {
	m, err := Compile([]List{
		{ID: "a", Keywords: []string{"he", "she", "his", "hers"}},
		{ID: "b", Keywords: []string{"测试词"}, Regex: []string{`\bfoo\d+\b`}},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		text    string
		allowed map[string]bool
		want    string
	}{
		{"ushers", nil, "a/keyword#"},
		{"xyz only", nil, ""},
		{"这是测试词。", nil, "b/keyword#0"},
		{"这是ＴＥＳＴ測試", nil, ""},
		{"x FOO12 y", nil, "b/regex#0"},
		{"ushers", map[string]bool{"b": true}, ""},
		{"测​试词", map[string]bool{"b": true}, "b/keyword#0"},
	}
	for _, c := range cases {
		h, ok := m.Match(c.text, c.allowed)
		got := ""
		if ok {
			got = h.RuleRef()
		}
		if c.want == "" && ok || c.want != "" && !strings.HasPrefix(got, c.want) {
			t.Errorf("Match(%q)=%q want prefix %q", c.text, got, c.want)
		}
	}
}

func TestMatcherDoesNotLeakWord(t *testing.T) {
	m, _ := Compile([]List{{ID: "w", Keywords: []string{"secretword"}}})
	h, ok := m.Match("a secretword b", nil)
	if !ok || strings.Contains(h.RuleRef(), "secret") {
		t.Fatalf("hit ref must not contain the word: %q", h.RuleRef())
	}
}

func TestBadRegex(t *testing.T) {
	if _, err := Compile([]List{{ID: "w", Regex: []string{"("}}}); err == nil {
		t.Fatal("expected error")
	}
}

func BenchmarkMatch10kWords1KiB(b *testing.B) {
	words := make([]string, 10000)
	for i := range words {
		words[i] = fmt.Sprintf("词%05dword", i)
	}
	m, _ := Compile([]List{{ID: "w", Keywords: words}})
	text := strings.Repeat("这是一段普通的中文与English混合文本。", 20)[:1024]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Match(text, nil)
	}
}
