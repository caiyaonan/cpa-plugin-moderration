package moderation

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakeAPI struct {
	calls  atomic.Int32
	handle func(w http.ResponseWriter, input any)
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.calls.Add(1)
	if r.URL.Path != "/v1/moderations" || r.Header.Get("Authorization") != "Bearer test-key" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var req struct {
		Model string `json:"model"`
		Input any    `json:"input"`
	}
	raw, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(raw, &req)
	f.handle(w, req.Input)
}

// flagWord flags any text input containing "FLAGME" with category "violence".
func flagWord(w http.ResponseWriter, input any) {
	var results []map[string]any
	switch in := input.(type) {
	case []any:
		for _, it := range in {
			s, _ := it.(string)
			if m, ok := it.(map[string]any); ok {
				u, _ := m["image_url"].(map[string]any)["url"].(string)
				s = u
			}
			flagged := strings.Contains(s, "FLAGME")
			results = append(results, map[string]any{"flagged": flagged, "categories": map[string]bool{"violence": flagged, "sexual": false}})
		}
	}
	if len(results) > 0 {
		if _, isImage := input.([]any)[0].(map[string]any); isImage {
			results = results[:1] // multimodal arrays return one combined result
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"id": "modr", "model": "m", "results": results})
}

func newClient(t *testing.T, h http.Handler, mut ...func(*Options)) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	opt := Options{BaseURL: srv.URL + "/v1", APIKeyEnv: "K", Model: "omni-moderation-latest", Timeout: 2 * time.Second,
		MaxInflight: 2, QueueTimeout: 50 * time.Millisecond, TextsPerRequest: 2, ImagesPerRequest: 1,
		ChunkChars: 100, ChunkOverlap: 10, CacheTTL: time.Minute, CacheMaxEntries: 100}
	for _, m := range mut {
		m(&opt)
	}
	c, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	c.getenv = func(string) string { return "test-key" }
	return c, srv
}

func TestPassAndCache(t *testing.T) {
	api := &fakeAPI{handle: flagWord}
	c, _ := newClient(t, api)
	items := []Item{{Text: "a", Cacheable: true}, {Text: "b", Cacheable: true}, {Text: "c", Cacheable: true},
		{Image: true, URL: "data:image/png;base64,AA", Digest: "d1", Cacheable: true}}
	v, err := c.Moderate(context.Background(), items)
	if err != nil || v.Flagged || v.Calls != 3 { // 2 text batches + 1 image
		t.Fatalf("v=%+v err=%v", v, err)
	}
	v, err = c.Moderate(context.Background(), items)
	if err != nil || v.CacheHits != 4 || v.Calls != 0 {
		t.Fatalf("second call should be cached: %+v %v", v, err)
	}
	// History reuse: only the new message is sent.
	v, _ = c.Moderate(context.Background(), append(items, Item{Text: "new", Cacheable: true}))
	if v.CacheHits != 4 || v.Calls != 1 {
		t.Fatalf("incremental: %+v", v)
	}
}

func TestFlaggedNotCached(t *testing.T) {
	api := &fakeAPI{handle: flagWord}
	c, _ := newClient(t, api)
	items := []Item{{Text: "fine", Cacheable: true}, {Text: "FLAGME please", Cacheable: true}}
	for i := 0; i < 2; i++ {
		v, err := c.Moderate(context.Background(), items)
		if err != nil || !v.Flagged || len(v.Categories) != 1 || v.Categories[0] != "violence" {
			t.Fatalf("run %d: %+v %v", i, v, err)
		}
	}
	if api.calls.Load() != 2 {
		t.Fatalf("flagged result must not be cached; calls=%d", api.calls.Load())
	}
}

func TestFlaggedImage(t *testing.T) {
	c, _ := newClient(t, &fakeAPI{handle: flagWord})
	v, err := c.Moderate(context.Background(), []Item{{Image: true, URL: "https://x/FLAGME.png"}})
	if err != nil || !v.Flagged {
		t.Fatalf("%+v %v", v, err)
	}
}

func TestChunkingCoversLongText(t *testing.T) {
	c, _ := newClient(t, &fakeAPI{handle: flagWord})
	long := strings.Repeat("x", 250) + "FLAGME" + strings.Repeat("y", 250)
	v, err := c.Moderate(context.Background(), []Item{{Text: long}})
	if err != nil || !v.Flagged {
		t.Fatalf("%+v %v", v, err)
	}
	chunks := Chunk(strings.Repeat("a", 250), 100, 10)
	if len(chunks) != 3 || len([]rune(chunks[0])) != 100 {
		t.Fatalf("chunks=%d", len(chunks))
	}
}

func TestUnavailable(t *testing.T) {
	cases := map[string]func(w http.ResponseWriter, input any){
		"500":        func(w http.ResponseWriter, _ any) { w.WriteHeader(500) },
		"429":        func(w http.ResponseWriter, _ any) { w.Header().Set("Retry-After", "3"); w.WriteHeader(429) },
		"bad json":   func(w http.ResponseWriter, _ any) { _, _ = w.Write([]byte("{oops")) },
		"no results": func(w http.ResponseWriter, _ any) { _, _ = w.Write([]byte(`{"results":[]}`)) },
		"no flagged": func(w http.ResponseWriter, _ any) { _, _ = w.Write([]byte(`{"results":[{"categories":{}}]}`)) },
		"count mismatch": func(w http.ResponseWriter, _ any) {
			_, _ = w.Write([]byte(`{"results":[{"flagged":false}]}`))
		},
		"slow": func(w http.ResponseWriter, _ any) {
			time.Sleep(500 * time.Millisecond)
			_, _ = w.Write([]byte(`{"results":[{"flagged":false}]}`))
		},
	}
	for name, h := range cases {
		c, _ := newClient(t, &fakeAPI{handle: h}, func(o *Options) { o.Timeout = 200 * time.Millisecond })
		_, err := c.Moderate(context.Background(), []Item{{Text: "a"}, {Text: "b"}})
		if !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s: want ErrUnavailable, got %v", name, err)
		}
		if err != nil && strings.Contains(err.Error(), "test-key") {
			t.Errorf("%s: error leaks key", name)
		}
	}
}

func TestMissingKey(t *testing.T) {
	c, _ := newClient(t, &fakeAPI{handle: flagWord})
	c.getenv = func(string) string { return "" }
	if _, err := c.Moderate(context.Background(), []Item{{Text: "a"}}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
	if c.KeyConfigured() {
		t.Fatal("key must be reported missing")
	}
}

func TestBusy(t *testing.T) {
	release := make(chan struct{})
	api := &fakeAPI{handle: func(w http.ResponseWriter, input any) {
		<-release
		flagWord(w, input)
	}}
	c, _ := newClient(t, api, func(o *Options) { o.MaxInflight = 1; o.Timeout = 5 * time.Second })
	done := make(chan error, 1)
	go func() {
		_, err := c.Moderate(context.Background(), []Item{{Text: "slow"}})
		done <- err
	}()
	for api.calls.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := c.Moderate(context.Background(), []Item{{Text: "second"}}); !errors.Is(err, ErrBusy) {
		t.Fatalf("want ErrBusy, got %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestCacheExpiryAndLRU(t *testing.T) {
	c := NewCache(2, time.Minute)
	now := time.Unix(0, 0)
	c.now = func() time.Time { return now }
	c.Put("a")
	c.Put("b")
	c.Has("a")
	c.Put("c") // evicts b (least recently used)
	if !c.Has("a") || c.Has("b") || !c.Has("c") {
		t.Fatal("LRU eviction wrong")
	}
	now = now.Add(2 * time.Minute)
	if c.Has("a") {
		t.Fatal("entry must expire")
	}
	c.Purge()
	if c.Len() != 0 {
		t.Fatal("purge")
	}
}

func TestAPIKeyFromConfigTakesPrecedence(t *testing.T) {
	var gotAuth atomic.Value
	api := &fakeAPI{handle: flagWord}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		r.Header.Set("Authorization", "Bearer test-key") // satisfy fakeAPI
		api.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	newWith := func(key, env string) *Client {
		c, err := New(Options{BaseURL: srv.URL + "/v1", APIKey: key, APIKeyEnv: "K", Model: "m", Timeout: time.Second,
			MaxInflight: 1, TextsPerRequest: 4, ImagesPerRequest: 1, ChunkChars: 100})
		if err != nil {
			t.Fatal(err)
		}
		c.getenv = func(string) string { return env }
		return c
	}
	c := newWith("from-config", "from-env")
	if _, err := c.Moderate(context.Background(), []Item{{Text: "a"}}); err != nil {
		t.Fatal(err)
	}
	if gotAuth.Load() != "Bearer from-config" || c.KeySource() != "config" {
		t.Fatalf("config key must win: auth=%v source=%s", gotAuth.Load(), c.KeySource())
	}
	c = newWith("", "from-env")
	if _, err := c.Moderate(context.Background(), []Item{{Text: "b"}}); err != nil {
		t.Fatal(err)
	}
	if gotAuth.Load() != "Bearer from-env" || c.KeySource() != "env" {
		t.Fatalf("env fallback: auth=%v source=%s", gotAuth.Load(), c.KeySource())
	}
	c = newWith("", "")
	_, err := c.Moderate(context.Background(), []Item{{Text: "c"}})
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "openai.api_key") || c.KeyConfigured() {
		t.Fatalf("missing key: %v", err)
	}
}
