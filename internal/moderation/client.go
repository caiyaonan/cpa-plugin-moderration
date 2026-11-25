// Package moderation calls the OpenAI moderation endpoint with bounded
// concurrency, chunking, batching and a pass-result cache.
package moderation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

var (
	// ErrUnavailable covers missing key, network errors, timeouts, non-2xx and
	// malformed responses. It is never a content verdict.
	ErrUnavailable = errors.New("moderation service unavailable")
	// ErrBusy means the local concurrency limit and queue were exhausted.
	ErrBusy = errors.New("moderation concurrency limit reached")
)

type Options struct {
	BaseURL          string
	APIKeyEnv        string
	Model            string
	ProxyURL         string
	Timeout          time.Duration
	MaxInflight      int
	QueueTimeout     time.Duration
	TextsPerRequest  int
	ImagesPerRequest int
	ChunkChars       int
	ChunkOverlap     int
	CacheTTL         time.Duration
	CacheMaxEntries  int
}

type Client struct {
	opt   Options
	http  *http.Client
	sem   chan struct{}
	cache *Cache
	// getenv is replaceable in tests.
	getenv func(string) string
}

func New(opt Options) (*Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = opt.MaxInflight
	if opt.ProxyURL != "" {
		u, err := url.Parse(opt.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy_url: %w", err)
		}
		transport.Proxy = http.ProxyURL(u)
	}
	return &Client{
		opt:    opt,
		http:   &http.Client{Timeout: opt.Timeout, Transport: transport},
		sem:    make(chan struct{}, opt.MaxInflight),
		cache:  NewCache(opt.CacheMaxEntries, opt.CacheTTL),
		getenv: os.Getenv,
	}, nil
}

func (c *Client) Model() string { return c.opt.Model }

func (c *Client) KeyConfigured() bool { return strings.TrimSpace(c.getenv(c.opt.APIKeyEnv)) != "" }

// PurgeCache drops cached verdicts, e.g. after a policy change.
func (c *Client) PurgeCache() { c.cache.Purge() }

type Item struct {
	Image     bool
	Text      string
	URL       string
	Cacheable bool   // false for remote URLs whose content may change
	Digest    string // content digest for images
}

type Verdict struct {
	Flagged    bool
	Categories []string // union of flagged categories, sorted
	CacheHits  int
	Calls      int
}

// Moderate checks all items. Any flagged item flags the verdict.
func (c *Client) Moderate(ctx context.Context, items []Item) (Verdict, error) {
	var v Verdict
	if len(items) == 0 {
		return v, nil
	}
	key := strings.TrimSpace(c.getenv(c.opt.APIKeyEnv))
	if key == "" {
		return v, fmt.Errorf("%w: environment variable %s is not set", ErrUnavailable, c.opt.APIKeyEnv)
	}

	var texts, images []pending
	for _, it := range items {
		if it.Image {
			p := pending{image: it.URL}
			if it.Cacheable {
				p.cacheKey = c.cacheKey("image", it.Digest)
			}
			images = append(images, p)
			continue
		}
		for _, chunk := range Chunk(it.Text, c.opt.ChunkChars, c.opt.ChunkOverlap) {
			texts = append(texts, pending{text: chunk, cacheKey: c.cacheKey("text", chunk)})
		}
	}
	texts = c.dropCached(texts, &v)
	images = c.dropCached(images, &v)
	if len(texts) == 0 && len(images) == 0 {
		return v, nil
	}

	if err := c.acquire(ctx); err != nil {
		return v, err
	}
	defer func() { <-c.sem }()

	cats := map[string]bool{}
	run := func(batch []pending, input any, perItem bool) error {
		results, err := c.call(ctx, key, input)
		v.Calls++
		if err != nil {
			return err
		}
		if perItem && len(results) != len(batch) {
			return fmt.Errorf("%w: expected %d results, got %d", ErrUnavailable, len(batch), len(results))
		}
		anyFlagged := false
		for _, r := range results {
			if !r.Flagged {
				continue
			}
			anyFlagged = true
			hitAny := false
			for name, hit := range r.Categories {
				if hit {
					cats[name] = true
					hitAny = true
				}
			}
			if !hitAny {
				cats["unspecified"] = true
			}
		}
		for i, p := range batch {
			flagged := anyFlagged
			if perItem {
				flagged = results[i].Flagged
			}
			if !flagged && p.cacheKey != "" {
				c.cache.Put(p.cacheKey)
			}
		}
		if anyFlagged {
			v.Flagged = true
		}
		return nil
	}

	for start := 0; start < len(texts); start += c.opt.TextsPerRequest {
		end := min(start+c.opt.TextsPerRequest, len(texts))
		batch := texts[start:end]
		input := make([]string, len(batch))
		for i, p := range batch {
			input[i] = p.text
		}
		if err := run(batch, input, true); err != nil {
			return v, err
		}
		if v.Flagged {
			v.Categories = sortedKeys(cats)
			return v, nil // already decided; skip remaining calls
		}
	}
	for start := 0; start < len(images); start += c.opt.ImagesPerRequest {
		end := min(start+c.opt.ImagesPerRequest, len(images))
		batch := images[start:end]
		input := make([]map[string]any, len(batch))
		for i, p := range batch {
			input[i] = map[string]any{"type": "image_url", "image_url": map[string]string{"url": p.image}}
		}
		if err := run(batch, input, false); err != nil {
			return v, err
		}
		if v.Flagged {
			break
		}
	}
	v.Categories = sortedKeys(cats)
	return v, nil
}

type pending struct {
	text     string
	image    string
	cacheKey string
}

func (c *Client) dropCached(in []pending, v *Verdict) []pending {
	out := in[:0]
	for _, p := range in {
		if p.cacheKey != "" && c.cache.Has(p.cacheKey) {
			v.CacheHits++
			continue
		}
		out = append(out, p)
	}
	return out
}

func (c *Client) cacheKey(kind, content string) string {
	h := sha256.New()
	h.Write([]byte(c.opt.Model))
	h.Write([]byte{0})
	h.Write([]byte(kind))
	h.Write([]byte{0})
	h.Write([]byte(content))
	return hex.EncodeToString(h.Sum(nil))
}

func (c *Client) acquire(ctx context.Context) error {
	select {
	case c.sem <- struct{}{}:
		return nil
	default:
	}
	if c.opt.QueueTimeout <= 0 {
		return ErrBusy
	}
	t := time.NewTimer(c.opt.QueueTimeout)
	defer t.Stop()
	select {
	case c.sem <- struct{}{}:
		return nil
	case <-t.C:
		return ErrBusy
	case <-ctx.Done():
		return fmt.Errorf("%w: %v", ErrUnavailable, ctx.Err())
	}
}

type apiResult struct {
	Flagged    *bool           `json:"flagged"`
	Categories map[string]bool `json:"categories"`
}

type result struct {
	Flagged    bool
	Categories map[string]bool
}

func (c *Client) call(ctx context.Context, key string, input any) ([]result, error) {
	payload, err := json.Marshal(map[string]any{"model": c.opt.Model, "input": input})
	if err != nil {
		return nil, fmt.Errorf("%w: encode request: %v", ErrUnavailable, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.opt.BaseURL, "/")+"/moderations", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %v", ErrUnavailable, err)
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, sanitizeNetErr(err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: read response: %v", ErrUnavailable, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		extra := ""
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			extra = ", retry-after " + ra
		}
		return nil, fmt.Errorf("%w: upstream status %d%s", ErrUnavailable, resp.StatusCode, extra)
	}
	var parsed struct {
		Results []apiResult `json:"results"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("%w: malformed response", ErrUnavailable)
	}
	if len(parsed.Results) == 0 {
		return nil, fmt.Errorf("%w: response has no results", ErrUnavailable)
	}
	out := make([]result, len(parsed.Results))
	for i, r := range parsed.Results {
		if r.Flagged == nil {
			return nil, fmt.Errorf("%w: result %d has no flagged field", ErrUnavailable, i)
		}
		out[i] = result{Flagged: *r.Flagged, Categories: r.Categories}
	}
	return out, nil
}

func sanitizeNetErr(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		if ue.Timeout() {
			return "timeout"
		}
		return ue.Op + " failed: " + rootCause(ue.Err)
	}
	return rootCause(err)
}

func rootCause(err error) string {
	for {
		next := errors.Unwrap(err)
		if next == nil {
			return err.Error()
		}
		err = next
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Chunk splits s into pieces of at most size runes with the given overlap so
// that context spanning a boundary is still seen by at least one chunk.
func Chunk(s string, size, overlap int) []string {
	r := []rune(s)
	if size <= 0 || len(r) <= size {
		return []string{s}
	}
	step := size - overlap
	if step <= 0 {
		step = size
	}
	var out []string
	for start := 0; start < len(r); start += step {
		end := min(start+size, len(r))
		out = append(out, string(r[start:end]))
		if end == len(r) {
			break
		}
	}
	return out
}
