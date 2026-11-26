package plugin

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"cpa-moderation/internal/engine"
)

// Event is the audit record of one moderated request. It never contains
// request content, matched words, scores, raw keys or authorization headers.
type Event struct {
	Time             time.Time          `json:"time"`
	RequestID        string             `json:"request_id"`
	Scope            string             `json:"scope"` // first 12 hex chars of the caller scope hash
	Model            string             `json:"model"`
	RequestedModel   string             `json:"requested_model"`
	Format           string             `json:"format"`
	Path             string             `json:"path,omitempty"`
	Stream           bool               `json:"stream"`
	Outcome          string             `json:"outcome"`
	Status           int                `json:"status,omitempty"`
	Code             string             `json:"code,omitempty"`
	Rules            []string           `json:"rules,omitempty"`
	Reason           string             `json:"reason,omitempty"`
	Categories       []string           `json:"categories,omitempty"`
	LoggedCategories []string           `json:"logged_categories,omitempty"`
	Scores           map[string]float64 `json:"scores,omitempty"`
	Texts            int                `json:"texts"`
	Images           int                `json:"images"`
	CacheHits        int                `json:"cache_hits"`
	Calls            int                `json:"calls"`
	DurationMS       float64            `json:"duration_ms"`
	Notes            []string           `json:"notes,omitempty"`
	Detail           string             `json:"detail,omitempty"`
}

func (a *App) recordEvent(req InterceptRequest, d engine.Decision) {
	scope := req.CallerScope
	if scope == "" {
		scope = metaString(req.Metadata, "caller_scope")
	}
	if len(scope) > 12 {
		scope = scope[:12]
	}
	a.events.add(Event{
		Time:             time.Now().UTC(),
		RequestID:        req.RequestID,
		Scope:            scope,
		Model:            req.Model,
		RequestedModel:   req.RequestedModel,
		Format:           req.SourceFormat,
		Path:             metaString(req.Metadata, "request_path"),
		Stream:           req.Stream,
		Outcome:          string(d.Outcome),
		Status:           d.Status,
		Code:             d.Code,
		Rules:            d.Rules,
		Reason:           d.Reason,
		Categories:       d.Categories,
		LoggedCategories: d.LoggedCategories,
		Scores:           d.Scores,
		Texts:            d.Texts,
		Images:           d.Images,
		CacheHits:        d.CacheHits,
		Calls:            d.Calls,
		DurationMS:       float64(d.Duration.Microseconds()) / 1000,
		Notes:            d.Notes,
		Detail:           d.Detail,
	})
}

type eventLog struct {
	mu      sync.Mutex
	ring    []Event
	next    int
	full    bool
	path    string
	maxSize int64
	file    *os.File
	size    int64
}

func newEventLog(capacity int, path string, maxMB int) *eventLog {
	l := &eventLog{}
	l.reconfigure(capacity, path, maxMB)
	return l
}

func (l *eventLog) reconfigure(capacity int, path string, maxMB int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if capacity <= 0 {
		capacity = 1000
	}
	if capacity != len(l.ring) {
		old := l.snapshotLocked(0)
		l.ring = make([]Event, capacity)
		l.next, l.full = 0, false
		for i := len(old) - 1; i >= 0; i-- { // old is newest-first
			l.pushLocked(old[i])
		}
	}
	if path != l.path {
		l.closeFileLocked()
		l.path = path
	}
	l.maxSize = int64(maxMB) << 20
}

func (l *eventLog) add(e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pushLocked(e)
	l.writeLocked(e)
}

func (l *eventLog) pushLocked(e Event) {
	if len(l.ring) == 0 {
		return
	}
	l.ring[l.next] = e
	l.next = (l.next + 1) % len(l.ring)
	if l.next == 0 {
		l.full = true
	}
}

// snapshot returns up to limit events, newest first (limit <= 0 = all).
func (l *eventLog) snapshot(limit int) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.snapshotLocked(limit)
}

func (l *eventLog) snapshotLocked(limit int) []Event {
	n := l.next
	if l.full {
		n = len(l.ring)
	}
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]Event, 0, limit)
	for i := 0; i < limit; i++ {
		idx := (l.next - 1 - i + len(l.ring)) % len(l.ring)
		out = append(out, l.ring[idx])
	}
	return out
}

func (l *eventLog) writeLocked(e Event) {
	if l.path == "" {
		return
	}
	if l.file == nil {
		if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
			return
		}
		f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return
		}
		if st, err := f.Stat(); err == nil {
			l.size = st.Size()
		}
		l.file = f
	}
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	line = append(line, '\n')
	if l.maxSize > 0 && l.size+int64(len(line)) > l.maxSize {
		l.closeFileLocked()
		_ = os.Rename(l.path, l.path+".1") // keep one rotated file
		l.writeLocked(e)
		return
	}
	n, _ := l.file.Write(line)
	l.size += int64(n)
}

func (l *eventLog) closeFileLocked() {
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
		l.size = 0
	}
}

func (l *eventLog) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closeFileLocked()
}

func (e Event) String() string { return fmt.Sprintf("%s %s %s", e.RequestID, e.Outcome, e.Reason) }
