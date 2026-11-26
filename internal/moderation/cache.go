package moderation

import (
	"container/list"
	"sync"
	"time"
)

// Cache remembers inputs that passed moderation, keyed by content hash, with
// their category scores so stricter per-rule thresholds still apply to cache
// hits. It never stores content, flagged results or errors.
type Cache struct {
	mu    sync.Mutex
	max   int
	ttl   time.Duration
	ll    *list.List
	items map[string]*list.Element
	now   func() time.Time
}

type entry struct {
	key     string
	expires time.Time
	scores  map[string]float64
}

func NewCache(max int, ttl time.Duration) *Cache {
	return &Cache{max: max, ttl: ttl, ll: list.New(), items: map[string]*list.Element{}, now: time.Now}
}

func (c *Cache) enabled() bool { return c != nil && c.max > 0 && c.ttl > 0 }

func (c *Cache) Has(key string) bool {
	_, ok := c.Get(key)
	return ok
}

// Get returns the cached category scores of a passed input.
func (c *Cache) Get(key string) (map[string]float64, bool) {
	if !c.enabled() {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	e := el.Value.(*entry)
	if c.now().After(e.expires) {
		c.ll.Remove(el)
		delete(c.items, key)
		return nil, false
	}
	c.ll.MoveToFront(el)
	return e.scores, true
}

func (c *Cache) Put(key string) { c.PutScores(key, nil) }

func (c *Cache) PutScores(key string, scores map[string]float64) {
	if !c.enabled() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	exp := c.now().Add(c.ttl)
	if el, ok := c.items[key]; ok {
		e := el.Value.(*entry)
		e.expires, e.scores = exp, scores
		c.ll.MoveToFront(el)
		return
	}
	c.items[key] = c.ll.PushFront(&entry{key: key, expires: exp, scores: scores})
	for c.ll.Len() > c.max {
		last := c.ll.Back()
		c.ll.Remove(last)
		delete(c.items, last.Value.(*entry).key)
	}
}

func (c *Cache) Purge() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ll.Init()
	c.items = map[string]*list.Element{}
}

func (c *Cache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}
