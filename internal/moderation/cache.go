package moderation

import (
	"container/list"
	"sync"
	"time"
)

// Cache remembers keys of inputs that passed moderation. It stores only
// hashes, never content, and never caches flagged results or errors.
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
}

func NewCache(max int, ttl time.Duration) *Cache {
	return &Cache{max: max, ttl: ttl, ll: list.New(), items: map[string]*list.Element{}, now: time.Now}
}

func (c *Cache) enabled() bool { return c != nil && c.max > 0 && c.ttl > 0 }

func (c *Cache) Has(key string) bool {
	if !c.enabled() {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return false
	}
	if c.now().After(el.Value.(*entry).expires) {
		c.ll.Remove(el)
		delete(c.items, key)
		return false
	}
	c.ll.MoveToFront(el)
	return true
}

func (c *Cache) Put(key string) {
	if !c.enabled() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	exp := c.now().Add(c.ttl)
	if el, ok := c.items[key]; ok {
		el.Value.(*entry).expires = exp
		c.ll.MoveToFront(el)
		return
	}
	c.items[key] = c.ll.PushFront(&entry{key: key, expires: exp})
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
