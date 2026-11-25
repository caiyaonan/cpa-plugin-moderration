package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var ErrConflict = errors.New("revision conflict")

// Store persists State as JSON and serializes writers. Readers use the
// snapshot handed out by Replace/Load and never touch the store lock.
type Store struct {
	mu    sync.Mutex
	path  string
	state State
}

func Open(path string) (*Store, State, error) {
	st := &Store{path: path}
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		st.state = State{Revision: 0}
		return st, st.state, nil
	case err != nil:
		return nil, State{}, fmt.Errorf("read state file: %w", err)
	}
	var s State
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, State{}, fmt.Errorf("parse state file %s: %w", path, err)
	}
	s.Normalize()
	if err := s.Validate(); err != nil {
		return nil, State{}, err
	}
	st.state = s
	return st, s, nil
}

func (st *Store) Current() State {
	st.mu.Lock()
	defer st.mu.Unlock()
	return clone(st.state)
}

// Update applies fn to a copy of the current state when expectedRevision
// matches, validates the result, writes it atomically and returns it.
func (st *Store) Update(expectedRevision int64, fn func(*State) error) (State, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if expectedRevision >= 0 && expectedRevision != st.state.Revision {
		return State{}, fmt.Errorf("%w: expected %d, current %d", ErrConflict, expectedRevision, st.state.Revision)
	}
	next := clone(st.state)
	if err := fn(&next); err != nil {
		return State{}, err
	}
	next.Normalize()
	if err := next.Validate(); err != nil {
		return State{}, err
	}
	next.Revision = st.state.Revision + 1
	if err := writeAtomic(st.path, next); err != nil {
		return State{}, err
	}
	st.state = next
	return clone(next), nil
}

func writeAtomic(path string, s State) error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".cpa-moderation-state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp state file: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("write state file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync state file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("replace state file: %w", err)
	}
	return nil
}

func clone(s State) State {
	raw, _ := json.Marshal(s)
	var out State
	_ = json.Unmarshal(raw, &out)
	return out
}
