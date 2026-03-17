package fsutil

import (
	"os"
	"sync"
	"sync/atomic"
)

// HandleTracker maps uint64 handle IDs to open *os.File descriptors.
type HandleTracker struct {
	mu      sync.RWMutex
	handles map[uint64]*os.File
	next    atomic.Uint64
}

func NewHandleTracker() *HandleTracker {
	return &HandleTracker{handles: make(map[uint64]*os.File)}
}

func (t *HandleTracker) Add(f *os.File) uint64 {
	id := t.next.Add(1)
	t.mu.Lock()
	t.handles[id] = f
	t.mu.Unlock()
	return id
}

func (t *HandleTracker) Get(id uint64) (*os.File, bool) {
	t.mu.RLock()
	f, ok := t.handles[id]
	t.mu.RUnlock()
	return f, ok
}

// Release closes the file and removes it from the tracker.
func (t *HandleTracker) Release(id uint64) error {
	t.mu.Lock()
	f, ok := t.handles[id]
	if ok {
		delete(t.handles, id)
	}
	t.mu.Unlock()
	if !ok {
		return nil
	}
	return f.Close()
}
