// Package memory provides an in-process implementation of persistence.Store.
//
// Single-instance only: state is not shared across pods, and any restart
// loses all state (issue #15). For a durable production backend, use a
// shared store (e.g. Redis). This implementation is appropriate for local
// development and the single-replica chart deployment.
//
// The store enforces bounded retention of terminal jobs (Finished/Failed)
// via a janitor goroutine — once a job has been in a terminal state for
// longer than the configured retention window, it is evicted. Without this
// the map would grow unboundedly with scan volume (issue #17). Non-terminal
// jobs are never evicted; the janitor leaves them alone until they reach a
// terminal state.
package memory

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/goharbor/harbor-scanner-kubescape/pkg/harbor"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/persistence"
)

const (
	// DefaultRetention is the time a Finished or Failed job is kept before
	// the janitor evicts it. Long enough for Harbor to complete its poll
	// loop after the scan finishes, short enough to bound memory.
	DefaultRetention = 1 * time.Hour
	// DefaultCleanupInterval is how often the janitor runs.
	DefaultCleanupInterval = 5 * time.Minute
)

// Store is an in-memory persistence.Store. See package doc for caveats.
type Store struct {
	mu              sync.RWMutex
	jobs            map[string]*persistence.ScanJob
	retention       time.Duration
	cleanupInterval time.Duration
	now             func() time.Time
	stop            chan struct{}
	stopOnce        sync.Once
	stopped         chan struct{}
}

// Option configures a Store.
type Option func(*Store)

// WithRetention overrides the terminal-job retention window. A zero or
// negative value disables eviction (jobs are kept forever — only useful for
// short-lived tests, never for production).
func WithRetention(d time.Duration) Option {
	return func(s *Store) { s.retention = d }
}

// WithCleanupInterval overrides how often the janitor runs.
func WithCleanupInterval(d time.Duration) Option {
	return func(s *Store) { s.cleanupInterval = d }
}

// WithNow overrides the clock. Tests inject a fixed time.
func WithNow(f func() time.Time) Option {
	return func(s *Store) { s.now = f }
}

// NewStore creates a Store and starts its janitor goroutine. Call Close()
// on shutdown to stop the janitor cleanly. Safe defaults are applied when
// no options are provided.
func NewStore(opts ...Option) *Store {
	s := &Store{
		jobs:            make(map[string]*persistence.ScanJob),
		retention:       DefaultRetention,
		cleanupInterval: DefaultCleanupInterval,
		now:             time.Now,
		stop:            make(chan struct{}),
		stopped:         make(chan struct{}),
	}
	for _, opt := range opts {
		opt(s)
	}

	go s.janitor()
	return s
}

// Close stops the janitor goroutine. Safe to call multiple times.
func (s *Store) Close() {
	s.stopOnce.Do(func() {
		close(s.stop)
		<-s.stopped
	})
}

func (s *Store) Create(_ context.Context, job persistence.ScanJob) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[job.ID] = &job
	return nil
}

func (s *Store) Get(_ context.Context, id string) (*persistence.ScanJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	job, ok := s.jobs[id]
	if !ok {
		return nil, nil
	}
	// Return a copy to prevent data races from concurrent access.
	copy := *job
	return &copy, nil
}

func (s *Store) UpdateStatus(_ context.Context, id string, status persistence.ScanJobStatus, errMsg ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[id]
	if !ok {
		return fmt.Errorf("scan job not found: %s", id)
	}
	job.Status = status
	if len(errMsg) > 0 {
		job.Error = errMsg[0]
	}
	if status == persistence.Finished || status == persistence.Failed {
		job.TerminalAt = s.now()
	}
	return nil
}

func (s *Store) UpdateReport(_ context.Context, id string, report harbor.ScanReport) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[id]
	if !ok {
		return fmt.Errorf("scan job not found: %s", id)
	}
	job.Report = report
	return nil
}

// Len returns the current number of jobs in the store. Useful for tests
// asserting eviction; not part of any public interface.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.jobs)
}

// Cleanup runs one eviction pass, deleting terminal jobs whose TerminalAt
// is older than retention. Returns the number of jobs evicted. Exported so
// tests can drive cleanup deterministically without waiting for the ticker.
func (s *Store) Cleanup() int {
	if s.retention <= 0 {
		return 0
	}
	cutoff := s.now().Add(-s.retention)

	s.mu.Lock()
	defer s.mu.Unlock()

	evicted := 0
	for id, job := range s.jobs {
		if job.TerminalAt.IsZero() {
			continue
		}
		if job.TerminalAt.Before(cutoff) {
			delete(s.jobs, id)
			evicted++
		}
	}
	return evicted
}

func (s *Store) janitor() {
	defer close(s.stopped)
	if s.retention <= 0 || s.cleanupInterval <= 0 {
		// Eviction disabled. Wait for Close so the channel still closes
		// cleanly, but do nothing in the meantime.
		<-s.stop
		return
	}

	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			if n := s.Cleanup(); n > 0 {
				slog.Debug("Memory store eviction", slog.Int("evicted", n), slog.Int("remaining", s.Len()))
			}
		}
	}
}
