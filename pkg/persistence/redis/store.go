// Package redis provides a Redis-backed implementation of persistence.Store.
//
// Scan jobs are JSON-serialized and stored as keyspace entries with a TTL,
// so two desirable properties fall out for free:
//
//  1. Restart survival: a pod crash/rollout no longer loses in-flight or
//     recently-finished scans (issue #15). Subsequent Harbor poll requests
//     hit Redis and find the same job state.
//  2. Bounded retention: every write resets the TTL, so a job lingers in
//     Redis at most `retention` after its last update. No janitor needed,
//     no unbounded growth (issue #17 absorbed for this backend).
//
// Use NewStore with an externally-provided *redis.Client. The package does
// not own connection lifecycle — callers Close() the client themselves.
package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/goharbor/harbor-scanner-kubescape/pkg/harbor"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/persistence"
	"github.com/redis/go-redis/v9"
)

const (
	// DefaultKeyPrefix namespaces scan-job keys so multiple components can
	// safely share a single Redis instance without colliding.
	DefaultKeyPrefix = "harbor-scanner-kubescape:job:"

	// DefaultTTL is the time a scan job lives in Redis after its last
	// write. Generous enough that an in-flight scan won't expire mid-poll
	// (kubevuln poll budget is 10 minutes), and that Harbor can collect
	// the result well after the scan finishes.
	DefaultTTL = 1 * time.Hour
)

// Store implements persistence.Store on top of Redis.
type Store struct {
	client    *redis.Client
	ttl       time.Duration
	keyPrefix string
}

// Option configures a Store.
type Option func(*Store)

// WithTTL overrides the per-key TTL. A non-positive value disables expiry
// (keys live until manually deleted) — only useful for short-lived tests.
func WithTTL(d time.Duration) Option {
	return func(s *Store) { s.ttl = d }
}

// WithKeyPrefix overrides the namespace used for scan job keys.
func WithKeyPrefix(p string) Option {
	return func(s *Store) { s.keyPrefix = p }
}

// NewStore constructs a Redis-backed Store wrapping the given client.
func NewStore(client *redis.Client, opts ...Option) *Store {
	s := &Store{
		client:    client,
		ttl:       DefaultTTL,
		keyPrefix: DefaultKeyPrefix,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Ping verifies Redis reachability. Used by the readiness probe so the pod
// is marked NotReady when its store backend is offline.
func (s *Store) Ping(ctx context.Context) error {
	return s.client.Ping(ctx).Err()
}

func (s *Store) key(id string) string {
	return s.keyPrefix + id
}

func (s *Store) Create(ctx context.Context, job persistence.ScanJob) error {
	return s.save(ctx, &job)
}

func (s *Store) Get(ctx context.Context, id string) (*persistence.ScanJob, error) {
	b, err := s.client.Get(ctx, s.key(id)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// Distinguish "expired/never existed" from a real Redis
			// failure. Mirrors the memory-store contract: nil, nil means
			// not found.
			return nil, nil
		}
		return nil, fmt.Errorf("redis GET %s: %w", id, err)
	}
	var job persistence.ScanJob
	if err := json.Unmarshal(b, &job); err != nil {
		return nil, fmt.Errorf("unmarshal scan job %s: %w", id, err)
	}
	return &job, nil
}

func (s *Store) UpdateStatus(ctx context.Context, id string, status persistence.ScanJobStatus, errMsg ...string) error {
	job, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if job == nil {
		return fmt.Errorf("scan job not found: %s", id)
	}
	job.Status = status
	if len(errMsg) > 0 {
		job.Error = errMsg[0]
	}
	return s.save(ctx, job)
}

func (s *Store) UpdateReport(ctx context.Context, id string, report harbor.ScanReport) error {
	job, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if job == nil {
		return fmt.Errorf("scan job not found: %s", id)
	}
	job.Report = report
	return s.save(ctx, job)
}

func (s *Store) save(ctx context.Context, job *persistence.ScanJob) error {
	b, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("marshal scan job %s: %w", job.ID, err)
	}
	if err := s.client.Set(ctx, s.key(job.ID), b, s.ttl).Err(); err != nil {
		return fmt.Errorf("redis SET %s: %w", job.ID, err)
	}
	return nil
}
