package memory

import (
	"context"
	"fmt"
	"sync"

	"github.com/goharbor/harbor-scanner-kubescape/pkg/harbor"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/persistence"
)

// Store is an in-memory implementation of persistence.Store.
//
// Single-instance only. Scan state is not shared across pods, so any
// multi-replica deployment will return 404 on Harbor poll requests that land
// on a replica different from the one that accepted the scan. The Helm chart
// fails installation when replicaCount > 1 unless explicitly overridden — see
// https://github.com/goharbor/harbor-scanner-kubescape/issues/2 for the
// shared-backend (Redis/etc.) plan.
type Store struct {
	mu   sync.RWMutex
	jobs map[string]*persistence.ScanJob
}

func NewStore() *Store {
	return &Store{
		jobs: make(map[string]*persistence.ScanJob),
	}
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
