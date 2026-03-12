package memory

import (
	"context"
	"fmt"
	"sync"

	"github.com/goharbor/harbor-scanner-kubescape/pkg/harbor"
	"github.com/goharbor/harbor-scanner-kubescape/pkg/persistence"
)

// Store is an in-memory implementation of persistence.Store.
// Suitable for single-instance deployments. For HA, replace with Redis.
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
