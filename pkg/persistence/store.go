package persistence

import (
	"context"

	"github.com/goharbor/harbor-scanner-kubescape/pkg/harbor"
)

// ScanJobStatus represents the state of a scan job.
type ScanJobStatus int

const (
	Queued ScanJobStatus = iota
	Pending
	Finished
	Failed
)

func (s ScanJobStatus) String() string {
	switch s {
	case Queued:
		return "Queued"
	case Pending:
		return "Pending"
	case Finished:
		return "Finished"
	case Failed:
		return "Failed"
	default:
		return "Unknown"
	}
}

// ScanJob represents a scan job with its status and result.
type ScanJob struct {
	ID      string
	Request harbor.ScanRequest
	Status  ScanJobStatus
	Report  harbor.ScanReport
	Error   string
}

// Store provides persistence for scan jobs.
type Store interface {
	Create(ctx context.Context, job ScanJob) error
	Get(ctx context.Context, id string) (*ScanJob, error)
	UpdateStatus(ctx context.Context, id string, status ScanJobStatus, errMsg ...string) error
	UpdateReport(ctx context.Context, id string, report harbor.ScanReport) error
}
