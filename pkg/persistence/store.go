package persistence

import (
	"context"
	"time"

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
//
// TerminalAt is set when Status transitions to Finished or Failed. Stores
// that retain finished/failed jobs for a bounded window (e.g. the in-memory
// store) use this timestamp to decide when to evict an entry. A zero
// TerminalAt means the job has not yet reached a terminal state.
type ScanJob struct {
	ID         string
	Request    harbor.ScanRequest
	Status     ScanJobStatus
	Report     harbor.ScanReport
	Error      string
	TerminalAt time.Time
}

// Store provides persistence for scan jobs.
type Store interface {
	Create(ctx context.Context, job ScanJob) error
	Get(ctx context.Context, id string) (*ScanJob, error)
	UpdateStatus(ctx context.Context, id string, status ScanJobStatus, errMsg ...string) error
	UpdateReport(ctx context.Context, id string, report harbor.ScanReport) error

	// SetFinished publishes the scan report and the Finished status as a
	// single store operation. The previous two-call pattern
	// (UpdateReport followed by UpdateStatus) had a window where a crash
	// or transient backend failure between the two writes left a stored
	// report behind a stale Pending status — Harbor would keep getting
	// 302s for a scan that already had a result waiting. See issue #31.
	SetFinished(ctx context.Context, id string, report harbor.ScanReport) error
}
