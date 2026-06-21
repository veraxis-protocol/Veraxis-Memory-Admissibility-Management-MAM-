package axis

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"veraxis-memory-admissibility/pkg/quarantine"
)

type MemoryTransformationJob struct {
	MemoryID       [16]byte
	AnchorVector   StructuralVector
	MutatedVector  StructuralVector
	OperatorID     string
	SourcePipeline string
	PolicySnapshot [32]byte
}

type WorkerStats struct {
	Processed   uint64
	Quarantined uint64
	Dropped     uint64
	Errors      uint64
}

type DriftMonitorCoordinator struct {
	Ledger     *quarantine.FileLedger
	Monitor    *quarantine.RuntimeMonitor
	Dimensions InvariantDimensions
	Threshold  float64
	JobQueue   chan MemoryTransformationJob

	processed   atomic.Uint64
	quarantined atomic.Uint64
	dropped     atomic.Uint64
	errors      atomic.Uint64

	wg sync.WaitGroup
}

func NewDriftMonitorCoordinator(
	ledger *quarantine.FileLedger,
	monitor *quarantine.RuntimeMonitor,
	dims InvariantDimensions,
	threshold float64,
	queueBuffer int,
) *DriftMonitorCoordinator {
	if queueBuffer <= 0 {
		queueBuffer = 1
	}
	return &DriftMonitorCoordinator{
		Ledger:     ledger,
		Monitor:    monitor,
		Dimensions: dims,
		Threshold:  threshold,
		JobQueue:   make(chan MemoryTransformationJob, queueBuffer),
	}
}

func (c *DriftMonitorCoordinator) Start(ctx context.Context, workerCount int) {
	if workerCount <= 0 {
		workerCount = 1
	}
	for i := 0; i < workerCount; i++ {
		c.wg.Add(1)
		go c.workerLoop(ctx)
	}
}

func (c *DriftMonitorCoordinator) Wait() {
	c.wg.Wait()
}

func (c *DriftMonitorCoordinator) StopAccepting() {
	close(c.JobQueue)
}

func (c *DriftMonitorCoordinator) SubmitNonBlocking(job MemoryTransformationJob) bool {
	select {
	case c.JobQueue <- job:
		return true
	default:
		c.dropped.Add(1)
		return false
	}
}

func (c *DriftMonitorCoordinator) Stats() WorkerStats {
	return WorkerStats{
		Processed:   c.processed.Load(),
		Quarantined: c.quarantined.Load(),
		Dropped:     c.dropped.Load(),
		Errors:      c.errors.Load(),
	}
}

func (c *DriftMonitorCoordinator) workerLoop(ctx context.Context) {
	defer c.wg.Done()

	for {
		select {
		case job, ok := <-c.JobQueue:
			if !ok {
				return
			}
			c.processJob(job)
		case <-ctx.Done():
			return
		}
	}
}

func (c *DriftMonitorCoordinator) ProcessJobForTest(job MemoryTransformationJob) error {
	return c.processJob(job)
}

func (c *DriftMonitorCoordinator) processJob(job MemoryTransformationJob) error {
	c.processed.Add(1)

	res := EvaluateDrift(job.AnchorVector, job.MutatedVector, c.Dimensions, c.Threshold)
	if res.AxisPreserved {
		return nil
	}

	event, err := c.eventForDrift(job, res)
	if err != nil {
		c.errors.Add(1)
		return err
	}

	if c.Ledger != nil {
		if err := c.Ledger.AppendEvent(event); err != nil {
			c.errors.Add(1)
			return err
		}
	}

	if c.Monitor != nil {
		c.Monitor.AppendEvent(event)
		c.Monitor.CompileAndSwap(time.Now().UTC())
	}

	c.quarantined.Add(1)
	return nil
}

func (c *DriftMonitorCoordinator) eventForDrift(job MemoryTransformationJob, res AxisCheckResult) (quarantine.RevocationEvent, error) {
	eventID, err := newEventID()
	if err != nil {
		return quarantine.RevocationEvent{}, err
	}

	qReason, eType := MapDriftToQuarantine(res.DriftType)

	return quarantine.RevocationEvent{
		EventID:    eventID,
		MemoryID:   job.MemoryID,
		EventType:  eType,
		Reason:     qReason,
		OperatorID: job.OperatorID,
		Source:     job.SourcePipeline,
		CreatedAt:  time.Now().UTC(),
		PolicyHash: job.PolicySnapshot,
		NewState:   "quarantined",
	}, nil
}

func MapDriftToQuarantine(driftType string) (quarantine.QuarantineReason, quarantine.EventType) {
	switch driftType {
	case DriftTypeTemporality:
		return quarantine.ReasonPoisoningSuspected, quarantine.EventPoisoningSuspected
	case DriftTypeEpistemic:
		return quarantine.ReasonPoisoningSuspected, quarantine.EventPoisoningSuspected
	case DriftTypeScope:
		return quarantine.ReasonCrossSessionLeak, quarantine.EventCrossSessionLeak
	case DriftTypeTrust:
		return quarantine.ReasonRetroactiveRevocation, quarantine.EventQuarantineMemory
	case DriftTypeMandate:
		return quarantine.ReasonPromptInjectionDetected, quarantine.EventPromptInjectionDetected
	default:
		return quarantine.ReasonPoisoningSuspected, quarantine.EventQuarantineMemory
	}
}

func newEventID() ([16]byte, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return id, errors.New("AXIS_EVENT_ID_FAILURE: crypto random source unavailable")
	}
	return id, nil
}
