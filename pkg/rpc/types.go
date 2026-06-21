package rpc

type RuntimeContext struct {
	TenantHash          []byte
	DomainHash          []byte
	RequiredLifecycle   uint64
	ProhibitedSafety    uint64
	AllowedUseClasses   uint64
	ProhibitedUseBlocks uint64
}

type MemoryCandidate struct {
	MemoryId    []byte
	MemoryHash  []byte
	MemoryFlags uint64
}

type EvaluateRequest struct {
	SessionId  string
	AgentId    string
	Context    *RuntimeContext
	Candidates []*MemoryCandidate
}

type MemoryDecisionLeaf struct {
	MemoryId     []byte
	DecisionCode uint32
	ReasonCode   string
	Injected     bool
}

type EvaluateResponse struct {
	SessionId              string
	MerkleRoot             []byte
	Decisions              []*MemoryDecisionLeaf
	RuntimeSnapshotVersion uint64
}

type RevocationRequest struct {
	MemoryId   []byte
	EventType  uint32
	ReasonCode uint32
	OperatorId string
	Source     string
}

type RevocationResponse struct {
	EventId                []byte
	UpdatedSnapshotVersion uint64
	UpdatedSnapshotHash    []byte
}
