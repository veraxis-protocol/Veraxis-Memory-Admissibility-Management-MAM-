export declare const DECISION_USE = 0;
export declare const DECISION_QUALIFY = 1;
export declare const DECISION_REFRESH = 2;
export declare const DECISION_ESCALATE = 3;
export declare const DECISION_REFUSE = 4;
export declare const DECISION_IGNORE = 5;
export declare const DECISION_QUARANTINE = 6;
export declare const DECISION_DELETE_REQUESTED = 7;
export declare const DECISION_HARD_REFUSE = 8;
export declare const HARD_REFUSE_TOMBSTONE = "[VERAXIS: HARD_REFUSE_BOUNDARY_VIOLATION - CONTENT_STRIPPED]";
export declare const QUARANTINE_TOMBSTONE = "[VERAXIS: MEMORY_QUARANTINED - CONTENT_STRIPPED]";
export declare const REFUSE_TOMBSTONE = "[VERAXIS: MEMORY_ADMISSIBILITY_DENIED - CONTENT_STRIPPED]";
export declare const DELETE_REQUESTED_TOMBSTONE = "[VERAXIS: MEMORY_DELETION_REQUESTED - CONTENT_STRIPPED]";
export declare const IGNORE_TOMBSTONE = "[VERAXIS: MEMORY_IGNORED - CONTENT_STRIPPED]";
export declare const REFRESH_TOMBSTONE = "[VERAXIS: MEMORY_REFRESH_REQUIRED - CONTENT_STRIPPED]";
export declare const ESCALATION_TOMBSTONE = "[VERAXIS: MEMORY_ESCALATION_REQUIRED - CONTENT_STRIPPED]";
export interface MemoryContextBinding {
    memoryId: Uint8Array;
    memoryHash: Uint8Array;
    messageIdx: number;
}
export interface LLMMessage {
    role: string;
    content: string;
}
export interface EvaluationMask {
    requiredLifecycle: bigint;
    prohibitedSafety: bigint;
    allowedUseClasses: bigint;
    prohibitedUseBlocks: bigint;
}
export interface MemoryDecisionLeaf {
    memoryId: Uint8Array;
    decisionCode: number;
    reasonCode: string;
    injected: boolean;
}
export interface SanitizedTurnResult {
    sanitizedMessages: LLMMessage[];
    merkleRoot: Uint8Array;
    snapshotVersion: bigint;
    decisions: MemoryDecisionLeaf[];
}
export interface EvaluateMemoryUseRequest {
    sessionId: string;
    agentId: string;
    tenantHash: Uint8Array;
    domainHash: Uint8Array;
    mask: EvaluationMask;
    candidates: MemoryContextBinding[];
}
export interface EvaluateMemoryUseResponse {
    merkleRoot: Uint8Array;
    snapshotVersion: bigint;
    decisions: MemoryDecisionLeaf[];
}
export interface MemoryAdmissibilityTransport {
    evaluateMemoryUse(request: EvaluateMemoryUseRequest): Promise<EvaluateMemoryUseResponse>;
}
export declare class MockMemoryAdmissibilityTransport implements MemoryAdmissibilityTransport {
    private readonly blockedMemoryIds;
    private readonly merkleRoot;
    private readonly snapshotVersion;
    constructor(options?: {
        blockedMemoryIds?: Uint8Array[];
        merkleRoot?: Uint8Array;
        snapshotVersion?: bigint;
    });
    evaluateMemoryUse(request: EvaluateMemoryUseRequest): Promise<EvaluateMemoryUseResponse>;
}
export declare class GrpcMemoryAdmissibilityTransport implements MemoryAdmissibilityTransport {
    private readonly generatedClient;
    constructor(generatedClient: unknown);
    evaluateMemoryUse(_request: EvaluateMemoryUseRequest): Promise<EvaluateMemoryUseResponse>;
}
export declare class VeraxisClientWrapper {
    private readonly endpoint;
    private readonly transport;
    constructor(grpcEndpoint: string, transport?: MemoryAdmissibilityTransport);
    sanitizeContextWindow(sessionId: string, agentId: string, tenantHash: Uint8Array, domainHash: Uint8Array, mask: EvaluationMask, messages: LLMMessage[], bindings: MemoryContextBinding[]): Promise<SanitizedTurnResult>;
}
export declare function tombstoneForDecision(decision: MemoryDecisionLeaf): string;
