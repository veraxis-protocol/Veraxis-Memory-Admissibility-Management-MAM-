export const DECISION_USE = 0;
export const DECISION_QUALIFY = 1;
export const DECISION_REFRESH = 2;
export const DECISION_ESCALATE = 3;
export const DECISION_REFUSE = 4;
export const DECISION_IGNORE = 5;
export const DECISION_QUARANTINE = 6;
export const DECISION_DELETE_REQUESTED = 7;
export const DECISION_HARD_REFUSE = 8;

export const HARD_REFUSE_TOMBSTONE = "[VERAXIS: HARD_REFUSE_BOUNDARY_VIOLATION - CONTENT_STRIPPED]";
export const QUARANTINE_TOMBSTONE = "[VERAXIS: MEMORY_QUARANTINED - CONTENT_STRIPPED]";
export const REFUSE_TOMBSTONE = "[VERAXIS: MEMORY_ADMISSIBILITY_DENIED - CONTENT_STRIPPED]";
export const DELETE_REQUESTED_TOMBSTONE = "[VERAXIS: MEMORY_DELETION_REQUESTED - CONTENT_STRIPPED]";
export const IGNORE_TOMBSTONE = "[VERAXIS: MEMORY_IGNORED - CONTENT_STRIPPED]";
export const REFRESH_TOMBSTONE = "[VERAXIS: MEMORY_REFRESH_REQUIRED - CONTENT_STRIPPED]";
export const ESCALATION_TOMBSTONE = "[VERAXIS: MEMORY_ESCALATION_REQUIRED - CONTENT_STRIPPED]";

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

export class MockMemoryAdmissibilityTransport implements MemoryAdmissibilityTransport {
  private readonly blockedMemoryIds: Set<string>;
  private readonly merkleRoot: Uint8Array;
  private readonly snapshotVersion: bigint;

  constructor(options?: {
    blockedMemoryIds?: Uint8Array[];
    merkleRoot?: Uint8Array;
    snapshotVersion?: bigint;
  }) {
    this.blockedMemoryIds = new Set((options?.blockedMemoryIds ?? []).map(bytesToKey));
    this.merkleRoot = options?.merkleRoot ?? new Uint8Array(32).fill(0x88);
    this.snapshotVersion = options?.snapshotVersion ?? 201n;
  }

  public async evaluateMemoryUse(request: EvaluateMemoryUseRequest): Promise<EvaluateMemoryUseResponse> {
    return {
      merkleRoot: this.merkleRoot,
      snapshotVersion: this.snapshotVersion,
      decisions: request.candidates.map((candidate) => {
        if (this.blockedMemoryIds.has(bytesToKey(candidate.memoryId))) {
          return {
            memoryId: candidate.memoryId,
            decisionCode: DECISION_HARD_REFUSE,
            reasonCode: "HARD_REFUSE_BOUNDARY_VIOLATION",
            injected: false
          };
        }
        return {
          memoryId: candidate.memoryId,
          decisionCode: DECISION_USE,
          reasonCode: "CLEAN_PASS",
          injected: true
        };
      })
    };
  }
}

export class GrpcMemoryAdmissibilityTransport implements MemoryAdmissibilityTransport {
  private readonly generatedClient: unknown;

  constructor(generatedClient: unknown) {
    this.generatedClient = generatedClient;
  }

  public async evaluateMemoryUse(_request: EvaluateMemoryUseRequest): Promise<EvaluateMemoryUseResponse> {
    void this.generatedClient;
    throw new Error("GRPC_TRANSPORT_NOT_BOUND: bind generated @grpc/grpc-js client from schemas/mam.proto.");
  }
}

export class VeraxisClientWrapper {
  private readonly endpoint: string;
  private readonly transport: MemoryAdmissibilityTransport;

  constructor(grpcEndpoint: string, transport?: MemoryAdmissibilityTransport) {
    this.endpoint = grpcEndpoint;
    if (!transport) {
      throw new Error("TRANSPORT_REQUIRED: provide generated gRPC transport or MockMemoryAdmissibilityTransport.");
    }
    this.transport = transport;
  }

  public async sanitizeContextWindow(
    sessionId: string,
    agentId: string,
    tenantHash: Uint8Array,
    domainHash: Uint8Array,
    mask: EvaluationMask,
    messages: LLMMessage[],
    bindings: MemoryContextBinding[]
  ): Promise<SanitizedTurnResult> {
    void this.endpoint;

    validateBytes("tenantHash", tenantHash, 32);
    validateBytes("domainHash", domainHash, 32);

    for (const binding of bindings) {
      validateBytes("memoryId", binding.memoryId, 16);
      validateBytes("memoryHash", binding.memoryHash, 32);
      if (!Number.isInteger(binding.messageIdx) || binding.messageIdx < 0 || binding.messageIdx >= messages.length) {
        throw new Error("INVALID_MESSAGE_INDEX: Binding points outside message array.");
      }
    }

    const response = await this.transport.evaluateMemoryUse({
      sessionId,
      agentId,
      tenantHash,
      domainHash,
      mask,
      candidates: bindings
    });

    validateBytes("merkleRoot", response.merkleRoot, 32);

    const decisionByMemoryId = new Map(response.decisions.map((decision) => [bytesToKey(decision.memoryId), decision]));
    const sanitizedMessages: LLMMessage[] = messages.map((message) => ({
      role: message.role,
      content: message.content
    }));

    for (const binding of bindings) {
      const decision = decisionByMemoryId.get(bytesToKey(binding.memoryId));
      const current = sanitizedMessages[binding.messageIdx];
      if (!current) {
        throw new Error("INVALID_MESSAGE_INDEX: Binding points outside message array.");
      }

      if (!decision) {
        sanitizedMessages[binding.messageIdx] = { role: current.role, content: HARD_REFUSE_TOMBSTONE };
        continue;
      }

      if (!decision.injected) {
        sanitizedMessages[binding.messageIdx] = { role: current.role, content: tombstoneForDecision(decision) };
      }
    }

    return {
      sanitizedMessages,
      merkleRoot: response.merkleRoot,
      snapshotVersion: response.snapshotVersion,
      decisions: response.decisions
    };
  }
}

export function tombstoneForDecision(decision: MemoryDecisionLeaf): string {
  if (decision.decisionCode === DECISION_HARD_REFUSE) return HARD_REFUSE_TOMBSTONE;
  if (decision.decisionCode === DECISION_QUARANTINE) return QUARANTINE_TOMBSTONE;
  if (decision.decisionCode === DECISION_DELETE_REQUESTED) return DELETE_REQUESTED_TOMBSTONE;
  if (decision.decisionCode === DECISION_REFRESH) return REFRESH_TOMBSTONE;
  if (decision.decisionCode === DECISION_ESCALATE) return ESCALATION_TOMBSTONE;
  if (decision.decisionCode === DECISION_REFUSE) return REFUSE_TOMBSTONE;
  if (decision.decisionCode === DECISION_IGNORE) return IGNORE_TOMBSTONE;
  if (!decision.injected) return HARD_REFUSE_TOMBSTONE;
  return "";
}

function validateBytes(name: string, value: Uint8Array, expected: number): void {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Uint8Array.`);
  }
  if (value.byteLength !== expected) {
    throw new Error(`INVALID_IDENTIFIER_SIZE: ${name} must be exactly ${expected} bytes.`);
  }
}

function bytesToKey(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
