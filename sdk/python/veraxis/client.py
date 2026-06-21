from __future__ import annotations

import abc
import dataclasses
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence


# Decision enum values mirror the Go evaluate.Decision iota order.
DECISION_USE = 0
DECISION_QUALIFY = 1
DECISION_REFRESH = 2
DECISION_ESCALATE = 3
DECISION_REFUSE = 4
DECISION_IGNORE = 5
DECISION_QUARANTINE = 6
DECISION_DELETE_REQUESTED = 7
DECISION_HARD_REFUSE = 8


HARD_REFUSE_TOMBSTONE = "[VERAXIS: HARD_REFUSE_BOUNDARY_VIOLATION - CONTENT_STRIPPED]"
QUARANTINE_TOMBSTONE = "[VERAXIS: MEMORY_QUARANTINED - CONTENT_STRIPPED]"
REFUSE_TOMBSTONE = "[VERAXIS: MEMORY_ADMISSIBILITY_DENIED - CONTENT_STRIPPED]"
DELETE_REQUESTED_TOMBSTONE = "[VERAXIS: MEMORY_DELETION_REQUESTED - CONTENT_STRIPPED]"
IGNORE_TOMBSTONE = "[VERAXIS: MEMORY_IGNORED - CONTENT_STRIPPED]"
REFRESH_TOMBSTONE = "[VERAXIS: MEMORY_REFRESH_REQUIRED - CONTENT_STRIPPED]"
ESCALATION_TOMBSTONE = "[VERAXIS: MEMORY_ESCALATION_REQUIRED - CONTENT_STRIPPED]"


@dataclasses.dataclass(frozen=True)
class MemoryContextBinding:
    memory_id: bytes
    memory_hash: bytes
    message_idx: int


@dataclasses.dataclass(frozen=True)
class LLMMessage:
    role: str
    content: str


@dataclasses.dataclass(frozen=True)
class EvaluationMask:
    required_lifecycle: int = 0
    prohibited_safety: int = 0
    allowed_use_classes: int = 0
    prohibited_use_blocks: int = 0


@dataclasses.dataclass(frozen=True)
class MemoryDecision:
    memory_id: bytes
    decision_code: int
    reason_code: str
    injected: bool


@dataclasses.dataclass(frozen=True)
class SanitizedTurnResult:
    sanitized_messages: List[LLMMessage]
    merkle_root: bytes
    snapshot_version: int
    decisions: List[MemoryDecision]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "sanitized_messages": [dataclasses.asdict(m) for m in self.sanitized_messages],
            "merkle_root": self.merkle_root.hex(),
            "snapshot_version": self.snapshot_version,
            "decisions": [
                {
                    "memory_id": d.memory_id.hex(),
                    "decision_code": d.decision_code,
                    "reason_code": d.reason_code,
                    "injected": d.injected,
                }
                for d in self.decisions
            ],
        }


class MemoryAdmissibilityTransport(abc.ABC):
    @abc.abstractmethod
    async def evaluate_memory_use(
        self,
        *,
        session_id: str,
        agent_id: str,
        tenant_hash: bytes,
        domain_hash: bytes,
        mask: EvaluationMask,
        candidates: Sequence[MemoryContextBinding],
    ) -> SanitizedTurnResult:
        """Return daemon-authored memory decisions.

        Transport implementations must not compute admissibility locally.
        """


class MockMemoryAdmissibilityTransport(MemoryAdmissibilityTransport):
    """Deterministic local transport used for SDK unit tests.

    This does not implement the authority spine. It only simulates daemon responses
    so client-side structural behavior can be tested without a live gRPC daemon.
    """

    def __init__(
        self,
        *,
        blocked_memory_ids: Optional[Iterable[bytes]] = None,
        snapshot_version: int = 201,
        merkle_root: bytes = b"\x88" * 32,
    ) -> None:
        self.blocked_memory_ids = set(blocked_memory_ids or [])
        self.snapshot_version = snapshot_version
        self.merkle_root = merkle_root

    async def evaluate_memory_use(
        self,
        *,
        session_id: str,
        agent_id: str,
        tenant_hash: bytes,
        domain_hash: bytes,
        mask: EvaluationMask,
        candidates: Sequence[MemoryContextBinding],
    ) -> SanitizedTurnResult:
        decisions: List[MemoryDecision] = []
        for binding in candidates:
            if binding.memory_id in self.blocked_memory_ids:
                decisions.append(
                    MemoryDecision(
                        memory_id=binding.memory_id,
                        decision_code=DECISION_HARD_REFUSE,
                        reason_code="HARD_REFUSE_BOUNDARY_VIOLATION",
                        injected=False,
                    )
                )
            else:
                decisions.append(
                    MemoryDecision(
                        memory_id=binding.memory_id,
                        decision_code=DECISION_USE,
                        reason_code="CLEAN_PASS",
                        injected=True,
                    )
                )

        return SanitizedTurnResult(
            sanitized_messages=[],
            merkle_root=self.merkle_root,
            snapshot_version=self.snapshot_version,
            decisions=decisions,
        )


class GrpcMemoryAdmissibilityTransport(MemoryAdmissibilityTransport):
    """Transport adapter for generated gRPC stubs.

    The SDK keeps gRPC at the transport edge. Generated modules are supplied by
    the deployment environment from schemas/mam.proto.

    Expected generated modules:
      - mam_pb2
      - mam_pb2_grpc
    """

    def __init__(self, endpoint: str, *, mam_pb2: Any, mam_pb2_grpc: Any) -> None:
        try:
            import grpc  # type: ignore
        except ImportError as exc:
            raise RuntimeError("grpcio is required for GrpcMemoryAdmissibilityTransport") from exc

        self._grpc = grpc
        self.endpoint = endpoint
        self._mam_pb2 = mam_pb2
        self._channel = grpc.aio.insecure_channel(endpoint)
        self._stub = mam_pb2_grpc.MemoryAdmissibilityServiceStub(self._channel)

    async def evaluate_memory_use(
        self,
        *,
        session_id: str,
        agent_id: str,
        tenant_hash: bytes,
        domain_hash: bytes,
        mask: EvaluationMask,
        candidates: Sequence[MemoryContextBinding],
    ) -> SanitizedTurnResult:
        pb = self._mam_pb2
        request = pb.EvaluateRequest(
            session_id=session_id,
            agent_id=agent_id,
            context=pb.RuntimeContext(
                tenant_hash=tenant_hash,
                domain_hash=domain_hash,
                required_lifecycle=mask.required_lifecycle,
                prohibited_safety=mask.prohibited_safety,
                allowed_use_classes=mask.allowed_use_classes,
                prohibited_use_blocks=mask.prohibited_use_blocks,
            ),
            candidates=[
                pb.MemoryCandidate(
                    memory_id=b.memory_id,
                    memory_hash=b.memory_hash,
                    memory_flags=0,
                )
                for b in candidates
            ],
        )
        response = await self._stub.EvaluateMemoryUse(request)

        decisions = [
            MemoryDecision(
                memory_id=d.memory_id,
                decision_code=int(d.decision_code),
                reason_code=d.reason_code,
                injected=bool(d.injected),
            )
            for d in response.decisions
        ]

        return SanitizedTurnResult(
            sanitized_messages=[],
            merkle_root=response.merkle_root,
            snapshot_version=int(response.runtime_snapshot_version),
            decisions=decisions,
        )

    async def close(self) -> None:
        await self._channel.close()


class VeraxisClientWrapper:
    """Async Python wrapper for Veraxis MAM.

    The wrapper validates local byte sizes, delegates authority to the daemon
    transport, then enforces returned decisions by mutating the context window
    before provider invocation.
    """

    def __init__(
        self,
        grpc_channel_endpoint: str = "",
        *,
        transport: Optional[MemoryAdmissibilityTransport] = None,
    ) -> None:
        self.endpoint = grpc_channel_endpoint
        self.transport = transport

    async def sanitize_context_window(
        self,
        session_id: str,
        agent_id: str,
        tenant_hash: bytes,
        domain_hash: bytes,
        mask: EvaluationMask,
        messages: Sequence[LLMMessage],
        bindings: Sequence[MemoryContextBinding],
    ) -> SanitizedTurnResult:
        self._validate_hash("tenant_hash", tenant_hash, 32)
        self._validate_hash("domain_hash", domain_hash, 32)

        message_count = len(messages)
        for binding in bindings:
            self._validate_hash("memory_id", binding.memory_id, 16)
            self._validate_hash("memory_hash", binding.memory_hash, 32)
            if binding.message_idx < 0 or binding.message_idx >= message_count:
                raise ValueError("INVALID_MESSAGE_INDEX: Binding points outside message array.")

        if self.transport is None:
            raise RuntimeError("VeraxisClientWrapper requires a transport or generated gRPC adapter.")

        response = await self.transport.evaluate_memory_use(
            session_id=session_id,
            agent_id=agent_id,
            tenant_hash=tenant_hash,
            domain_hash=domain_hash,
            mask=mask,
            candidates=list(bindings),
        )

        decision_by_memory_id = {d.memory_id: d for d in response.decisions}
        sanitized = [LLMMessage(role=m.role, content=m.content) for m in messages]

        for binding in bindings:
            decision = decision_by_memory_id.get(binding.memory_id)
            if decision is None:
                sanitized[binding.message_idx] = LLMMessage(
                    role=sanitized[binding.message_idx].role,
                    content=HARD_REFUSE_TOMBSTONE,
                )
                continue

            if not decision.injected:
                sanitized[binding.message_idx] = LLMMessage(
                    role=sanitized[binding.message_idx].role,
                    content=tombstone_for_decision(decision),
                )

        return SanitizedTurnResult(
            sanitized_messages=sanitized,
            merkle_root=response.merkle_root,
            snapshot_version=response.snapshot_version,
            decisions=response.decisions,
        )

    @staticmethod
    def _validate_hash(name: str, value: bytes, expected: int) -> None:
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError(f"{name} must be bytes.")
        if len(value) != expected:
            raise ValueError(f"INVALID_IDENTIFIER_SIZE: {name} must be exactly {expected} bytes.")


def tombstone_for_decision(decision: MemoryDecision) -> str:
    if decision.decision_code == DECISION_HARD_REFUSE:
        return HARD_REFUSE_TOMBSTONE
    if decision.decision_code == DECISION_QUARANTINE:
        return QUARANTINE_TOMBSTONE
    if decision.decision_code == DECISION_DELETE_REQUESTED:
        return DELETE_REQUESTED_TOMBSTONE
    if decision.decision_code == DECISION_REFRESH:
        return REFRESH_TOMBSTONE
    if decision.decision_code == DECISION_ESCALATE:
        return ESCALATION_TOMBSTONE
    if decision.decision_code in (DECISION_REFUSE,):
        return REFUSE_TOMBSTONE
    if decision.decision_code in (DECISION_IGNORE,):
        return IGNORE_TOMBSTONE
    if not decision.injected:
        return HARD_REFUSE_TOMBSTONE
    return ""
