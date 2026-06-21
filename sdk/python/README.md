# Veraxis MAM Python SDK v0.1.0

This package is the Python edge adapter for the frozen Veraxis MAM authority core.

It does not compute admissibility, Merkle roots, vector similarity, or policy logic locally.

It validates local byte shapes, calls the Veraxis daemon transport, and enforces returned decisions by scrubbing the Python context window before provider invocation.

## Invariant

The spine governs. The edge adapts.

## Install

In a connected environment:

```bash
pip install grpcio protobuf
```

Generate Python stubs from the repository schema:

```bash
python -m grpc_tools.protoc \
  -I../../schemas \
  --python_out=. \
  --grpc_python_out=. \
  ../../schemas/mam.proto
```

## Local tests

```bash
python -m unittest discover -s tests
```

## Usage

```python
from veraxis.client import (
    EvaluationMask,
    LLMMessage,
    MemoryContextBinding,
    VeraxisClientWrapper,
)

client = VeraxisClientWrapper(transport=my_transport)

result = await client.sanitize_context_window(
    session_id="sess",
    agent_id="agent",
    tenant_hash=b"\x01" * 32,
    domain_hash=b"\x02" * 32,
    mask=EvaluationMask(allowed_use_classes=1),
    messages=[LLMMessage(role="user", content="retrieved memory")],
    bindings=[
        MemoryContextBinding(
            memory_id=b"\x10" * 16,
            memory_hash=b"\x20" * 32,
            message_idx=0,
        )
    ],
)
```
