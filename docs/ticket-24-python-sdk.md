# Ticket 24 — Python Client SDK

Component: `sdk/python`

Core invariant:

The Python SDK mirrors data structures and handles transport. It does not compute admissibility logic or Merkle roots locally. It delegates authority to the core daemon and enforces returned decisions.

Implemented assets:

- `sdk/python/veraxis/client.py`
- `sdk/python/veraxis/__init__.py`
- `sdk/python/tests/test_client.py`
- `sdk/python/pyproject.toml`
- `sdk/python/README.md`

The SDK includes:

- typed dataclasses for context messages, bindings, masks, decisions, and results;
- async wrapper interface;
- byte-size validation;
- injected / non-injected decision enforcement;
- tombstone replacement;
- mock transport for local unit tests;
- optional generated gRPC transport seam for connected environments.

No NumPy, SciPy, PyTorch, agent framework, or vector library dependency is introduced.
