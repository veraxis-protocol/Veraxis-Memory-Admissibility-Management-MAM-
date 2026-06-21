# Ticket 11 — Provider Serialization Adapters

Component: `pkg/gateway`

Status: implemented baseline.

Core principle:

Adapter shape first. Provider clients second.

Ticket 11 implements dependency-free OpenAI and Anthropic payload conversion from sanitized Veraxis `[]LLMMessage` values.

No provider SDKs, HTTP clients, credentials, streaming logic, or network dependencies are introduced.

Implemented files:

- `pkg/gateway/openai_adapter.go`
- `pkg/gateway/anthropic_adapter.go`
- `tests/unit/provider_adapter_test.go`

Acceptance:

- OpenAI preserves message count, order, roles, tombstones, and annotations.
- Anthropic extracts system prompts to top-level `System`, preserves user/assistant order, rejects unsupported roles, and preserves tombstones/annotations.
