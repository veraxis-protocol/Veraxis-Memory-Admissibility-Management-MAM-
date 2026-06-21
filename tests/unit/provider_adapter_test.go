package unit

import (
	"encoding/json"
	"testing"

	"veraxis-memory-admissibility/pkg/gateway"
)

func getProviderAdapterTestMessages() []gateway.LLMMessage {
	return []gateway.LLMMessage{
		{Role: "system", Content: "System Directive Baseline"},
		{Role: "user", Content: "Legitimate User Query Content"},
		{Role: "assistant", Content: "[VERAXIS: MEMORY_QUARANTINED - CONTENT_STRIPPED]"},
		{Role: "user", Content: "Context Block: [VERAXIS QUALIFIED MEMORY: tone adjustment only]"},
	}
}

func cloneMessages(in []gateway.LLMMessage) []gateway.LLMMessage {
	out := make([]gateway.LLMMessage, len(in))
	copy(out, in)
	return out
}

func assertMessagesUnchanged(t *testing.T, before, after []gateway.LLMMessage) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("message count changed: got %d want %d", len(after), len(before))
	}
	for i := range before {
		if before[i] != after[i] {
			t.Fatalf("input mutation detected at index %d: got %#v want %#v", i, after[i], before[i])
		}
	}
}

func TestOpenAIAdapterFidelity(t *testing.T) {
	origMessages := getProviderAdapterTestMessages()
	before := cloneMessages(origMessages)

	adapter := gateway.OpenAIAdapter{ModelName: "gpt-4o"}
	payload := adapter.Convert(origMessages)

	if payload.Model != "gpt-4o" {
		t.Fatalf("OpenAI model mismatch: got %q", payload.Model)
	}
	if len(payload.Messages) != len(origMessages) {
		t.Fatalf("OpenAI count mismatch: got %d, want %d", len(payload.Messages), len(origMessages))
	}

	for i, msg := range origMessages {
		if payload.Messages[i].Role != msg.Role || payload.Messages[i].Content != msg.Content {
			t.Errorf("OpenAI mutation detected at index %d", i)
		}
	}

	if payload.Messages[2].Content != gateway.TombstoneQuarantine {
		t.Fatalf("OpenAI tombstone altered: got %q", payload.Messages[2].Content)
	}
	if payload.Messages[3].Content != "Context Block: [VERAXIS QUALIFIED MEMORY: tone adjustment only]" {
		t.Fatalf("OpenAI qualification annotation altered: got %q", payload.Messages[3].Content)
	}

	if _, err := json.Marshal(payload); err != nil {
		t.Fatalf("OpenAI JSON serialization failed: %v", err)
	}

	assertMessagesUnchanged(t, before, origMessages)
}

func TestAnthropicAdapterFidelity(t *testing.T) {
	origMessages := []gateway.LLMMessage{
		{Role: "system", Content: "Directive 1"},
		{Role: "user", Content: "User Turn"},
		{Role: "system", Content: "Directive 2"},
		{Role: "assistant", Content: gateway.TombstoneRefuse},
		{Role: "user", Content: "Context Block: [VERAXIS QUALIFIED MEMORY: tone adjustment only]"},
	}
	before := cloneMessages(origMessages)

	adapter := gateway.AnthropicAdapter{ModelName: "claude-3-5-sonnet"}
	payload, err := adapter.Convert(origMessages)
	if err != nil {
		t.Fatalf("Anthropic conversion failed: %v", err)
	}

	expectedSystem := "Directive 1\nDirective 2"
	if payload.System != expectedSystem {
		t.Errorf("Anthropic system mismatch: got %q, want %q", payload.System, expectedSystem)
	}
	if payload.Model != "claude-3-5-sonnet" {
		t.Fatalf("Anthropic model mismatch: got %q", payload.Model)
	}

	if len(payload.Messages) != 3 {
		t.Fatalf("Anthropic message timeline mismatch: got %d", len(payload.Messages))
	}
	if payload.Messages[0].Role != "user" || payload.Messages[1].Role != "assistant" || payload.Messages[2].Role != "user" {
		t.Fatal("Anthropic message timeline sequencing broken")
	}

	if payload.Messages[1].Content != gateway.TombstoneRefuse {
		t.Fatal("Anthropic dropped or altered context tombstone marker")
	}
	if payload.Messages[2].Content != "Context Block: [VERAXIS QUALIFIED MEMORY: tone adjustment only]" {
		t.Fatal("Anthropic dropped or altered qualification annotation")
	}

	if _, err := json.Marshal(payload); err != nil {
		t.Fatalf("Anthropic JSON serialization failed: %v", err)
	}

	assertMessagesUnchanged(t, before, origMessages)
}

func TestAnthropicAdapterRejectsUnsupportedRole(t *testing.T) {
	adapter := gateway.AnthropicAdapter{ModelName: "claude-3-5-sonnet"}
	invalidMessages := []gateway.LLMMessage{{Role: "tool", Content: "Malformed Trigger"}}

	_, err := adapter.Convert(invalidMessages)
	if err == nil {
		t.Fatal("Anthropic failed to reject invalid message role structure")
	}
}

func TestAdaptersPreserveGatewayTombstones(t *testing.T) {
	messages := []gateway.LLMMessage{
		{Role: "user", Content: gateway.TombstoneHardRefuse},
		{Role: "assistant", Content: gateway.TombstoneDeleteRequested},
		{Role: "user", Content: gateway.TombstoneQuarantine},
	}

	openAI := gateway.OpenAIAdapter{ModelName: "gpt-4o"}
	openPayload := openAI.Convert(messages)
	for i := range messages {
		if openPayload.Messages[i].Content != messages[i].Content {
			t.Fatalf("OpenAI tombstone mutation at %d", i)
		}
	}

	anthropic := gateway.AnthropicAdapter{ModelName: "claude-3-5-sonnet"}
	anthropicPayload, err := anthropic.Convert(messages)
	if err != nil {
		t.Fatalf("Anthropic conversion failed: %v", err)
	}
	for i := range messages {
		if anthropicPayload.Messages[i].Content != messages[i].Content {
			t.Fatalf("Anthropic tombstone mutation at %d", i)
		}
	}
}
