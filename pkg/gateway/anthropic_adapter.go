package gateway

import "errors"

type AnthropicRequestPayload struct {
	Model    string             `json:"model"`
	System   string             `json:"system,omitempty"`
	Messages []AnthropicMessage `json:"messages"`
}

type AnthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type AnthropicAdapter struct {
	ModelName string
}

// Convert translates internal messages into an Anthropic message structure, pulling system prompts out.
// It returns an explicit error if an unsupported role is encountered.
func (a *AnthropicAdapter) Convert(messages []LLMMessage) (AnthropicRequestPayload, error) {
	systemPrompt := ""
	anthropicMessages := make([]AnthropicMessage, 0, len(messages))

	for _, msg := range messages {
		if msg.Role == "system" {
			if systemPrompt != "" {
				systemPrompt += "\n" + msg.Content
			} else {
				systemPrompt = msg.Content
			}
			continue
		}

		if msg.Role != "user" && msg.Role != "assistant" {
			return AnthropicRequestPayload{}, errors.New("ANTHROPIC_PROVIDER_ERR: role must be user or assistant")
		}

		anthropicMessages = append(anthropicMessages, AnthropicMessage{
			Role:    msg.Role,
			Content: msg.Content,
		})
	}

	return AnthropicRequestPayload{
		Model:    a.ModelName,
		System:   systemPrompt,
		Messages: anthropicMessages,
	}, nil
}
