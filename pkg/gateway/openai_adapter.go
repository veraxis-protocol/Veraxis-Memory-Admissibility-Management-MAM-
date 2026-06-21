package gateway

type OpenAIRequestPayload struct {
	Model    string          `json:"model"`
	Messages []OpenAIMessage `json:"messages"`
}

type OpenAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type OpenAIAdapter struct {
	ModelName string
}

// Convert processes internal audited messages into an OpenAI-compatible wire payload.
// This operation is read-only and does not mutate the input slice.
func (a *OpenAIAdapter) Convert(messages []LLMMessage) OpenAIRequestPayload {
	openAIMessages := make([]OpenAIMessage, len(messages))
	for i, msg := range messages {
		openAIMessages[i] = OpenAIMessage{
			Role:    msg.Role,
			Content: msg.Content,
		}
	}

	return OpenAIRequestPayload{
		Model:    a.ModelName,
		Messages: openAIMessages,
	}
}
