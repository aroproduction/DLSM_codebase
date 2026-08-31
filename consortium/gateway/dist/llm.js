class MockLlmClient {
    async complete(input) {
        return {
            answer: [
                `Mock LLM response for ${input.userId}.`,
                'The request passed the DLSM security gateway, so the prompt was forwarded to the protected LLM layer.',
                `Prompt summary: ${summarizePrompt(input.prompt)}`
            ].join(' '),
            modelVersion: 'mock-llm-v0.1',
            timestamp: Math.floor(Date.now() / 1000)
        };
    }
}
class HttpLlmClient {
    endpoint;
    constructor(endpoint) {
        this.endpoint = endpoint;
    }
    async complete(input) {
        const response = await fetch(this.endpoint, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(input),
            signal: AbortSignal.timeout(10_000)
        });
        if (!response.ok) {
            throw new Error(`LLM request failed with status ${response.status}`);
        }
        const result = await response.json();
        if (typeof result.answer !== 'string' ||
            result.answer.length === 0 ||
            typeof result.modelVersion !== 'string' ||
            typeof result.timestamp !== 'number') {
            throw new Error('LLM returned an invalid result');
        }
        return result;
    }
}
function summarizePrompt(prompt) {
    const singleLine = prompt.replace(/\s+/g, ' ').trim();
    if (singleLine.length <= 140) {
        return singleLine;
    }
    return `${singleLine.slice(0, 137)}...`;
}
export function createLlmClient() {
    const mode = process.env.LLM_MODE ?? 'mock';
    if (mode === 'mock') {
        return new MockLlmClient();
    }
    if (mode === 'http') {
        const endpoint = process.env.LLM_URL;
        if (!endpoint) {
            throw new Error('LLM_URL is required when LLM_MODE=http');
        }
        return new HttpLlmClient(endpoint);
    }
    throw new Error(`Unsupported LLM_MODE: ${mode}`);
}
