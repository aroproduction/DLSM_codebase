class MockClassifierClient {
    async classify(input) {
        const prompt = input.prompt.toLowerCase();
        const suspicious = [
            'ignore previous instructions',
            'jailbreak',
            'bypass safety',
            'system prompt'
        ].some((pattern) => prompt.includes(pattern));
        return {
            promptId: input.promptId,
            userId: input.userId,
            orgId: input.orgId,
            promptHash: input.promptHash,
            riskScore: suspicious ? 0.92 : 0.03,
            binaryLabel: suspicious ? 'attack' : 'benign',
            dlsmClass: suspicious
                ? 'class_1_prompt_subversion'
                : 'class_4_compliant_functional_use',
            attackFamily: suspicious ? 'prompt_injection' : 'benign',
            modelVersion: 'mock-classifier-v0.1',
            timestamp: Math.floor(Date.now() / 1000)
        };
    }
}
class HttpClassifierClient {
    endpoint;
    constructor(endpoint) {
        this.endpoint = endpoint;
    }
    async classify(input) {
        const response = await fetch(this.endpoint, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(input),
            signal: AbortSignal.timeout(5_000)
        });
        if (!response.ok) {
            throw new Error(`Classifier request failed with status ${response.status}`);
        }
        const result = await response.json();
        if (result.promptId !== input.promptId ||
            result.userId !== input.userId ||
            result.orgId !== input.orgId ||
            result.promptHash !== input.promptHash ||
            typeof result.riskScore !== 'number' ||
            result.riskScore < 0 ||
            result.riskScore > 1 ||
            (result.binaryLabel !== 'benign' && result.binaryLabel !== 'attack') ||
            typeof result.dlsmClass !== 'string' ||
            typeof result.attackFamily !== 'string' ||
            typeof result.modelVersion !== 'string' ||
            typeof result.timestamp !== 'number') {
            throw new Error('Classifier returned an invalid or mismatched result');
        }
        return result;
    }
}
export function createClassifierClient() {
    const mode = process.env.CLASSIFIER_MODE ?? 'mock';
    if (mode === 'mock') {
        return new MockClassifierClient();
    }
    if (mode === 'http') {
        const endpoint = process.env.CLASSIFIER_URL;
        if (!endpoint) {
            throw new Error('CLASSIFIER_URL is required when CLASSIFIER_MODE=http');
        }
        return new HttpClassifierClient(endpoint);
    }
    throw new Error(`Unsupported CLASSIFIER_MODE: ${mode}`);
}
