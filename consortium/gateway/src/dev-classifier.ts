import Fastify from 'fastify';

interface ClassifierRequest {
  promptId: string;
  userId: string;
  orgId: string;
  prompt: string;
  promptHash: string;
  conversationId?: string;
  history?: string[];
}

type BinaryLabel = 'benign' | 'attack';

interface DevClassification {
  riskScore: number;
  binaryLabel: BinaryLabel;
  dlsmClass: string;
  attackFamily: string;
}

const app = Fastify({ logger: true });

function classifyPrompt(prompt: string): DevClassification {
  const normalizedPrompt = prompt.toLowerCase();

  const criticalPatterns = [
    'ignore previous instructions',
    'reveal the system prompt',
    'developer message',
    'system prompt',
    'bypass safety',
    'jailbreak'
  ];

  const mediumPatterns = [
    'roleplay as',
    'pretend you are',
    'do anything now',
    'disable your rules'
  ];

  if (criticalPatterns.some((pattern) => normalizedPrompt.includes(pattern))) {
    return {
      riskScore: 0.92,
      binaryLabel: 'attack',
      dlsmClass: 'class_1_prompt_subversion',
      attackFamily: 'prompt_injection'
    };
  }

  if (mediumPatterns.some((pattern) => normalizedPrompt.includes(pattern))) {
    return {
      riskScore: 0.64,
      binaryLabel: 'attack',
      dlsmClass: 'class_2_policy_evasion',
      attackFamily: 'jailbreak_attempt'
    };
  }

  return {
    riskScore: 0.03,
    binaryLabel: 'benign',
    dlsmClass: 'class_4_compliant_functional_use',
    attackFamily: 'benign'
  };
}

app.get('/health', async () => {
  return {
    service: 'dlsm-dev-classifier',
    status: 'ok',
    modelVersion: 'dev-http-classifier-v0.1'
  };
});

app.post('/classify', {
  schema: {
    body: {
      type: 'object',
      additionalProperties: false,
      required: ['promptId', 'userId', 'orgId', 'prompt', 'promptHash'],
      properties: {
        promptId: { type: 'string', minLength: 1 },
        userId: { type: 'string', minLength: 1 },
        orgId: { type: 'string', minLength: 1 },
        prompt: { type: 'string', minLength: 1 },
        promptHash: {
          type: 'string',
          pattern: '^[a-fA-F0-9]{64}$'
        },
        conversationId: { type: 'string', minLength: 1 },
        history: {
          type: 'array',
          items: { type: 'string', minLength: 1 }
        }
      }
    }
  }
}, async (request) => {
  const body = request.body as ClassifierRequest;
  const classification = classifyPrompt(body.prompt);

  return {
    promptId: body.promptId,
    userId: body.userId,
    orgId: body.orgId,
    promptHash: body.promptHash,
    ...classification,
    modelVersion: 'dev-http-classifier-v0.1',
    timestamp: Math.floor(Date.now() / 1000),
    contextAware: Boolean(body.history && body.history.length > 0)
  };
});

const port = Number(process.env.CLASSIFIER_PORT ?? 4000);

try {
  await app.listen({ host: '127.0.0.1', port });
} catch (error) {
  app.log.error(error);
  process.exit(1);
}
