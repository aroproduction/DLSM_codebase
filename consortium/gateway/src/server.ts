import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import Fastify from 'fastify';
import {
  closeFabricConnection,
  getDlsmContract
} from './fabric.js';
import {
  createClassifierClient,
  type ClassifierResult
} from './classifier.js';
import {
  createLlmClient,
  type LlmResult
} from './llm.js';

interface EvaluationRequest {
  requestId: string;
  userId: string;
  orgId: string;
  prompt: string;
}

interface ChatRequest {
  requestId?: string;
  userId: string;
  orgId: string;
  prompt: string;
  conversationId?: string;
}

interface ConversationState {
  conversationId: string;
  history: string[];
  terminated: boolean;
}

type RiskLevel = 'low' | 'medium' | 'high' | 'critical';
type GatewayDecision = 'allow' | 'review' | 'block';
type ChatStatus = 'forwarded' | 'warned' | 'blocked';

interface StoredSecurityEvent {
  userId: string;
  requestId: string;
  promptHash: string;
}

interface GatewayEvaluation {
  requestId: string;
  userId: string;
  orgId: string;
  promptHash: string;
  conversationId: string;
  classifier: ClassifierResult;
  sessionRisk?: number;
  multiTurnDetected?: boolean;
  riskLevel: RiskLevel;
  gatewayDecision: GatewayDecision;
  eventId?: string;
  adjustment?: unknown;
}

const app = Fastify({ logger: true });
const classifierClient = createClassifierClient();
const llmClient = createLlmClient();

// In-memory conversation tracking. The authoritative sliding-window state
// lives on the ledger (SubmitPromptRisk); this mirror is used only for the
// ML context-history and quick UX checks.
const conversations = new Map<string, ConversationState>();

function getConversation(
  userId: string,
  conversationId?: string
): ConversationState {
  if (conversationId) {
    const existing = conversations.get(conversationId);

    if (existing) {
      return existing;
    }

    const created: ConversationState = {
      conversationId,
      history: [],
      terminated: false
    };

    conversations.set(conversationId, created);
    return created;
  }

  const key = `conv-${userId}`;
  const existing = conversations.get(key);

  if (existing) {
    return existing;
  }

  const created: ConversationState = {
    conversationId: key,
    history: [],
    terminated: false
  };

  conversations.set(key, created);
  return created;
}

const MAX_HISTORY = 8;

function appendHistory(state: ConversationState, prompt: string): void {
  state.history.push(prompt);

  if (state.history.length > MAX_HISTORY) {
    state.history.splice(0, state.history.length - MAX_HISTORY);
  }
}

function hashPrompt(prompt: string): string {
  return createHash('sha256').update(prompt, 'utf8').digest('hex');
}

function decide(riskScore: number): {
  riskLevel: RiskLevel;
  gatewayDecision: GatewayDecision;
} {
  if (riskScore >= 0.8) {
    return { riskLevel: 'high', gatewayDecision: 'block' };
  }

  if (riskScore >= 0.5) {
    return { riskLevel: 'medium', gatewayDecision: 'review' };
  }

  return { riskLevel: 'low', gatewayDecision: 'allow' };
}

function errorText(error: unknown): string {
  if (!(error instanceof Error)) {
    return String(error);
  }

  const details = 'details' in error
    ? JSON.stringify((error as { details?: unknown }).details)
    : '';

  return `${error.message} ${details}`;
}

function isAlreadyExists(error: unknown): boolean {
  return errorText(error).includes('already exists');
}

function createRequestId(): string {
  return `req-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;
}

async function readPublicFile(fileName: string): Promise<string> {
  return readFile(path.join(process.cwd(), 'public', fileName), 'utf8');
}

async function getSecurityEvent(
  userId: string,
  eventId: string
): Promise<StoredSecurityEvent> {
  const contract = await getDlsmContract();

  const result = await contract.evaluateTransaction(
    'GetSecurityEvent',
    userId,
    eventId
  );

  return JSON.parse(Buffer.from(result).toString('utf8'));
}

async function applyReputationAdjustment(
  userId: string,
  eventId: string
): Promise<unknown> {
  const contract = await getDlsmContract();

  try {
    await contract.submitTransaction(
      'ApplyReputationAdjustment',
      userId,
      eventId
    );
  } catch (error) {
    if (!isAlreadyExists(error)) {
      throw error;
    }
  }

  const result = await contract.evaluateTransaction(
    'GetReputationAdjustment',
    userId,
    eventId
  );

  return JSON.parse(Buffer.from(result).toString('utf8'));
}

async function recordSecurityEvent(
  request: EvaluationRequest,
  promptHash: string,
  classifier: ClassifierResult,
  riskLevel: RiskLevel,
  gatewayDecision: GatewayDecision
): Promise<string> {
  const eventId = `evt-${request.requestId}`;
  const contract = await getDlsmContract();

  const interactionClass = classifier.dlsmClass.startsWith('class_2')
    ? 'class_2'
    : classifier.dlsmClass.startsWith('class_3')
      ? 'class_3'
      : classifier.dlsmClass.startsWith('class_4')
        ? 'class_4'
        : 'class_1';

  try {
    await contract.submitTransaction(
      'RecordSecurityEvent',
      eventId,
      request.userId,
      request.requestId,
      promptHash,
      riskLevel,
      classifier.attackFamily,
      classifier.modelVersion,
      gatewayDecision,
      interactionClass
    );
  } catch (error) {
    if (!isAlreadyExists(error)) {
      throw error;
    }

    const existing = await getSecurityEvent(request.userId, eventId);

    if (
      existing.userId !== request.userId ||
      existing.requestId !== request.requestId ||
      existing.promptHash !== promptHash
    ) {
      throw new Error('requestId is already associated with different data');
    }
  }

  return eventId;
}

async function submitSessionRisk(
  userId: string,
  conversationId: string,
  promptHash: string,
  riskScore: number
): Promise<{ verdict: string; sessionRisk?: number; terminated?: boolean; breachEventId?: string; penalty?: number; scoreAfter?: number; tierAfter?: string }> {
  const contract = await getDlsmContract();

  const result = await contract.submitTransaction(
    'SubmitPromptRisk',
    userId,
    conversationId,
    promptHash,
    String(riskScore)
  );

  return JSON.parse(Buffer.from(result).toString('utf8'));
}

async function evaluatePrompt(
  request: EvaluationRequest,
  conversation: ConversationState
): Promise<GatewayEvaluation> {
  const promptHash = hashPrompt(request.prompt);

  const classifier = await classifierClient.classify({
    promptId: request.requestId,
    userId: request.userId,
    orgId: request.orgId,
    prompt: request.prompt,
    promptHash,
    conversationId: conversation.conversationId,
    history: conversation.history
  });

  const policy = decide(classifier.riskScore);
  let eventId: string | undefined;
  let adjustment: unknown;
  let sessionRisk: number | undefined;
  let multiTurnDetected = false;

  // Submit the per-turn risk to the on-chain sliding window. The ledger is
  // authoritative: if the aggregated session risk breaches τ_critical, the
  // chaincode records a Multi-Turn Subversion incident, applies the p=35
  // penalty, terminates the session and returns verdict 'block'.
  const session = await submitSessionRisk(
    request.userId,
    conversation.conversationId,
    promptHash,
    classifier.riskScore
  );

  sessionRisk = session.sessionRisk;

  if (session.verdict === 'block') {
    conversation.terminated = true;
    eventId = session.breachEventId;
    adjustment = {
      scoreAfter: session.scoreAfter,
      tierAfter: session.tierAfter,
      penalty: session.penalty
    };
    multiTurnDetected = true;

    return {
      requestId: request.requestId,
      userId: request.userId,
      orgId: request.orgId,
      promptHash,
      conversationId: conversation.conversationId,
      classifier,
      sessionRisk,
      multiTurnDetected,
      riskLevel: 'critical',
      gatewayDecision: 'block',
      eventId,
      adjustment
    };
  }

  if (policy.gatewayDecision !== 'allow') {
    eventId = await recordSecurityEvent(
      request,
      promptHash,
      classifier,
      policy.riskLevel,
      policy.gatewayDecision
    );

    adjustment = await applyReputationAdjustment(request.userId, eventId);
  }

  return {
    requestId: request.requestId,
    userId: request.userId,
    orgId: request.orgId,
    promptHash,
    conversationId: conversation.conversationId,
    classifier,
    sessionRisk,
    multiTurnDetected,
    ...policy,
    eventId,
    adjustment
  };
}

function chatStatus(decision: GatewayDecision): ChatStatus {
  if (decision === 'block') {
    return 'blocked';
  }

  if (decision === 'review') {
    return 'warned';
  }

  return 'forwarded';
}

app.get('/', async (_request, reply) => {
  const html = await readPublicFile('index.html');
  return reply.type('text/html; charset=utf-8').send(html);
});

app.get('/ui/styles.css', async (_request, reply) => {
  const css = await readPublicFile('styles.css');
  return reply.type('text/css; charset=utf-8').send(css);
});

app.get('/ui/app.js', async (_request, reply) => {
  const js = await readPublicFile('app.js');
  return reply.type('application/javascript; charset=utf-8').send(js);
});

app.get('/health', async () => {
  return {
    service: 'dlsm-gateway',
    status: 'ok',
    classifierMode: process.env.CLASSIFIER_MODE ?? 'mock',
    llmMode: process.env.LLM_MODE ?? 'mock'
  };
});

app.post('/v1/users/register', {
  schema: {
    body: {
      type: 'object',
      additionalProperties: false,
      required: ['userId', 'orgId', 'role'],
      properties: {
        userId: { type: 'string', minLength: 1 },
        orgId: { type: 'string', minLength: 1 },
        role: {
          type: 'string',
          enum: ['Admin', 'Manager', 'Developer', 'General']
        }
      }
    }
  }
}, async (request) => {
  const body = request.body as {
    userId: string;
    orgId: string;
    role: 'Admin' | 'Manager' | 'Developer' | 'General';
  };
  const contract = await getDlsmContract();

  try {
    await contract.submitTransaction(
      'RegisterUser',
      body.userId,
      body.orgId,
      body.role
    );
  } catch (error) {
    if (!isAlreadyExists(error)) {
      throw error;
    }
  }

  const result = await contract.evaluateTransaction(
    'GetUserReputation',
    body.userId
  );

  return JSON.parse(Buffer.from(result).toString('utf8'));
});

app.get('/v1/reputation/:userId', {
  schema: {
    params: {
      type: 'object',
      required: ['userId'],
      properties: {
        userId: { type: 'string', minLength: 1 }
      }
    }
  }
}, async (request) => {
  const { userId } = request.params as { userId: string };
  const contract = await getDlsmContract();

  const result = await contract.evaluateTransaction(
    'GetUserReputation',
    userId
  );

  return JSON.parse(Buffer.from(result).toString('utf8'));
});

app.get('/v1/incidents/:userId/:eventId', async (request) => {
  const { userId, eventId } = request.params as {
    userId: string;
    eventId: string;
  };

  const contract = await getDlsmContract();

  const result = await contract.evaluateTransaction(
    'GetSecurityEvent',
    userId,
    eventId
  );

  return JSON.parse(Buffer.from(result).toString('utf8'));
});

app.get(
  '/v1/reputation/:userId/events/:eventId/adjustment',
  async (request) => {
    const { userId, eventId } = request.params as {
      userId: string;
      eventId: string;
    };

    const contract = await getDlsmContract();

    const result = await contract.evaluateTransaction(
      'GetReputationAdjustment',
      userId,
      eventId
    );

    return JSON.parse(Buffer.from(result).toString('utf8'));
  }
);

app.post('/v1/gateway/evaluate', {
  schema: {
    body: {
      type: 'object',
      additionalProperties: false,
      required: ['requestId', 'userId', 'orgId', 'prompt'],
      properties: {
        requestId: { type: 'string', minLength: 1 },
        userId: { type: 'string', minLength: 1 },
        orgId: { type: 'string', minLength: 1 },
        prompt: { type: 'string', minLength: 1 },
        conversationId: { type: 'string', minLength: 1 }
      }
    }
  }
}, async (request) => {
  const body = request.body as EvaluationRequest & { conversationId?: string };
  const conversation = getConversation(body.userId, body.conversationId);
  const evaluation = await evaluatePrompt(body, conversation);
  appendHistory(conversation, body.prompt);

  return evaluation;
});

app.post('/v1/gateway/chat', {
  schema: {
    body: {
      type: 'object',
      additionalProperties: false,
      required: ['userId', 'orgId', 'prompt'],
      properties: {
        requestId: { type: 'string', minLength: 1 },
        userId: { type: 'string', minLength: 1 },
        orgId: { type: 'string', minLength: 1 },
        prompt: { type: 'string', minLength: 1 },
        conversationId: { type: 'string', minLength: 1 }
      }
    }
  }
}, async (request) => {
  const body = request.body as ChatRequest;
  const conversation = getConversation(body.userId, body.conversationId);
  const evaluationRequest: EvaluationRequest = {
    requestId: body.requestId ?? createRequestId(),
    userId: body.userId,
    orgId: body.orgId,
    prompt: body.prompt
  };

  const evaluation = await evaluatePrompt(evaluationRequest, conversation);
  const status = chatStatus(evaluation.gatewayDecision);
  let llm: LlmResult | undefined;
  let responseMessage: string;

  if (evaluation.gatewayDecision === 'block') {
    responseMessage = evaluation.multiTurnDetected
      ? 'Blocked by DLSM: a multi-turn jailbreak pattern was detected across this conversation (aggregated session risk breached the critical threshold) and the session was terminated.'
      : 'Blocked by DLSM: this prompt was classified as high-risk and was not forwarded to the LLM service.';
  } else {
    llm = await llmClient.complete(evaluationRequest);
    responseMessage = evaluation.gatewayDecision === 'review'
      ? `Warning: this request was flagged for review, but the demo policy allowed a limited LLM response. ${llm.answer}`
      : llm.answer;
  }

  appendHistory(conversation, body.prompt);

  return {
    ...evaluation,
    chatStatus: status,
    forwardedToLlm: evaluation.gatewayDecision !== 'block',
    llm,
    responseMessage
  };
});

app.post(
  '/internal/v1/reputation/:userId/events/:eventId/apply',
  async (request) => {
    const { userId, eventId } = request.params as {
      userId: string;
      eventId: string;
    };

    return applyReputationAdjustment(userId, eventId);
  }
);

app.addHook('onClose', async () => {
  await closeFabricConnection();
});

const port = Number(process.env.PORT ?? 3000);

try {
  await app.listen({ host: '127.0.0.1', port });
} catch (error) {
  app.log.error(error);
  process.exit(1);
}
