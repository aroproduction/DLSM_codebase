"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DLSMContract = void 0;
const fabric_contract_api_1 = require("fabric-contract-api");
// ---------------------------------------------------------------------------
// Multi-turn sliding-window parameters (paper Section 3.3, Equation 4)
// ---------------------------------------------------------------------------
const WINDOW_W = 5; // sliding window size
const ALPHA = 0.8; // session forgetting factor
const TAU_CRITICAL = 2.0; // critical aggregated session risk threshold
const PENALTY_HALF_LIFE_DAYS = 30; // T_1/2 for exponential forgiveness decay
const LAMBDA = Math.LN2 / PENALTY_HALF_LIFE_DAYS; // ≈ 0.0231 (paper Eq 3)
// Fixed-point scale used for all on-chain math to keep endorser results
// deterministic (endorsers run identical binaries, so IEEE-754 ops agree).
const SCALE = 1000000;
// Incident penalty table (paper Table 4). Penalties are applied negatively.
const INCIDENT_PENALTY = {
    multi_turn_subversion: 35, // Class 1 — aggregated multi-prompt safety violation
    successful_jailbreak: 30, // Class 1 — direct prompt injection / safety bypass
    jailbreak_attempt: 30, // Class 1 — alias
    prompt_injection: 30, // Class 1 — alias
    data_extraction: 25, // Class 2 — context exfiltration, credentials, PII
    privacy_abuse: 25, // Class 2 — alias
    operational_abuse: 25, // Class 3 — quota bypass, floods, unauthorized calls
    policy_evasion: 25, // Class 3 — alias
    suspicious_heuristic: 15, // Class 1/2/3 — adversarial suffix / heuristic match
    policy_infraction: 5, // Class 4 — minor administrative non-compliance
};
// Fallback grid for categories not covered by the paper table (preserves the
// legacy behavior for e.g. 'harmful_content' single-turn blocks).
const FALLBACK_GRID = {
    allow: { low: 0, medium: 0, high: 0, critical: 0 },
    review: { low: -5, medium: -10, high: -15, critical: -25 },
    block: { low: -5, medium: -15, high: -25, critical: -40 },
};
// Reward points (paper Table 3).
const REWARD_POINTS = {
    good_behavior_streak: 2, // capped total of +20 from streaks
    warning_acknowledged: 5,
    security_retraining: 15,
};
const STREAK_REWARD_CAP = 20;
let DLSMContract = class DLSMContract extends fabric_contract_api_1.Contract {
    getBaseScore(role) {
        switch (role) {
            case 'Admin':
                return 100;
            case 'Manager':
                return 90;
            case 'Developer':
                return 80;
            case 'General':
                return 70;
            default:
                throw new Error(`Unsupported role: ${role}`);
        }
    }
    getAccessTier(score) {
        if (score >= 90) {
            return 'Trusted';
        }
        if (score >= 70) {
            return 'Standard';
        }
        if (score >= 50) {
            return 'Monitored';
        }
        if (score >= 30) {
            return 'Restricted';
        }
        if (score >= 10) {
            return 'ReadOnly';
        }
        return 'Suspended';
    }
    userKey(userId) {
        return `USER_REPUTATION_${userId}`;
    }
    sessionKey(ctx, userId, conversationId) {
        return ctx.stub.createCompositeKey('sessionRisk', [userId, conversationId]);
    }
    assertGatewayCaller(ctx) {
        const callerMsp = ctx.clientIdentity.getMSPID();
        const callerRole = ctx.clientIdentity.getAttributeValue('role');
        if (callerMsp !== 'Org1MSP' || callerRole !== 'gateway') {
            throw new Error('Only the authorized DLSM gateway identity can record security outcomes');
        }
    }
    securityEventKey(ctx, userId, eventId) {
        return ctx.stub.createCompositeKey('securityEvent', [userId, eventId]);
    }
    reputationAdjustmentKey(ctx, userId, eventId) {
        return ctx.stub.createCompositeKey('reputationAdjustment', [userId, eventId]);
    }
    transactionTimestamp(ctx) {
        const timestamp = ctx.stub.getTxTimestamp();
        const seconds = Number(timestamp.seconds.toString());
        const millis = seconds * 1000 + Math.floor(timestamp.nanos / 1000000);
        return { iso: new Date(millis).toISOString(), millis };
    }
    /**
     * Time-decayed penalty impact P(t) = Σ p_i · e^(−λ·Δt_i) (paper Eq 2).
     * λ = ln(2)/T_1/2 (paper Eq 3). Fixed-point integer math (scale 10^6)
     * keeps the result identical across endorsing peers.
     */
    decayedPenaltySum(incidents, nowMillis) {
        let totalScaled = 0;
        for (const incident of incidents) {
            const deltaDays = (nowMillis - incident.appliedAtMillis) / 86400000;
            const decay = Math.exp(-LAMBDA * Math.max(0, deltaDays));
            totalScaled += Math.round(incident.penalty * SCALE * decay);
        }
        return Math.round(totalScaled / SCALE);
    }
    /**
     * Dynamic reputation score S(t) = max(0, min(100, S_base + R(t) − P(t)))
     * (paper Eq 1), evaluated at the given block time.
     */
    computeScore(user, nowMillis) {
        const penalty = this.decayedPenaltySum(user.incidents, nowMillis);
        const score = user.baseScore + user.totalRewards - penalty;
        return Math.max(0, Math.min(100, score));
    }
    /**
     * Aggregated session risk over the sliding window:
     * C_current = Σ_{j=1..m} α^(m−j) · x_j  (paper Eq 4).
     * Newest turn has weight α^0; the window slides by dropping the oldest turn
     * once it exceeds W. Computed in fixed point for determinism.
     */
    aggregateSessionRisk(turns) {
        const m = turns.length;
        if (m === 0) {
            return 0;
        }
        let totalScaled = 0;
        for (let j = 0; j < m; j += 1) {
            const age = m - 1 - j; // 0 for newest turn
            const weightScaled = Math.round(Math.pow(ALPHA, age) * SCALE);
            const riskScaled = Math.round(turns[j].riskScore * SCALE);
            totalScaled += Math.round((weightScaled * riskScaled) / SCALE);
        }
        return totalScaled / SCALE;
    }
    penaltyFor(event) {
        const table = INCIDENT_PENALTY[event.attackCategory];
        if (table !== undefined) {
            return -table;
        }
        const fallback = FALLBACK_GRID[event.gatewayDecision][event.riskLevel];
        return fallback;
    }
    classForCategory(attackCategory) {
        switch (attackCategory) {
            case 'multi_turn_subversion':
            case 'successful_jailbreak':
            case 'jailbreak_attempt':
            case 'prompt_injection':
            case 'suspicious_heuristic':
                return 'class_1';
            case 'data_extraction':
            case 'privacy_abuse':
                return 'class_2';
            case 'operational_abuse':
            case 'policy_evasion':
                return 'class_3';
            case 'policy_infraction':
                return 'class_4';
            default:
                return 'class_1';
        }
    }
    // -------------------------------------------------------------------------
    // User registration
    // -------------------------------------------------------------------------
    async RegisterUser(ctx, userId, orgId, role) {
        const key = this.userKey(userId);
        const existing = await ctx.stub.getState(key);
        if (existing && existing.length > 0) {
            throw new Error(`User already exists: ${userId}`);
        }
        const baseScore = this.getBaseScore(role);
        const now = this.transactionTimestamp(ctx);
        const user = {
            docType: 'userReputation',
            userId,
            orgId,
            role,
            baseScore,
            currentScore: baseScore,
            currentTier: this.getAccessTier(baseScore),
            totalRewards: 0,
            streakReward: 0,
            incidentIds: [],
            incidents: [],
            rewards: [],
            createdAt: now.iso,
            updatedAt: now.iso
        };
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(user)));
    }
    // -------------------------------------------------------------------------
    // Security events
    // -------------------------------------------------------------------------
    async RecordSecurityEvent(ctx, eventId, userId, requestId, promptHash, riskLevel, attackCategory, modelVersion, gatewayDecision, interactionClass) {
        this.assertGatewayCaller(ctx);
        if (!['low', 'medium', 'high', 'critical'].includes(riskLevel)) {
            throw new Error(`Unsupported risk level: ${riskLevel}`);
        }
        if (!['allow', 'review', 'block'].includes(gatewayDecision)) {
            throw new Error(`Unsupported gateway decision: ${gatewayDecision}`);
        }
        if (!/^[a-fA-F0-9]{64}$/.test(promptHash)) {
            throw new Error('promptHash must be a SHA-256 hexadecimal hash');
        }
        const userKey = this.userKey(userId);
        const userBytes = await ctx.stub.getState(userKey);
        if (!userBytes || userBytes.length === 0) {
            throw new Error(`User does not exist: ${userId}`);
        }
        const eventKey = this.securityEventKey(ctx, userId, eventId);
        const existingEvent = await ctx.stub.getState(eventKey);
        if (existingEvent && existingEvent.length > 0) {
            throw new Error(`Security event already exists: ${eventId}`);
        }
        const now = this.transactionTimestamp(ctx);
        const cls = (interactionClass === 'class_1' ||
            interactionClass === 'class_2' ||
            interactionClass === 'class_3' ||
            interactionClass === 'class_4') ? interactionClass : this.classForCategory(attackCategory);
        const event = {
            docType: 'securityEvent',
            eventId,
            userId,
            requestId,
            promptHash,
            interactionClass: cls,
            riskLevel,
            attackCategory,
            modelVersion,
            gatewayDecision,
            recordedAt: now.iso,
            transactionId: ctx.stub.getTxID(),
            submittedByMsp: ctx.clientIdentity.getMSPID(),
            submittedClientId: ctx.clientIdentity.getID()
        };
        await ctx.stub.putState(eventKey, Buffer.from(JSON.stringify(event)));
        if (gatewayDecision !== 'allow') {
            const user = JSON.parse(userBytes.toString());
            user.incidentIds.push(eventId);
            user.updatedAt = now.iso;
            await ctx.stub.putState(userKey, Buffer.from(JSON.stringify(user)));
        }
        ctx.stub.setEvent('SecurityEventRecorded', Buffer.from(JSON.stringify(event)));
    }
    // -------------------------------------------------------------------------
    // Reputation adjustments (decayed, paper Eq 1-3)
    // -------------------------------------------------------------------------
    async ApplyReputationAdjustment(ctx, userId, eventId) {
        this.assertGatewayCaller(ctx);
        const eventKey = this.securityEventKey(ctx, userId, eventId);
        const eventBytes = await ctx.stub.getState(eventKey);
        if (!eventBytes || eventBytes.length === 0) {
            throw new Error(`Security event does not exist: ${eventId}`);
        }
        const adjustmentKey = this.reputationAdjustmentKey(ctx, userId, eventId);
        const existingAdjustment = await ctx.stub.getState(adjustmentKey);
        if (existingAdjustment && existingAdjustment.length > 0) {
            throw new Error(`Reputation adjustment already exists for: ${eventId}`);
        }
        const userKey = this.userKey(userId);
        const userBytes = await ctx.stub.getState(userKey);
        if (!userBytes || userBytes.length === 0) {
            throw new Error(`User does not exist: ${userId}`);
        }
        const event = JSON.parse(eventBytes.toString());
        const user = JSON.parse(userBytes.toString());
        const scoreDelta = this.penaltyFor(event);
        const now = this.transactionTimestamp(ctx);
        const scoreBefore = this.computeScore(user, now.millis);
        const tierBefore = this.getAccessTier(scoreBefore);
        user.incidents.push({
            eventId,
            penalty: Math.abs(scoreDelta),
            appliedAt: now.iso,
            appliedAtMillis: now.millis
        });
        const scoreAfter = this.computeScore(user, now.millis);
        const tierAfter = this.getAccessTier(scoreAfter);
        user.currentScore = scoreAfter;
        user.currentTier = tierAfter;
        user.updatedAt = now.iso;
        const adjustment = {
            docType: 'reputationAdjustment',
            adjustmentId: `ADJ_${eventId}`,
            eventId,
            userId,
            scoreDelta,
            scoreBefore,
            scoreAfter,
            tierBefore,
            tierAfter,
            policyVersion: 'reputation-policy-v2',
            appliedAt: now.iso,
            transactionId: ctx.stub.getTxID()
        };
        await ctx.stub.putState(userKey, Buffer.from(JSON.stringify(user)));
        await ctx.stub.putState(adjustmentKey, Buffer.from(JSON.stringify(adjustment)));
        ctx.stub.setEvent('ReputationAdjusted', Buffer.from(JSON.stringify(adjustment)));
    }
    // -------------------------------------------------------------------------
    // Behavioral rewards (paper Table 3)
    // -------------------------------------------------------------------------
    async ApplyReward(ctx, userId, reason) {
        this.assertGatewayCaller(ctx);
        const points = REWARD_POINTS[reason];
        if (points === undefined) {
            throw new Error(`Unsupported reward reason: ${reason}`);
        }
        const userKey = this.userKey(userId);
        const userBytes = await ctx.stub.getState(userKey);
        if (!userBytes || userBytes.length === 0) {
            throw new Error(`User does not exist: ${userId}`);
        }
        const user = JSON.parse(userBytes.toString());
        const now = this.transactionTimestamp(ctx);
        let granted = points;
        if (reason === 'good_behavior_streak') {
            const capRemaining = STREAK_REWARD_CAP - user.streakReward;
            granted = Math.min(points, Math.max(0, capRemaining));
            user.streakReward += granted;
        }
        user.totalRewards += granted;
        user.rewards.push({ reason, points: granted, appliedAt: now.iso });
        user.currentScore = this.computeScore(user, now.millis);
        user.currentTier = this.getAccessTier(user.currentScore);
        user.updatedAt = now.iso;
        await ctx.stub.putState(userKey, Buffer.from(JSON.stringify(user)));
        const result = { reason, granted, totalRewards: user.totalRewards };
        ctx.stub.setEvent('RewardApplied', Buffer.from(JSON.stringify(result)));
        return JSON.stringify(result);
    }
    // -------------------------------------------------------------------------
    // Multi-turn sliding-window detection (paper Section 3.3, Eq 4, Scenario B)
    // -------------------------------------------------------------------------
    async SubmitPromptRisk(ctx, userId, conversationId, promptHash, riskScore) {
        var _a, _b, _c;
        this.assertGatewayCaller(ctx);
        if (!/^[a-fA-F0-9]{64}$/.test(promptHash)) {
            throw new Error('promptHash must be a SHA-256 hexadecimal hash');
        }
        if (!(riskScore >= 0 && riskScore <= 1)) {
            throw new Error(`riskScore must be in [0, 1], got ${riskScore}`);
        }
        const userKey = this.userKey(userId);
        const userBytes = await ctx.stub.getState(userKey);
        if (!userBytes || userBytes.length === 0) {
            throw new Error(`User does not exist: ${userId}`);
        }
        const now = this.transactionTimestamp(ctx);
        const key = this.sessionKey(ctx, userId, conversationId);
        const existingBytes = await ctx.stub.getState(key);
        let window;
        if (existingBytes && existingBytes.length > 0) {
            window = JSON.parse(existingBytes.toString());
        }
        else {
            window = {
                docType: 'conversationWindow',
                userId,
                conversationId,
                turns: [],
                currentRisk: 0,
                status: 'active',
                updatedAt: now.iso
            };
        }
        if (window.status === 'terminated') {
            return JSON.stringify({
                verdict: 'block',
                conversationId,
                sessionRisk: window.currentRisk,
                status: 'terminated',
                breachEventId: window.breachEventId,
                penalty: (_a = window.breachPenalty) !== null && _a !== void 0 ? _a : 0,
                scoreAfter: (_b = window.breachScoreAfter) !== null && _b !== void 0 ? _b : 0,
                tierAfter: (_c = window.breachTierAfter) !== null && _c !== void 0 ? _c : ''
            });
        }
        const nextTurn = window.turns.length + 1;
        window.turns.push({
            turn: nextTurn,
            promptHash,
            riskScore,
            timestamp: now.iso
        });
        while (window.turns.length > WINDOW_W) {
            window.turns.shift();
        }
        const currentRisk = this.aggregateSessionRisk(window.turns);
        window.currentRisk = Math.round(currentRisk * SCALE) / SCALE;
        window.updatedAt = now.iso;
        if (currentRisk < TAU_CRITICAL) {
            await ctx.stub.putState(key, Buffer.from(JSON.stringify(window)));
            ctx.stub.setEvent('SessionRiskUpdated', Buffer.from(JSON.stringify({ userId, conversationId, currentRisk })));
            return JSON.stringify({
                verdict: 'allow',
                conversationId,
                sessionRisk: window.currentRisk,
                status: window.status
            });
        }
        // --- breach: τ_critical exceeded -> Multi-Turn Subversion incident -------
        window.status = 'terminated';
        window.breachedAt = now.iso;
        const eventId = `evt-mt-${conversationId}-${nextTurn}`;
        const eventKey = this.securityEventKey(ctx, userId, eventId);
        const existingEvent = await ctx.stub.getState(eventKey);
        if (existingEvent && existingEvent.length > 0) {
            throw new Error(`Multi-turn security event already exists: ${eventId}`);
        }
        const event = {
            docType: 'securityEvent',
            eventId,
            userId,
            requestId: `req-${conversationId}-${nextTurn}`,
            promptHash,
            interactionClass: 'class_1',
            riskLevel: 'critical',
            attackCategory: 'multi_turn_subversion',
            modelVersion: 'dlsm-window-v1',
            gatewayDecision: 'block',
            recordedAt: now.iso,
            transactionId: ctx.stub.getTxID(),
            submittedByMsp: ctx.clientIdentity.getMSPID(),
            submittedClientId: ctx.clientIdentity.getID()
        };
        window.breachEventId = eventId;
        await ctx.stub.putState(eventKey, Buffer.from(JSON.stringify(event)));
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(window)));
        const user = JSON.parse(userBytes.toString());
        user.incidentIds.push(eventId);
        user.incidents.push({
            eventId,
            penalty: INCIDENT_PENALTY.multi_turn_subversion,
            appliedAt: now.iso,
            appliedAtMillis: now.millis
        });
        user.currentScore = this.computeScore(user, now.millis);
        user.currentTier = this.getAccessTier(user.currentScore);
        user.updatedAt = now.iso;
        window.breachPenalty = INCIDENT_PENALTY.multi_turn_subversion;
        window.breachScoreAfter = user.currentScore;
        window.breachTierAfter = user.currentTier;
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(window)));
        const adjustment = {
            docType: 'reputationAdjustment',
            adjustmentId: `ADJ_${eventId}`,
            eventId,
            userId,
            scoreDelta: -INCIDENT_PENALTY.multi_turn_subversion,
            scoreBefore: this.computeScore({ ...user, incidents: user.incidents.slice(0, -1) }, now.millis),
            scoreAfter: user.currentScore,
            tierBefore: this.getAccessTier(this.computeScore({ ...user, incidents: user.incidents.slice(0, -1) }, now.millis)),
            tierAfter: user.currentTier,
            policyVersion: 'reputation-policy-v2',
            appliedAt: now.iso,
            transactionId: ctx.stub.getTxID()
        };
        await ctx.stub.putState(userKey, Buffer.from(JSON.stringify(user)));
        await ctx.stub.putState(this.reputationAdjustmentKey(ctx, userId, eventId), Buffer.from(JSON.stringify(adjustment)));
        ctx.stub.setEvent('MultiTurnSubversionDetected', Buffer.from(JSON.stringify({
            eventId,
            userId,
            conversationId,
            sessionRisk: window.currentRisk,
            threshold: TAU_CRITICAL,
            turns: window.turns.map(t => t.riskScore),
            penalty: INCIDENT_PENALTY.multi_turn_subversion,
            scoreAfter: user.currentScore,
            tierAfter: user.currentTier
        })));
        return JSON.stringify({
            verdict: 'block',
            conversationId,
            sessionRisk: window.currentRisk,
            status: 'terminated',
            breachEventId: eventId,
            penalty: INCIDENT_PENALTY.multi_turn_subversion,
            scoreAfter: user.currentScore,
            tierAfter: user.currentTier
        });
    }
    // -------------------------------------------------------------------------
    // Queries
    // -------------------------------------------------------------------------
    async GetSecurityEvent(ctx, userId, eventId) {
        const eventKey = this.securityEventKey(ctx, userId, eventId);
        const eventBytes = await ctx.stub.getState(eventKey);
        if (!eventBytes || eventBytes.length === 0) {
            throw new Error(`Security event does not exist: ${eventId}`);
        }
        return eventBytes.toString();
    }
    async GetReputationAdjustment(ctx, userId, eventId) {
        const adjustmentKey = this.reputationAdjustmentKey(ctx, userId, eventId);
        const adjustmentBytes = await ctx.stub.getState(adjustmentKey);
        if (!adjustmentBytes || adjustmentBytes.length === 0) {
            throw new Error(`Reputation adjustment does not exist for event: ${eventId}`);
        }
        return adjustmentBytes.toString();
    }
    async GetUserReputation(ctx, userId) {
        const key = this.userKey(userId);
        const data = await ctx.stub.getState(key);
        if (!data || data.length === 0) {
            throw new Error(`User does not exist: ${userId}`);
        }
        const user = JSON.parse(data.toString());
        const now = this.transactionTimestamp(ctx);
        const score = this.computeScore(user, now.millis);
        user.currentScore = score;
        user.currentTier = this.getAccessTier(score);
        return JSON.stringify(user);
    }
    async GetSessionRisk(ctx, userId, conversationId) {
        const key = this.sessionKey(ctx, userId, conversationId);
        const data = await ctx.stub.getState(key);
        if (!data || data.length === 0) {
            throw new Error(`Conversation window does not exist: ${userId}/${conversationId}`);
        }
        return data.toString();
    }
};
exports.DLSMContract = DLSMContract;
__decorate([
    (0, fabric_contract_api_1.Transaction)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [fabric_contract_api_1.Context, String, String, String]),
    __metadata("design:returntype", Promise)
], DLSMContract.prototype, "RegisterUser", null);
__decorate([
    (0, fabric_contract_api_1.Transaction)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [fabric_contract_api_1.Context, String, String, String, String, String, String, String, String, String]),
    __metadata("design:returntype", Promise)
], DLSMContract.prototype, "RecordSecurityEvent", null);
__decorate([
    (0, fabric_contract_api_1.Transaction)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [fabric_contract_api_1.Context, String, String]),
    __metadata("design:returntype", Promise)
], DLSMContract.prototype, "ApplyReputationAdjustment", null);
__decorate([
    (0, fabric_contract_api_1.Transaction)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [fabric_contract_api_1.Context, String, String]),
    __metadata("design:returntype", Promise)
], DLSMContract.prototype, "ApplyReward", null);
__decorate([
    (0, fabric_contract_api_1.Transaction)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [fabric_contract_api_1.Context, String, String, String, Number]),
    __metadata("design:returntype", Promise)
], DLSMContract.prototype, "SubmitPromptRisk", null);
__decorate([
    (0, fabric_contract_api_1.Transaction)(false),
    (0, fabric_contract_api_1.Returns)('string'),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [fabric_contract_api_1.Context, String, String]),
    __metadata("design:returntype", Promise)
], DLSMContract.prototype, "GetSecurityEvent", null);
__decorate([
    (0, fabric_contract_api_1.Transaction)(false),
    (0, fabric_contract_api_1.Returns)('string'),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [fabric_contract_api_1.Context, String, String]),
    __metadata("design:returntype", Promise)
], DLSMContract.prototype, "GetReputationAdjustment", null);
__decorate([
    (0, fabric_contract_api_1.Transaction)(false),
    (0, fabric_contract_api_1.Returns)('string'),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [fabric_contract_api_1.Context, String]),
    __metadata("design:returntype", Promise)
], DLSMContract.prototype, "GetUserReputation", null);
__decorate([
    (0, fabric_contract_api_1.Transaction)(false),
    (0, fabric_contract_api_1.Returns)('string'),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [fabric_contract_api_1.Context, String, String]),
    __metadata("design:returntype", Promise)
], DLSMContract.prototype, "GetSessionRisk", null);
exports.DLSMContract = DLSMContract = __decorate([
    (0, fabric_contract_api_1.Info)({
        title: 'DLSMContract',
        description: 'Reputation, access-control and multi-turn jailbreak detection chaincode for DLSM'
    })
], DLSMContract);
