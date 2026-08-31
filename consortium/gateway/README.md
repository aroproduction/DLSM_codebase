# DLSM Gateway Workspace

The gateway is the service that sits before the target LLM.

## Responsibility

The gateway will:

1. Receive a user prompt.
2. Call the classifier service or mock classifier.
3. Apply policy and risk calibration.
4. Decide allow, warn, restrict, or block.
5. Submit incidents and reputation updates to Fabric.
6. Forward safe prompts to the LLM.

## First Prototype Flow

```text
Prompt
  -> Gateway
  -> Mock Classifier
  -> Policy Layer
  -> Fabric Chaincode
  -> Decision
```

The gateway should be able to work before the real ML classifier exists.

## Planned Endpoints

```text
POST /v1/gateway/evaluate
GET  /v1/reputation/:userId
GET  /v1/incidents/:incidentId
GET  /v1/threats/:promptHash
```

