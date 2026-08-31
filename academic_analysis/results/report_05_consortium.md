# Consortium & On-Chain Auditability Analysis

## Gateway identity & consortium membership

| field | value |
|---|---|
| mspid | Org1MSP |
| identity name | dlsm-gateway@org1.example.com |

The gateway signs every chaincode transaction with a Fabric identity from org1 (Org1MSP, identity `dlsm-gateway@org1.example.com`), so it is a recognized member of the consortium rather than an anonymous client.

## Audit trail (per incident)

| incident | decision | class | risk | session risk | penalty | event id | score after | tier after |
|---|---|---|---|---|---|---|---|---|
| jailbreak_attempt | block | prompt_injection | 0.9979 | 0.9979 | 30 | evt-acad-cons-000 | 50 | Monitored |
| prompt_injection | block | prompt_injection | 0.9969 | 0.9969 | 30 | evt-acad-cons-001 | 20 | ReadOnly |
| data_extraction | block | harmful_content | 0.992 | 0.992 | 25 | evt-acad-cons-002 | 0 | Suspended |
| policy_infraction | block | harmful_content | 0.9981 | 0.9981 | 25 | evt-acad-cons-003 | 0 | Suspended |
| multi_turn_subversion | block | harmful_content | 0.9985 | 2.436196 | 35 | evt-mt-acad-cons-mt-3 | 0 | Suspended |

Prompt hashes present: True — unique: True. Prompt content itself is never stored on-chain; only its SHA-256 digest, preserving data privacy while keeping the audit immutable.

![Penalties recorded on-chain by incident class.](figures/fig_consortium_penalties.png)

*Penalties recorded on-chain by incident class.*

![Cumulative reputation impact visible to all consortium members.](figures/fig_consortium_reputation_impact.png)

*Cumulative reputation impact visible to all consortium members.*

## On-chain state (user reputation readback)

| field | value |
|---|---|
| current score | 0 |
| current tier | Suspended |
| incident count | 7 |
| incident event ids | evt-acad-cons-000, evt-acad-cons-001, evt-acad-cons-002, evt-acad-cons-003, evt-acad-cons-mt-00, evt-acad-cons-mt-01, evt-mt-acad-cons-mt-3 |
| applied penalties | evt-acad-cons-000=30; evt-acad-cons-001=30; evt-acad-cons-002=25; evt-acad-cons-003=25; evt-acad-cons-mt-00=30; evt-acad-cons-mt-01=25; evt-mt-acad-cons-mt-3=35 |

## Immutability & transparency

Every prompt evaluation is a SubmitPromptRisk chaincode invocation → the state (risk score, session risk, penalty, tier) is part of the Fabric ledger, readable by any consortium member. This gives the consortium shared situational awareness that a monolithic API gateway cannot provide.
