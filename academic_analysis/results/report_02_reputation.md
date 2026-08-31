# Reputation Model & Risk-Scoring Analysis

## Role base scores (paper Table 3)

| role | base score | live registered | tier | match |
|---|---|---|---|---|
| Admin | 100 | 100 | Trusted | True |
| Manager | 90 | 90 | Trusted | True |
| Developer | 80 | 80 | Standard | True |
| General | 70 | 70 | Standard | True |

## Penalty decay (paper Eq. 2/3)

λ = ln(2)/T½ = 0.0231 with T½ = 30 days. A 30-pt jailbreak penalty decays to ~50% after 30 days and ~12% after 90.

![Active penalty points decay over time for each incident class.](figures/fig_penalty_decay.png)

*Active penalty points decay over time for each incident class.*

## Scenario A — Alice recovery (paper worked example)

| step | score |
|---|---|
| breach -5 | 65.0 |
| warning +5 | 70.0 |
| retraining +15 | 86.0 |
| time-decay (day 35) | 88.0 |
| streak +2 (100 safe prompts) | 90.0 |

![Alice's reputation trajectory: breach, acknowledgment, retraining, decay, streak.](figures/fig_scenario_a.png)

*Alice's reputation trajectory: breach, acknowledgment, retraining, decay, streak.*

## Scenario B — Bob multi-turn breach (paper worked example)

| field | value |
|---|---|
| base | 80.0 |
| penalty | 35 |
| score after | 45.0 |
| tier after | Restricted |

![Bob's reputation collapse on multi-turn subversion.](figures/fig_scenario_b.png)

*Bob's reputation collapse on multi-turn subversion.*

## Live repeated-attack degradation

| attack # | score | tier |
|---|---|---|
| 0 | 80 | Standard |
| 1 | 50 | Monitored |
| 2 | 20 | ReadOnly |
| 3 | 0 | Suspended |
| 4 | 0 | Suspended |
| 5 | 0 | Suspended |

![On-chain reputation drop under repeated attacks (monotonic decay enforced).](figures/fig_live_degradation.png)

*On-chain reputation drop under repeated attacks (monotonic decay enforced).*
