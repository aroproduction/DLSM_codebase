# DLSM Evaluation Datasets

This directory contains the hand-curated benchmark datasets used in the DLSM paper evaluation.

## Dataset 1: Live Gateway Classifier Suite

**File:** `live_gateway_suite.json`

**Description:** 118 prompts for evaluating the DLSM dual-stage classifier in a live end-to-end setting.

**Composition:**
- 78 attack prompts across 9 threat categories
- 40 benign prompts
- 3 multi-turn crescendo scenarios

**Categories:**
| Category | Count | Type |
|----------|-------|------|
| obvious_jailbreak | 20 | Class 1 |
| encoding_obfuscation | 9 | Class 1 |
| token_smuggling | 8 | Class 1 |
| roleplay_persona | 7 | Class 1 |
| multi_turn_simulation | 10 | Class 1 |
| coercion_threats | 5 | Class 1 |
| sophisticated_academic_framing | 4 | Class 1 |
| sophisticated_narrative_wrapping | 7 | Class 1 |
| system_override_authority | 8 | Class 1 |
| benign | 40 | Class 4 |

**Evaluation Method:** Zero-shot prompt classification — each prompt is evaluated independently with no few-shot examples.

---

## Dataset 2: Multi-Role Policy Enforcement Suite

**File:** `multi_role_policy_suite.json`

**Description:** 48 prompt-role combinations (12 prompts × 4 roles) for evaluating reputation-based access control enforcement.

**Composition:**
- 12 prompt categories (5 benign, 2 low-risk, 5 high-risk)
- 4 user roles (Admin, Manager, Developer, General)
- Each role has different base reputation scores and tier thresholds

**Roles and Base Scores:**
| Role | Base Score | Default Tier |
|------|------------|--------------|
| Admin | 100 | Trusted |
| Manager | 90 | Trusted |
| Developer | 80 | Standard |
| General | 70 | Standard |

**Evaluation Method:** Zero-shot policy evaluation — each prompt is evaluated against the role's current reputation and tier to determine allow/review/block decisions.

---

## Repository Link

https://github.com/aroproduction/DLSM_codebase/

The datasets are located at: `https://github.com/aroproduction/DLSM_codebase/tree/main/datasets`

---

## Citation

If you use these datasets in your research, please cite the DLSM paper.
