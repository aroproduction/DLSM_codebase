# DLSM Codebase

Decentralized LLM Security Mesh (DLSM) - Consortium LLM-as-a-Service security framework with reputation-driven access control and blockchain-backed auditability.

## Repository Structure

```
DLSM_Codebase/
├── consortium/          # Hyperledger Fabric network, chaincode, and gateway
├── ml-service/         # FastAPI classifier service (Stage 1 DistilBERT + Stage 2 Llama Guard)
├── ml-training/        # Model training scripts and artifacts (Stage 1 v2, Stage 2)
├── academic_analysis/  # Evaluation scripts, figures, and reports used in the paper
└── media/              # Paper figures and architecture diagrams
```

## Components

### consortium/
Hyperledger Fabric permissioned network with Raft ordering service (2 orgs, 2 peers).

| Path | Description |
|------|-------------|
| `scripts/` | Shell scripts for Fabric setup; `run_consortium.py` orchestrates the full network lifecycle |
| `chaincode/dlsm-contract/` | TypeScript chaincode (`dlsm-contract`) - implements reputation scoring, sliding-window risk aggregation, and on-chain enforcement |
| `gateway/` | Fastify gateway - prompt interception, hashing, classifier invocation, verdict enforcement, and web UI |

### ml-service/
FastAPI backend exposing `/classify` endpoint.

- `app.py` - FastAPI application entry point
- `pipeline.py` - Dual-stage classifier pipeline (Stage 1 DistilBERT prefilter + Stage 2 Llama Guard 3 1B)
- `stage1_prefilter/` - Fine-tuned DistilBERT model (v2 checkpoint, 67M params)
- `requirements.txt` - Python dependencies

### ml-training/
Stage 1 and Stage 2 filter training.

| Path | Description |
|------|-------------|
| `stage1_prefilter_v2/` | Stage 1 v2 training script, model checkpoint, tokenizer, and training artifacts |
| `stage2_filter_v2/` | Stage 2 filter script using Llama Guard 3 1B for borderline prompt classification |
| `pipeline_results.json` | Dual-stage cascade evaluation results |

### academic_analysis/
Scripts and outputs for paper evaluation.

| Path | Description |
|------|-------------|
| `analyze_ml_model.py` | Stage 1 prefilter metrics and training dynamics analysis |
| `analyze_gateway_e2e.py` | End-to-end gateway evaluation with 118 prompts |
| `analyze_consortium.py` | Consortium policy enforcement and tier boundary analysis |
| `analyze_reputation.py` | Reputation model simulations (Scenarios A & B) |
| `analyze_multiturn.py` | Multi-turn jailbreak detection and sliding-window sensitivity |
| `results/figures/` | Figures used in the paper |
| `results/*.md` | Evaluation reports |

### media/
Figures referenced in the paper:
- `DLSM-architecture.png` - System architecture diagram
- `fig_loss_epoch.png`, `fig_val_metrics.png` - Stage 1 training dynamics
- `fig_prompt_funnel.png` - Dual-stage routing funnel
- `fig_catch_rates.png` - Attack detection rates by category
- `fig_multiturn_paper_trace.png`, `fig_multiturn_live_trace.png` - Multi-turn detection traces
