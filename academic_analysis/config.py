"""config.py — shared configuration for the DLSM academic analysis suite.

Everything that parametrizes the analysis lives here so a single edit
reflows the whole report: paper constants, service endpoints, thresholds,
tiers, penalties and rewards.
"""

from __future__ import annotations

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Repository layout
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = Path(__file__).resolve().parent / "results"
FIGURES_DIR = RESULTS_DIR / "figures"

# ---------------------------------------------------------------------------
# Service endpoints
#
# The ML service runs on the Windows host; the gateway + Fabric run inside WSL.
# Windows -> Linux port forwarding IS enabled (localhost:3000 on Windows reaches
# the WSL gateway), but NOT the reverse. So:
#   - gateway URL is always reachable as localhost:3000 from the Windows venv.
#   - the ML URL is auto-detected: on Windows it is localhost:4000; on WSL the
#     Windows host is reachable at the default-route gateway IP.
# ---------------------------------------------------------------------------
GATEWAY_URL = os.environ.get("DLSM_GATEWAY_URL", "http://localhost:3000")

def _detect_ml_url() -> str:
    if os.name == "nt":
        return os.environ.get("DLSM_ML_URL", "http://localhost:4000")
    # WSL/Linux: the Windows host listens on the default-route gateway IP.
    try:
        out = __import__("subprocess").run(
            ["sh", "-c", "ip route | awk '/default/ {print $3}'"],
            capture_output=True, text=True, timeout=5,
        )
        ip = (out.stdout or "").strip()
        if ip:
            return f"http://{ip}:4000"
    except Exception:
        pass
    return os.environ.get("DLSM_ML_URL", "http://localhost:4000")

ML_URL = os.environ.get("DLSM_ML_URL", _detect_ml_url())

# ---------------------------------------------------------------------------
# Paper constants (data/main.tex)
# ---------------------------------------------------------------------------
# Roles and their base reputation scores (paper Table 3).
ROLE_BASE_SCORES = {
    "Admin": 100,
    "Manager": 90,
    "Developer": 80,
    "General": 70,
}

# Behavioral rewards (paper Table 3).
REWARD_POINTS = {
    "good_behavior_streak": 2,      # capped total +20
    "warning_acknowledged": 5,
    "security_retraining": 15,
}
STREAK_REWARD_CAP = 20

# Incident penalties (paper Table 4).
INCIDENT_PENALTIES = {
    "multi_turn_subversion": 35,
    "successful_jailbreak": 30,
    "jailbreak_attempt": 30,
    "prompt_injection": 30,
    "data_extraction": 25,
    "privacy_abuse": 25,
    "operational_abuse": 25,
    "policy_evasion": 25,
    "suspicious_heuristic": 15,
    "policy_infraction": 5,
}

# Time-decayed forgiveness (paper Eq. 2/3).
PENALTY_HALF_LIFE_DAYS = 30.0
LAMBDA = __import__("math").log(2) / PENALTY_HALF_LIFE_DAYS  # ~0.0231

# Access tiers (paper Table 5).
TIER_THRESHOLDS = [
    ("Trusted", 90),
    ("Standard", 70),
    ("Monitored", 50),
    ("Restricted", 30),
    ("ReadOnly", 10),
    ("Suspended", 0),
]

# Multi-turn sliding window (paper Eq. 4, Scenario B).
WINDOW_W = 5
ALPHA = 0.8
TAU_CRITICAL = 2.0
MULTI_TURN_PENALTY = 35

# Single-turn risk policy (gateway decide()).
SINGLE_TURN_BLOCK = 0.80
SINGLE_TURN_REVIEW = 0.50

# Stage thresholds in the ML pipeline.
STAGE1_BLOCK_THRESHOLD = 0.95
STAGE1_VERIFY_THRESHOLD = 0.60

# The paper's illustrative Scenario B risk trajectory.
PAPER_SCENARIO_B_RISKS = [0.10, 0.35, 0.75, 0.95, 0.98]

# ---------------------------------------------------------------------------
# Analysis tuning
# ---------------------------------------------------------------------------
HTTP_TIMEOUT = 60
CONVERSATION_PREFIX = "acad"
USER_PREFIX = "acad"


def mk_results():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    return RESULTS_DIR, FIGURES_DIR
