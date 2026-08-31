"""common.py — shared helpers for the DLSM academic analysis suite.

Provides thin HTTP JSON helpers, plotting style, aggregated-risk math
(replicating the on-chain Eq. 4 exactly) and a tiny markdown-report writer.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

import config as C


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
def http_request(
    method: str,
    url: str,
    body: dict[str, Any] | None = None,
    timeout: float = C.HTTP_TIMEOUT,
) -> dict[str, Any]:
    data = None
    headers = {"content-type": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        return {"_http_error": exc.code, "_http_body": (exc.read() or b"").decode("utf-8", "replace")[:500]}
    except Exception as exc:  # noqa: BLE001
        return {"_http_error": str(exc)}


def health(url: str) -> dict[str, Any]:
    return http_request("GET", f"{url}/health", timeout=10)


# ---------------------------------------------------------------------------
# Aggregated session risk — on-chain Eq. 4 replication
# C_current = sum_{j=1..m} alpha^(m-j) * x_j   (W = last 5 turns)
# ---------------------------------------------------------------------------
def aggregated_risk(turns: list[float], alpha: float = C.ALPHA, w: int = C.WINDOW_W) -> float:
    window = turns[-w:]
    m = len(window)
    if m == 0:
        return 0.0
    total = 0.0
    for j in range(m):
        age = m - 1 - j
        total += (alpha ** age) * window[j]
    return round(total, 5)


def risk_series(turns: list[float], alpha: float = C.ALPHA, w: int = C.WINDOW_W) -> list[float]:
    out = []
    for i in range(1, len(turns) + 1):
        out.append(aggregated_risk(turns[:i], alpha=alpha, w=w))
    return out


# ---------------------------------------------------------------------------
# Reputation model — on-chain Eq. 1/2/3 replication
# S(t) = max(0, min(100, S_base + R(t) - P(t)))
# P(t) = sum_i p_i * e^(-lambda * dt_i)
# ---------------------------------------------------------------------------
def decayed_penalty_sum(incidents: list[tuple[float, float]], now_millis: float) -> float:
    """incidents: list of (applied_penalty, applied_at_millis).

    Replicates the on-chain computation (dlsm-contract.ts line ~244), which
    sums scaled penalties and rounds the total back to an integer.
    """
    total_scaled = 0.0
    for penalty, applied_at in incidents:
        delta_days = (now_millis - applied_at) / 86_400_000.0
        total_scaled += penalty * np.exp(-C.LAMBDA * max(0.0, delta_days))
    return round(total_scaled)


def reputation_score(base_score: float, rewards: float, incidents: list[tuple[float, float]], now_millis: float) -> float:
    penalty = decayed_penalty_sum(incidents, now_millis)
    return float(max(0, min(100, base_score + rewards - penalty)))


def tier_for_score(score: float) -> str:
    for name, threshold in C.TIER_THRESHOLDS:
        if score >= threshold:
            return name
    return "Suspended"


# ---------------------------------------------------------------------------
# Plotting style
# ---------------------------------------------------------------------------
def style_axis(ax, title: str = "", xlabel: str = "", ylabel: str = "") -> None:
    ax.set_title(title, fontsize=12, fontweight="bold", pad=10)
    ax.set_xlabel(xlabel, fontsize=10)
    ax.set_ylabel(ylabel, fontsize=10)
    ax.tick_params(labelsize=9)
    ax.grid(alpha=0.25, linestyle="--", linewidth=0.6)


def save_fig(fig, name: str) -> str:
    path = C.FIGURES_DIR / name
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return name


# ---------------------------------------------------------------------------
# JSON result persistence
# ---------------------------------------------------------------------------
def save_json(payload: dict[str, Any], name: str) -> Path:
    C.mk_results()
    path = C.RESULTS_DIR / name
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return path


def load_json(name: str) -> dict[str, Any]:
    path = C.RESULTS_DIR / name
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {}


# ---------------------------------------------------------------------------
# X.509 cert subject extraction (pure-Python DER walk; no openssl needed)
# ---------------------------------------------------------------------------
_OID_CN = bytes([0x55, 0x04, 0x03])  # 2.5.4.3 commonName
_OID_O = bytes([0x55, 0x04, 0x0A])   # 2.5.4.10 organizationName
_OID_OU = bytes([0x55, 0x04, 0x0B])  # 2.5.4.11 organizationalUnitName
_OID_ATTRS = {"2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.11": "OU"}


def _asn1_read(data: bytes, pos: int) -> tuple[int, bytes, int]:
    tag = data[pos]
    pos += 1
    ln = data[pos]
    pos += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    return tag, data[pos:pos + ln], pos + ln


def _oid_str(oid_bytes: bytes) -> str:
    parts = [oid_bytes[0] // 40, oid_bytes[0] % 40]
    val = 0
    for b in oid_bytes[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(val)
            val = 0
    return ".".join(str(p) for p in parts)


def _collect_attributes(data: bytes) -> dict[str, list[str]]:
    """Walk a DER SEQUENCE collecting (OID, string-value) attribute pairs."""
    attrs: dict[str, list[str]] = {}
    stack = [data]
    while stack:
        chunk = stack.pop()
        pos = 0
        while pos < len(chunk):
            try:
                tag, payload, nxt = _asn1_read(chunk, pos)
            except Exception:  # noqa: BLE001
                break
            if tag == 0x30:  # SEQUENCE
                stack.append(payload)
            elif tag == 0x06:  # OID
                oid = _oid_str(payload)
                # peek next element: string type
                if nxt < len(chunk):
                    ntag, nval, _n = _asn1_read(chunk, nxt)
                    if ntag in (0x0C, 0x13, 0x14, 0x16, 0x1E, 0x16):
                        try:
                            attrs.setdefault(oid, []).append(nval.decode("utf-8", "replace"))
                        except Exception:  # noqa: BLE001
                            pass
                        pos = _n
                        continue
            pos = nxt
    return attrs


def parse_cert_subject(cert_path: str) -> dict[str, str]:
    """Extract subject attributes (CN, O, OU) from an X.509 PEM certificate."""
    import ssl

    pem = Path(cert_path).read_text(encoding="utf-8", errors="replace")
    der = ssl.PEM_cert_to_DER_cert(pem)
    attrs = _collect_attributes(der)
    return {
        _OID_ATTRS[oid]: " / ".join(vals)
        for oid, vals in attrs.items()
        if oid in _OID_ATTRS
    }


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------
class Report:
    def __init__(self, name: str, title: str):
        C.mk_results()
        self.path = C.RESULTS_DIR / name
        self.lines: list[str] = [f"# {title}", ""]

    def h1(self, text: str) -> None:
        self.lines += [f"## {text}", ""]

    def h2(self, text: str) -> None:
        self.lines += [f"### {text}", ""]

    def p(self, text: str) -> None:
        self.lines += [text, ""]

    def table(self, header: list[str], rows: list[list[Any]]) -> None:
        self.lines.append("| " + " | ".join(str(h) for h in header) + " |")
        self.lines.append("|" + "---|" * len(header))
        for row in rows:
            self.lines.append("| " + " | ".join(str(c) for c in row) + " |")
        self.lines.append("")

    def figure(self, filename: str, caption: str) -> None:
        self.lines.append(f"![{caption}](figures/{filename})")
        self.lines.append("")
        self.lines.append(f"*{caption}*")
        self.lines.append("")

    def code(self, text: str) -> None:
        self.lines += ["```", text, "```", ""]

    def write(self) -> Path:
        self.path.write_text("\n".join(self.lines), encoding="utf-8")
        return self.path
