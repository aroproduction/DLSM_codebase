#!/usr/bin/env python3
"""DLSM consortium environment manager.

Brings the whole stack up as background processes:

    1.  Hyperledger Fabric test network + dlsmchannel (if not already running)
    2.  DLSM chaincode deployment (if not already deployed at the right version)
    3.  dlsm-gateway Fabric identity (if missing)
    4.  ML service: either reachability check of a remote ML (WSL hybrid),
        or a fully local ML service started on 127.0.0.1:4000 (--start-ml)
    5.  Gateway build + background start (detached, PID-tracked)

Commands
--------
    up       Bring up Fabric, deploy chaincode, start the gateway (default).
             Add --start-ml to also set up and run the ML service locally.
    stop     Cleanly stop the background gateway (+ --ml / --fabric).
    status   Show health of gateway, ML service, Fabric, chaincode.
    down     Stop gateway + ML and tear down the Fabric network.

Examples
--------
    python3 scripts/run_consortium.py up
    python3 scripts/run_consortium.py up --start-ml
    python3 scripts/run_consortium.py up --ml-url http://<win-host>:4000
    python3 scripts/run_consortium.py up --ml-wait 120 --restart-gateway
    python3 scripts/run_consortium.py status
    python3 scripts/run_consortium.py stop --ml
    python3 scripts/run_consortium.py down
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TEST_NETWORK = REPO_ROOT / "fabric-samples" / "test-network"
BIN_DIR = TEST_NETWORK.parent / "bin"
CHAINCODE_SRC = REPO_ROOT / "fabric" / "chaincode" / "dlsm-contract"
GATEWAY_DIR = REPO_ROOT / "gateway"

STATE_DIR = REPO_ROOT / ".consortium"
PID_FILE = STATE_DIR / "gateway.pid"
LOG_FILE = STATE_DIR / "gateway.log"
ML_PID_FILE = STATE_DIR / "ml.pid"
ML_LOG_FILE = STATE_DIR / "ml.log"
ML_VENV = REPO_ROOT / ".venv-e2e"
ML_SERVICE_DIR = REPO_ROOT / "ml-service"

CHANNEL = "dlsmchannel"
CHAINCODE_NAME = "dlsm"
CHAINCODE_VERSION = "1.7"
GATEWAY_IDENTITY = "dlsm-gateway@org1.example.com"
GATEWAY_PORT = 3000
ML_PORT = 4000

PEER0_ORG1 = "peer0.org1.example.com"
CHAINCODE_CONTAINER_PREFIX = "dev-peer0.org1.example.com-dlsm"


def log(msg: str = "") -> None:
    print(msg, flush=True)


# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------
def run(
    cmd: list[str],
    cwd: Path,
    env: dict[str, str] | None = None,
    timeout: int = 1800,
    check: bool = True,
) -> subprocess.CompletedProcess:
    merged = dict(os.environ)
    if env:
        merged.update(env)
    result = subprocess.run(cmd, cwd=str(cwd), env=merged, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(cmd)}\n"
            f"stdout: {result.stdout[-2000:]}\nstderr: {result.stderr[-2000:]}"
        )
    return result


def http_get_json(url: str, timeout: float = 5) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8")
        return json.loads(raw) if raw else {}


def detect_ml_url() -> str:
    """In a hybrid WSL setup the ML service listens on the Windows host,
    reachable at the WSL default gateway IP."""
    try:
        out = run(["sh", "-c", "ip route | awk '/default/ {print $3}'"], REPO_ROOT, check=False, timeout=5)
        ip = (out.stdout or "").strip()
        if ip:
            return f"http://{ip}:{ML_PORT}"
    except Exception:
        pass
    return f"http://127.0.0.1:{ML_PORT}"


def docker_running(name_fragment: str) -> bool:
    result = run(
        ["docker", "ps", "--format", "{{.Names}}"],
        REPO_ROOT,
        check=False,
        timeout=60,
    )
    return name_fragment in (result.stdout or "")


def gateway_health() -> dict | None:
    try:
        return http_get_json(f"http://127.0.0.1:{GATEWAY_PORT}/health", timeout=5)
    except Exception:
        return None


def wait_http(url: str, name: str, timeout_sec: float = 180) -> dict:
    deadline = time.time() + timeout_sec
    last: dict | None = None
    while time.time() < deadline:
        try:
            last = http_get_json(url, timeout=5)
            if last:
                log(f"  [ok] {name} reachable at {url}")
                return last
        except Exception:
            pass
        time.sleep(3)
    raise RuntimeError(f"{name} did not become ready at {url} within {timeout_sec}s. Last={last}")


# ----------------------------------------------------------------------------
# Fabric
# ----------------------------------------------------------------------------
def fabric_env() -> dict[str, str]:
    env = dict(os.environ)
    env["PATH"] = f"{BIN_DIR}:{env.get('PATH', '')}"
    return env


def is_fabric_up() -> bool:
    return (
        docker_running(PEER0_ORG1)
        and docker_running("orderer.example.com")
        and docker_running("ca_org1")
        and docker_running("ca_org2")
        and docker_running("ca_orderer")
    )


def is_chaincode_deployed() -> bool:
    # Version-specific: a stale chaincode container from an older version would
    # otherwise be mistaken for "already deployed". Container names look like
    # dev-peer0.org1.example.com-dlsm_1.7-<hash>.
    return docker_running(f"{CHAINCODE_CONTAINER_PREFIX}_{CHAINCODE_VERSION}-")


def is_gateway_identity_present() -> bool:
    cert = (
        TEST_NETWORK
        / "organizations" / "peerOrganizations" / "org1.example.com"
        / "users" / GATEWAY_IDENTITY / "msp" / "signcerts" / "cert.pem"
    )
    return cert.exists()


def bring_up_fabric() -> None:
    if is_fabric_up():
        log("  Fabric network already running (peers + orderer + CAs detected)")
        return
    # Stale ledgers/certs persist in docker volumes when containers were
    # stopped without `network.sh down`. A clean down -> up guarantees the
    # channel and CAs are regenerated identically, avoiding the "channel /
    # ledger already exists" error loop.
    log("  cleaning stale Fabric state (network.sh down)")
    run([str(TEST_NETWORK / "network.sh"), "down"], TEST_NETWORK, env=fabric_env(), check=False, timeout=600)
    log("  bringing up Fabric test network + dlsmchannel (CA + CouchDB)")
    run(
        [
            str(TEST_NETWORK / "network.sh"), "up", "createChannel",
            "-ca", "-s", "couchdb", "-c", CHANNEL,
        ],
        TEST_NETWORK,
        env=fabric_env(),
        timeout=1800,
    )


def wait_for_chaincode(timeout_sec: float = 180) -> None:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        if is_chaincode_deployed():
            return
        time.sleep(5)
    raise RuntimeError("chaincode containers did not appear after deployCC")


def deploy_chaincode() -> None:
    if is_chaincode_deployed():
        log(f"  chaincode {CHAINCODE_NAME} already deployed")
        return
    log("  deploying DLSM chaincode")
    run(
        [
            str(TEST_NETWORK / "network.sh"), "deployCC",
            "-c", CHANNEL,
            "-ccn", CHAINCODE_NAME,
            "-ccp", str(CHAINCODE_SRC),
            "-ccl", "typescript",
            "-ccv", CHAINCODE_VERSION,
        ],
        TEST_NETWORK,
        env=fabric_env(),
        timeout=1800,
    )
    wait_for_chaincode()


def ensure_gateway_identity() -> None:
    if is_gateway_identity_present():
        log(f"  gateway identity {GATEWAY_IDENTITY} already present")
        return
    log("  registering + enrolling dlsm-gateway Fabric identity")
    org1 = TEST_NETWORK / "organizations" / "peerOrganizations" / "org1.example.com"
    ca_cert = TEST_NETWORK / "organizations" / "fabric-ca" / "org1" / "ca-cert.pem"
    if not ca_cert.exists():
        raise RuntimeError(f"CA cert missing at {ca_cert}; was the network started with -ca?")

    env = dict(fabric_env())
    env["FABRIC_CA_CLIENT_HOME"] = str(org1)

    register = run(
        [
            str(BIN_DIR / "fabric-ca-client"), "register",
            "--caname", "ca-org1",
            "--id.name", "dlsm-gateway",
            "--id.secret", "dlsmgatewaypw",
            "--id.type", "client",
            "--id.attrs", "role=gateway:ecert",
            "--tls.certfiles", str(ca_cert),
        ],
        TEST_NETWORK,
        env=env,
        check=False,
        timeout=120,
    )
    if register.returncode != 0 and "already registered" not in register.stdout + register.stderr:
        raise RuntimeError(f"fabric-ca register failed: {register.stderr[-1000:]}")

    identity_msp = org1 / "users" / GATEWAY_IDENTITY / "msp"
    enroll = run(
        [
            str(BIN_DIR / "fabric-ca-client"), "enroll",
            "-u", "https://dlsm-gateway:dlsmgatewaypw@localhost:7054",
            "--caname", "ca-org1",
            "-M", str(identity_msp),
            "--tls.certfiles", str(ca_cert),
        ],
        TEST_NETWORK,
        env=env,
        check=False,
        timeout=300,
    )
    if enroll.returncode != 0:
        raise RuntimeError(f"fabric-ca enroll failed: {enroll.stderr[-1000:]}")

    cfg = org1 / "msp" / "config.yaml"
    if cfg.exists():
        shutil.copy(cfg, identity_msp / "config.yaml")
    if not (identity_msp / "signcerts" / "cert.pem").exists():
        raise RuntimeError("dlsm-gateway identity still missing cert.pem after enroll")
    log("  dlsm-gateway identity ready")


# ----------------------------------------------------------------------------
# ML service reachability (timer + recheck)
# ----------------------------------------------------------------------------
def ml_healthy(url: str) -> bool:
    try:
        health = http_get_json(f"{url}/health", timeout=10)
        return health.get("status") == "ok" and health.get("stage1_loaded") is True
    except Exception:
        return False


def wait_for_ml(url: str, wait_sec: int, recheck: bool, quiet_loop: bool = False) -> bool:
    if ml_healthy(url):
        log(f"  [ok] ML service up at {url}")
        return True

    log(f"  ML service NOT detected at {url}")
    log("  Start it on the Windows host, e.g.:")
    log(f"    uvicorn app:app --host 0.0.0.0 --port {ML_PORT}")
    log(f"  Waiting up to {wait_sec}s ...")
    deadline = time.time() + wait_sec
    while time.time() < deadline:
        remaining = int(deadline - time.time())
        if not quiet_loop:
            print(f"  \r  checking ML ... {remaining:3d}s left   ", end="", flush=True)
        if ml_healthy(url):
            if not quiet_loop:
                print()
            log(f"  [ok] ML service up at {url}")
            return True
        time.sleep(3)
    if not quiet_loop:
        print()

    if recheck:
        while True:
            try:
                answer = input("  ML still not up. Start it, then press Enter to recheck (or type 'q' to continue without ML): ").strip()
            except EOFError:
                answer = "q"
            if answer.lower() in {"q", "quit", "exit"}:
                log("  Continuing without ML service. Gateway will fail classify calls.")
                return False
            if ml_healthy(url):
                log(f"  [ok] ML service up at {url}")
                return True
            log("  Still not detected. Rechecking ...")

    log("  ML service not up after wait window. Continuing anyway.")
    return False


# ----------------------------------------------------------------------------
# Gateway
# ----------------------------------------------------------------------------
def build_gateway() -> None:
    log("  building gateway")
    if not (GATEWAY_DIR / "node_modules").exists():
        run(["npm", "install"], GATEWAY_DIR, timeout=1200)
    run(["npm", "run", "build"], GATEWAY_DIR, timeout=600)
    if not (GATEWAY_DIR / "dist" / "server.js").exists():
        raise RuntimeError("gateway dist/server.js missing after build")


def start_gateway(ml_url: str, restart: bool) -> bool:
    health = gateway_health()
    if health and not restart:
        log(f"  gateway already running at http://127.0.0.1:{GATEWAY_PORT} (use --restart-gateway to force)")
        return True

    if health and restart:
        stop_gateway()

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["FABRIC_TEST_NETWORK"] = str(TEST_NETWORK)
    env["FABRIC_IDENTITY"] = GATEWAY_IDENTITY
    env["CLASSIFIER_MODE"] = "http"
    env["CLASSIFIER_URL"] = f"{ml_url}/classify"
    env["LLM_MODE"] = "mock"
    env["PORT"] = str(GATEWAY_PORT)

    log(f"  starting gateway as background process -> log: {LOG_FILE}")
    log_file = LOG_FILE.open("w")
    proc = subprocess.Popen(
        ["node", "dist/server.js"],
        cwd=str(GATEWAY_DIR),
        env=env,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    PID_FILE.write_text(str(proc.pid), encoding="utf-8")

    try:
        health = wait_http(f"http://127.0.0.1:{GATEWAY_PORT}/health", "gateway", timeout_sec=180)
        log(f"  gateway health: {health}")
        log(f"  gateway PID {proc.pid} (saved to {PID_FILE})")
        return True
    except Exception:
        log("  gateway failed to become ready; tail of log:")
        print(LOG_FILE.read_text(encoding="utf-8", errors="replace")[-3000:])
        stop_gateway()
        raise


def stop_gateway() -> bool:
    if not PID_FILE.exists():
        log("  no gateway PID file found; nothing to stop")
        return True

    pid = int(PID_FILE.read_text().strip())
    if not pid:
        PID_FILE.unlink(missing_ok=True)
        return True

    alive = True
    try:
        os.kill(pid, 0)
    except OSError:
        alive = False

    if not alive:
        log(f"  gateway process {pid} is not running")
        PID_FILE.unlink(missing_ok=True)
        return True

    log(f"  sending SIGTERM to gateway process group {pid}")
    try:
        os.killpg(pid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass

    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            log("  gateway exited cleanly")
            PID_FILE.unlink(missing_ok=True)
            return True
        time.sleep(0.5)

    log("  gateway did not exit after SIGTERM; sending SIGKILL")
    try:
        os.killpg(pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    PID_FILE.unlink(missing_ok=True)
    log("  gateway stopped")
    return True


def tear_down_fabric() -> None:
    log("  tearing down Fabric network")
    run([str(TEST_NETWORK / "network.sh"), "down"], TEST_NETWORK, env=fabric_env(), check=False, timeout=600)


# ----------------------------------------------------------------------------
# Local ML service (optional: run the classifier on the same machine)
# ----------------------------------------------------------------------------
def ml_venv_python() -> Path:
    return ML_VENV / "bin" / "python"


def setup_local_ml() -> None:
    """Create .venv-e2e and install the ML-service requirements (first run only)."""
    python = ml_venv_python()
    if not python.exists():
        log("  creating ML virtualenv (.venv-e2e)")
        run(["python3", "-m", "venv", str(ML_VENV)], REPO_ROOT, timeout=300)
    else:
        log("  ML virtualenv already present (.venv-e2e)")
    log("  installing ML-service requirements (torch, transformers, ...)")
    run([str(python), "-m", "pip", "install", "--upgrade", "pip"], REPO_ROOT, timeout=300)
    run(
        [str(python), "-m", "pip", "install", "-r", str(ML_SERVICE_DIR / "requirements.txt")],
        REPO_ROOT,
        timeout=1800,
    )
    stage1 = ML_SERVICE_DIR / "stage1_prefilter" / "model.safetensors"
    if not stage1.exists():
        log("  fetching Stage 1 DistilBERT model (git lfs pull)")
        run(["git", "lfs", "pull"], REPO_ROOT, timeout=1800)
    if not stage1.exists():
        raise RuntimeError("Stage 1 model still missing after git lfs pull")
    log(f"  Stage 1 model OK ({stage1.stat().st_size / 1e6:.0f} MB)")


def start_local_ml(restart: bool) -> bool:
    """Start uvicorn for the ML service on 127.0.0.1:ML_PORT in the background."""
    if ml_healthy(f"http://127.0.0.1:{ML_PORT}") and not restart:
        log(f"  ML service already running at http://127.0.0.1:{ML_PORT}")
        return True
    if restart:
        stop_local_ml()

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    log(f"  starting ML service as background process -> log: {ML_LOG_FILE}")
    log_file = ML_LOG_FILE.open("w")
    proc = subprocess.Popen(
        [str(ml_venv_python()), "-m", "uvicorn", "app:app", "--host", "127.0.0.1", "--port", str(ML_PORT)],
        cwd=str(ML_SERVICE_DIR),
        env=env,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    ML_PID_FILE.write_text(str(proc.pid), encoding="utf-8")

    try:
        health = wait_http(f"http://127.0.0.1:{ML_PORT}/health", "ML service", timeout_sec=600)
        log(f"  ML health: {health}")
        log(f"  ML PID {proc.pid} (saved to {ML_PID_FILE})")
        return True
    except Exception:
        log("  ML service failed to become ready; tail of log:")
        print(ML_LOG_FILE.read_text(encoding="utf-8", errors="replace")[-3000:])
        stop_local_ml()
        raise


def stop_local_ml() -> bool:
    if not ML_PID_FILE.exists():
        log("  no ML PID file found; nothing to stop")
        return True
    pid = int(ML_PID_FILE.read_text().strip())
    if not pid:
        ML_PID_FILE.unlink(missing_ok=True)
        return True
    alive = True
    try:
        os.kill(pid, 0)
    except OSError:
        alive = False
    if not alive:
        log(f"  ML process {pid} is not running")
        ML_PID_FILE.unlink(missing_ok=True)
        return True
    log(f"  sending SIGTERM to ML process group {pid}")
    try:
        os.killpg(pid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            log("  ML exited cleanly")
            ML_PID_FILE.unlink(missing_ok=True)
            return True
        time.sleep(0.5)
    log("  ML did not exit after SIGTERM; sending SIGKILL")
    try:
        os.killpg(pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    ML_PID_FILE.unlink(missing_ok=True)
    log("  ML stopped")
    return True


# ----------------------------------------------------------------------------
# Commands
# ----------------------------------------------------------------------------
def cmd_up(args: argparse.Namespace) -> int:
    log("=== DLSM consortium environment up ===")
    log(f"repo root: {REPO_ROOT}")

    if not args.skip_fabric:
        bring_up_fabric()
        deploy_chaincode()
        ensure_gateway_identity()
    else:
        log("  --skip-fabric: assuming Fabric is already running")

    if args.start_ml:
        setup_local_ml()
        start_local_ml(args.restart_gateway)
        ml_url = f"http://127.0.0.1:{ML_PORT}"
    else:
        ml_url = args.ml_url or detect_ml_url()
        wait_for_ml(ml_url, args.ml_wait, args.recheck, quiet_loop=args.quiet)

    build_gateway()
    start_gateway(ml_url, args.restart_gateway)

    log("\nEnvironment is up:")
    log(f"  Fabric    : {PEER0_ORG1}, orderer.example.com (+ dev-peer dlsm containers)")
    log(f"  Gateway   : http://127.0.0.1:{GATEWAY_PORT}   (PID {PID_FILE.read_text().strip() if PID_FILE.exists() else '?'})")
    if args.start_ml:
        log(f"  ML service: http://127.0.0.1:{ML_PORT}   (PID {ML_PID_FILE.read_text().strip() if ML_PID_FILE.exists() else '?'})")
    else:
        log(f"  ML service: {ml_url}")
    log("\nUseful commands:")
    log("  python3 scripts/run_consortium.py status")
    log("  python3 scripts/run_consortium.py stop")
    log("  python3 scripts/run_consortium.py down")
    log("  python3 scripts/run_live_validation.py")
    return 0


def cmd_status(_args: argparse.Namespace) -> int:
    log("=== DLSM consortium environment status ===")

    gw = gateway_health()
    if gw:
        log(f"  Gateway      : UP   {gw}")
    else:
        log("  Gateway      : DOWN")
    if PID_FILE.exists():
        log(f"    (PID file: {PID_FILE.read_text().strip()})")

    ml_url = detect_ml_url()
    if ml_healthy(ml_url):
        log(f"  ML service   : UP   at {ml_url}")
    else:
        log(f"  ML service   : DOWN/not reached at {ml_url}")
    if ML_PID_FILE.exists():
        log(f"    (PID file: {ML_PID_FILE.read_text().strip()})")

    if is_fabric_up():
        log("  Fabric       : UP   (peers + orderer + CAs detected)")
    else:
        log("  Fabric       : DOWN")

    if is_chaincode_deployed():
        log(f"  Chaincode    : UP   ({CHAINCODE_NAME} container detected)")
    else:
        log("  Chaincode    : DOWN (not deployed)")

    if is_gateway_identity_present():
        log(f"  Gateway ID   : present ({GATEWAY_IDENTITY})")
    else:
        log("  Gateway ID   : MISSING")

    log("\nRunning containers:")
    result = run(["docker", "ps", "--format", "table {{.Names}}\\t{{.Status}}"], REPO_ROOT, check=False, timeout=60)
    print(result.stdout)
    return 0


def cmd_stop(_args: argparse.Namespace) -> int:
    log("=== DLSM consortium environment stop ===")
    stop_gateway()
    if _args.ml:
        stop_local_ml()
    if _args.fabric:
        tear_down_fabric()
    log("done")
    return 0


def cmd_down(_args: argparse.Namespace) -> int:
    log("=== DLSM consortium environment down ===")
    stop_gateway()
    stop_local_ml()
    tear_down_fabric()
    log("done")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DLSM consortium environment manager")
    sub = parser.add_subparsers(dest="command")

    up = sub.add_parser("up", help="Bring up Fabric + chaincode + gateway (background)")
    up.add_argument("--ml-url", default=None, help="ML service base URL (default: auto-detect WSL host)")
    up.add_argument("--start-ml", action="store_true", help="Set up and run the ML service locally on 127.0.0.1:4000 (needs .venv-e2e; installs deps + model on first run)")
    up.add_argument("--ml-wait", type=int, default=120, help="Seconds to poll for ML service (default 120)")
    up.add_argument("--no-recheck", action="store_true", help="Do not prompt to recheck after the wait window")
    up.add_argument("--restart-gateway", action="store_true", help="Restart the gateway even if already running")
    up.add_argument("--skip-fabric", action="store_true", help="Assume Fabric is already running; skip network/chaincode/identity setup")
    up.add_argument("--quiet", action="store_true", help="Reduce polling output")

    sub.add_parser("status", help="Show status of all components")
    stop = sub.add_parser("stop", help="Cleanly stop the background gateway")
    stop.add_argument("--ml", action="store_true", help="Also stop the background ML service")
    stop.add_argument("--fabric", action="store_true", help="Also tear down the Fabric network")
    sub.add_parser("down", help="Stop gateway, ML service, and tear down the Fabric network")

    args = parser.parse_args()
    args.recheck = not getattr(args, "no_recheck", False)
    if not args.command:
        args.command = "up"
    return args


def main() -> int:
    args = parse_args()
    handlers = {
        "up": cmd_up,
        "status": cmd_status,
        "stop": cmd_stop,
        "down": cmd_down,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())