#!/usr/bin/env python3
"""
SEV-SNP guest client for the attestation + secret release server (snpguest-based).

Invoke this script with sudo (required because snpguest needs privileged access):
  sudo ./client.py client_config.json
or
  sudo python3 client.py client_config.json

snpguest can have PATH issues due to sudo:
  - The script resolves an absolute path to snpguest.
  - You can optionally specify it in config as "snpguest_path".
  - Otherwise it tries PATH, then common locations.

Flow:
  1) Read config JSON: server_ip, server_port, deployment_name, requester_name
  2) POST stage=init to https://<server_ip>:<port>/<deployment_name> to receive nonce (request_id, base64)
  3) Write nonce (64 raw bytes) to <request-file>
  4) Run: <snpguest_path> report <att-report-path> <request-file>
  5) Base64-encode the raw report bytes and POST stage=attest to receive the secret

Default behavior:
  sudo ./client.py client_config.json
  -> init -> snpguest report -> attest -> prints secret

Optional split behavior:
  Step 1: request nonce
    sudo ./client.py client_config.json --init-only
    -> prints request_id (base64 nonce) to stdout
    (Flow stages 1 and 2)

  Step 2: attest using a provided request_id (base64 nonce)
    sudo ./client.py client_config.json --attest-only --request-id "<BASE64_NONCE>"
    -> prints secret (or failed response) to stdout
    (Flow stages 1, 3-5)


Config example (client_config.json):
{
  "server_ip": "10.0.0.5",
  "server_port": 8443,
  "deployment_name": "my-deployment",
  "requester_name": "alice",

  "tls_verify": false,
  "timeout_seconds": 25,

  "work_dir": "/tmp/snp_client",
  "keep_artifacts": false,

  "snpguest_path": "/usr/local/bin/snpguest"
}

Dependencies:
  pip install requests
"""

import argparse
import base64
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests


def die(msg: str, code: int = 2) -> None:
    print(f"[ERROR] {msg}", file=sys.stderr)
    raise SystemExit(code)


def info(msg: str, verbose: bool) -> None:
    if verbose:
        print(f"[INFO] {msg}", file=sys.stderr)


def load_config(path: str) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        die(f"Config file not found: {p}")
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        die(f"Failed to parse config JSON: {e}")


# ----------------------------
# snpguest path resolution
# ----------------------------
def resolve_snpguest_path(verbose: bool) -> Optional[str]:
    info("Resolving snpguest path...", verbose)

    # 1) Try PATH as inherited by this process (may be restricted under sudo)
    p = shutil.which("snpguest")
    if p:
        info(f"Found snpguest in PATH: {p}", verbose)
        return p
    info("snpguest not found in current PATH", verbose)

    # 2) Try common absolute locations
    candidates = [
        "/usr/bin/snpguest",
        "/usr/local/bin/snpguest",
        "/bin/snpguest",
        "/usr/sbin/snpguest",
        "/sbin/snpguest",
    ]
    for c in candidates:
        if Path(c).is_file():
            info(f"Found snpguest at common location: {c}", verbose)
            return c
        info(f"Checked {c}: not found", verbose)

    info("snpguest not found in common locations", verbose)
    return None


def ensure_snpguest_present(cfg: Dict[str, Any], verbose: bool) -> str:
    # Prefer explicit config override
    sp = str(cfg.get("snpguest_path", "")).strip()
    if sp:
        info(f"Using snpguest_path from config: {sp}", verbose)
        p = Path(sp)
        if not p.exists():
            die(f"Configured snpguest_path does not exist: {sp}")
        if not p.is_file():
            die(f"Configured snpguest_path is not a file: {sp}")
        resolved = str(p.resolve())
        info(f"snpguest_path resolved to: {resolved}", verbose)
        return resolved

    # Otherwise attempt auto-resolution
    resolved = resolve_snpguest_path(verbose)
    if resolved:
        resolved = str(Path(resolved).resolve())
        info(f"Auto-resolved snpguest path: {resolved}", verbose)
        return resolved

    die(
        "snpguest not found. Set 'snpguest_path' in config to the absolute path "
        "(e.g., output of 'which snpguest')."
    )
    return ""


# ----------------------------
# snpguest invocation
# ----------------------------
def run_snpguest_report(
    snpguest_path: str,
    nonce_64: bytes,
    report_path: Path,
    request_file_path: Path,
    verbose: bool,
) -> None:
    if len(nonce_64) != 64:
        die(f"Nonce must be exactly 64 bytes; got {len(nonce_64)} bytes")

    report_path.parent.mkdir(parents=True, exist_ok=True)
    request_file_path.parent.mkdir(parents=True, exist_ok=True)

    request_file_path.write_bytes(nonce_64)
    info(f"Wrote nonce to request file: {request_file_path} (64 bytes)", verbose)

    cmd = [snpguest_path, "report", str(report_path), str(request_file_path)]
    info(f"Running command: {' '.join(cmd)}", verbose)

    try:
        res = subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        out = (e.stdout or "").strip()
        err = (e.stderr or "").strip()
        die(f"snpguest failed (rc={e.returncode}). stdout={out!r} stderr={err!r}")

    if verbose:
        if res.stdout:
            info(f"snpguest stdout: {res.stdout.strip()}", verbose)
        if res.stderr:
            info(f"snpguest stderr: {res.stderr.strip()}", verbose)

    if not report_path.exists():
        die("snpguest completed but report file was not created")
    if report_path.stat().st_size <= 0:
        die("snpguest completed but report file is empty")

    info(f"Attestation report written: {report_path} ({report_path.stat().st_size} bytes)", verbose)

# ----------------------------
# helpers
# ----------------------------
def build_server_url(cfg: Dict[str, Any]) -> str:
    server_ip = str(cfg.get("server_ip", "")).strip()
    server_port = int(cfg.get("server_port", 8443))
    deployment_name = str(cfg.get("deployment_name", "")).strip()
    if not server_ip:
        die("Config missing server_ip")
    if not deployment_name:
        die("Config missing deployment_name")
    return f"https://{server_ip}:{server_port}/{deployment_name}"


def request_nonce(
    sess: requests.Session,
    url: str,
    requester_name: str,
    deployment_name: str,
    timeout: int,
    tls_verify: bool,
    verbose: bool = False,
) -> Tuple[str, bytes, Dict[str, Any]]:
    # should return (request_id, nonce_b64, nonce_raw_64, full_init_json)
    init_payload = {
        "stage": "init",
        "requester_name": requester_name,
    }
    info(f"INIT request payload keys: {list(init_payload.keys())}", verbose)

    try:
        r = sess.post(url, json=init_payload, timeout=timeout, verify=tls_verify)
    except requests.RequestException as e:
        die(f"Failed to contact server (init): {e}")

    info(f"INIT response status: {r.status_code}", verbose)
    if r.status_code != 200:
        die(f"Init failed: HTTP {r.status_code}: {r.text}")

    init_resp = r.json()
    request_id = init_resp.get("request_id")

    if not isinstance(request_id, str):
        die("Init response missing request_id")

    nonce_b64 = init_resp.get("nonce_b64")

    if not isinstance(nonce_b64, str) or not nonce_b64:
        die("Init response missing nonce_b64")

    try:
        nonce = base64.b64decode(nonce_b64, validate=True)
    except Exception as e:
        die(f"Init response nonce_b64 is invalid base64: {e}")

    if len(nonce) != 64:
        die(f"Nonce length != 64: {len(nonce)}")

    return request_id, nonce_b64, nonce, init_resp


def build_report_b64_from_nonce(
    snpguest_path: str,
    nonce_64: bytes,
    work_dir: Path,
    verbose: bool,
) -> Tuple[str, Path, Path]:
    work_dir.mkdir(parents=True, exist_ok=True)
    report_path = work_dir / "attestation_report.bin"
    request_file_path = work_dir / "attestation_request.bin"

    run_snpguest_report(snpguest_path, nonce_64, report_path, request_file_path, verbose)

    report_bytes = report_path.read_bytes()
    report_b64 = base64.b64encode(report_bytes).decode("ascii")

    info(f"Report binary size: {len(report_bytes)} bytes", verbose)
    info(f"Report base64 size: {len(report_b64)} chars", verbose)
    return report_b64, report_path, request_file_path


def submit_attestation(
    sess: requests.Session,
    url: str,
    request_id: str,
    requester_name: str,
    deployment_name: str,
    attestation_report_b64: str,
    timeout: int,
    tls_verify: bool,
    verbose: bool = False,
) -> Dict[str, Any]:
    attest_payload = {
        "stage": "attest",
        "request_id": request_id,
        "requester_name": requester_name,
        "attestation_report_b64": attestation_report_b64,
    }

    try:
        r2 = sess.post(url, json=attest_payload, timeout=timeout, verify=tls_verify)
    except requests.RequestException as e:
        die(f"Failed to contact server (attest): {e}")

    info(f"ATTEST response status: {r2.status_code}", verbose)
    if r2.status_code != 200:
        die(f"Attest failed: HTTP {r2.status_code}: {r2.text}")

    attest_resp = r2.json()
    return attest_resp

# ----------------------------
# Main flow
# ----------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="SEV-SNP attestation client (snpguest)")
    parser.add_argument("config", help="Path to client config JSON")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument("--deployment-name", help="Override deployment_name from config (used as path component on server, e.g. https://IP:PORT/<deployment>)")

    # Optional split flags (default behavior unchanged unless you set these)
    g = parser.add_mutually_exclusive_group()
    g.add_argument("--init-only", action="store_true", help="Only request nonce (stage=init) and print request_id")
    g.add_argument("--attest-only", action="store_true", help="Only perform attestation (stage=attest); requires --request-id")

    parser.add_argument("--request-id",help="request_id to be used for --attest-only.")
    parser.add_argument("--nonce-b64", help="Base64 nonce from init response (nonce_b64). Required for --attest-only.")


    args = parser.parse_args()

    # Enforce sudo/root invocation
    try:
        import os
        if os.geteuid() != 0:
            die("This script must be run with sudo/root (snpguest requires privileged access).")
    except Exception:
        pass

    cfg = load_config(args.config)

    server_ip = str(cfg.get("server_ip", "")).strip()
    server_port = int(cfg.get("server_port", 8443))
    deployment_name = str(cfg.get("deployment_name", "")).strip()
    requester_name = str(cfg.get("requester_name", "")).strip()

    if args.deployment_name:
        override = str(args.deployment_name).strip()
        if not override:
            raise SystemExit("ERROR: --deployment-name was provided but is empty after stripping")
        if args.verbose:
            print(f"[client] Overriding deployment_name: {cfg.get('deployment_name')} -> {override}")
        cfg["deployment_name"] = override


    if not requester_name:
        die("Config missing requester_name")
    if not deployment_name:
        die("Config missing deployment_name")

    tls_verify = bool(cfg.get("tls_verify", False))
    timeout = int(cfg.get("timeout_seconds", 25))

    work_dir = Path(cfg.get("work_dir", "/tmp/snp_client")).resolve()
    keep_artifacts = bool(cfg.get("keep_artifacts", False))

    if not server_ip:
        die("Config missing server_ip")
    if not deployment_name:
        die("Config missing deployment_name")
    if not requester_name:
        die("Config missing requester_name")

    snpguest_path = ensure_snpguest_present(cfg, args.verbose)
    info(f"Using snpguest at: {snpguest_path}", args.verbose)

    url = build_server_url(cfg)
    info(f"Server URL: {url}", args.verbose)
    info(f"TLS verify: {tls_verify}", args.verbose)

    sess = requests.Session()


    # init only
    if args.init_only:
        request_id, nonce_b64, _nonce, init_resp = request_nonce(
            sess=sess,
            url=url,
            requester_name=requester_name,
            deployment_name=deployment_name,
            timeout=timeout,
            tls_verify=tls_verify,
            verbose=args.verbose,
        )
        # just print request id for possible piping
        print(json.dumps({"request_id": request_id, "nonce_b64": nonce_b64}, indent=2))
        return

    # attest only
    if args.attest_only:
        if not args.request_id:
            die("--attest-only requires --request-id and --nonce-b64")

        request_id = str(args.request_id).strip()
        nonce_b64 = str(args.nonce_b64).strip()

        try:
            nonce = base64.b64decode(nonce_b64, validate=True)
        except Exception as e:
            die(f"Invalid base64 nonce_b64: {e}")

        if len(nonce) != 64:
            die(f"Nonce length != 64 after decoding nonce_b64, got: {len(nonce)}")

        report_b64, report_path, request_file_path = build_report_b64_from_nonce(
            snpguest_path=snpguest_path,
            nonce_64=nonce,
            work_dir=work_dir,
            verbose=args.verbose,
        )
        attest_resp = submit_attestation(
            sess=sess,
            url=url,
            request_id=request_id,
            requester_name=requester_name,
            deployment_name=deployment_name,
            attestation_report_b64=report_b64,
            timeout=timeout,
            tls_verify=tls_verify,
            verbose=args.verbose,
        )
        secret = attest_resp.get("secret")
        if not isinstance(secret, str):
            die("No secret in response")
        print(secret)

        if not keep_artifacts:
            report_path.unlink(missing_ok=True)
            request_file_path.unlink(missing_ok=True)
            info("Cleaned up temporary artifacts", args.verbose)
        else:
            info(f"Kept artifacts in {work_dir}", args.verbose)
        return


    # default flow
    request_id, nonce_b64, nonce, _init_resp = request_nonce(
        sess=sess,
        url=url,
        requester_name=requester_name,
        deployment_name=deployment_name,
        timeout=timeout,
        tls_verify=tls_verify,
        verbose=args.verbose,
    )

    report_b64, report_path, request_file_path = build_report_b64_from_nonce(
        snpguest_path=snpguest_path,
        nonce_64=nonce,
        work_dir=work_dir,
        verbose=args.verbose,
    )

    attest_resp = submit_attestation(
        sess=sess,
        url=url,
        request_id=request_id,
        requester_name=requester_name,
        deployment_name=deployment_name,
        attestation_report_b64=report_b64,
        timeout=timeout,
        tls_verify=tls_verify,
        verbose=args.verbose,
    )

    secret = attest_resp.get("secret")
    if not isinstance(secret, str):
        die("No secret in response")

    print(secret)

    if not keep_artifacts:
        report_path.unlink(missing_ok=True)
        request_file_path.unlink(missing_ok=True)
        info("Cleaned up temporary artifacts", args.verbose)
    else:
        info(f"Kept artifacts in {work_dir}", args.verbose)


if __name__ == "__main__":
    main()
