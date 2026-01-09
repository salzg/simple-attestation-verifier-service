#!/usr/bin/env python3
"""
client-frontend.py
==================

Minimal HTTPS web UI for the SEV-SNP attestation client workflow.

Directory layout:
    client/
        web/
            index.html
            app.js
            styles.css
        client_config.json
        client-frontend.py
        client.py

Measurement:
- Client does NOT use server/policies.json.
- The UI shows the actual VM measurement by generating a local SNP report once and extracting the measurement from the report bytes.

Server semantics (updated):
- stage=init returns:
    request_id  (session identifier; NOT embedded into SNP report)
    nonce_b64   (base64 of 64-byte nonce; MUST be embedded into report_data)
- stage=attest expects:
    request_id
    attestation_report_b64 (report_data == nonce)

Run (requires root because snpguest needs privileged access):
  sudo python3 client-frontend.py \
    --tls-cert ./frontend.crt --tls-key ./frontend.key

Optional:
  --client-config ./client_config.json
  --web-root ./web
  --host 0.0.0.0 --port 9443

Dependencies:
  pip install requests
"""

import argparse
import base64
import json
import ssl
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Tuple, Optional

import requests

# Import reusable functionality from client.py (same directory) and ensure import works even if script is invoked from another location
import sys as _sys
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in _sys.path:
    _sys.path.insert(0, str(_SCRIPT_DIR))

import client as client_mod

# SNP report layout
OFF_MEASUREMENT = 0x90
LEN_MEASUREMENT = 48        # 48 bytes (SHA-384)


# web assets
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".map": "application/json; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
}

def safe_read_asset(web_root: Path, rel: str) -> Tuple[bytes, str]:
    # Reads a file from web_root with traversal protection. Returns (bytes, content_type)
    rel = rel.lstrip("/")
    p = (web_root / rel).resolve()
    if web_root != p and web_root not in p.parents:
        raise FileNotFoundError("path traversal rejected")
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(str(p))
    ctype = CONTENT_TYPES.get(p.suffix.lower(), "application/octet-stream")
    return p.read_bytes(), ctype


# measurement extraction
def extract_measurement_hex(report_bytes: bytes) -> str:
    end = OFF_MEASUREMENT + LEN_MEASUREMENT
    if len(report_bytes) < end:
        raise RuntimeError(f"Report too short for measurement: {len(report_bytes)} bytes")
    return report_bytes[OFF_MEASUREMENT:end].hex()


def build_server_url(cfg: Dict[str, Any], deployment_name_given: Optional[str] = None) -> str:
    # https://{server_ip}:{server_port}/{deployment_name}
    # If deployment_name is provided, it overrides cfg["deployment_name"] for this call.

    server_ip = str(cfg.get("server_ip", "")).strip()
    server_port = int(cfg.get("server_port", 8443))
    deployment_name = str(deployment_name_given if deployment_name_given is not None else cfg.get("deployment_name", "")).strip()
    if not server_ip:
        raise RuntimeError("Config missing server_ip")
    if not deployment_name:
        raise RuntimeError("Config missing deployment_name")
    return f"https://{server_ip}:{server_port}/{deployment_name}"


def build_server_base_url(cfg: Dict[str, Any]) -> str:
    server_ip = str(cfg.get("server_ip", "")).strip()
    server_port = int(cfg.get("server_port", 8443))

    if not server_ip:
        raise ValueError("client_config missing server_ip")

    return f"https://{server_ip}:{server_port}"


def compute_actual_measurement_hex(cfg: Dict[str, Any], snpguest_path: str, work_dir: Path, verbose: bool) -> str:
    # Generates a local report once (with a dummy nonce) and extracts measurement
    work_dir.mkdir(parents=True, exist_ok=True)
    report_path = work_dir / "measurement_probe_report.bin"
    request_path = work_dir / "measurement_probe_request.bin"

    dummy_nonce = b"\x00" * 64
    client_mod.run_snpguest_report(snpguest_path, dummy_nonce, report_path, request_path, verbose)

    report_bytes = report_path.read_bytes()
    return extract_measurement_hex(report_bytes)


# server calls (init and attest)

def call_init(sess: requests.Session, cfg: Dict[str, Any], deployment_name: str) -> Dict[str, Any]:
    url = build_server_url(cfg, deployment_name)
    payload = {
        "stage": "init",
        "requester_name": str(cfg.get("requester_name", "")).strip(),
    }
    timeout = int(cfg.get("timeout_seconds", 25))
    verify = bool(cfg.get("tls_verify", False))

    r = sess.post(url, json=payload, timeout=timeout, verify=verify)
    out: Dict[str, Any] = {"http_status": r.status_code, "text": r.text, "headers": dict(r.headers)}
    try:
        out["json"] = r.json()
    except Exception:
        out["json"] = None
    return out


def call_attest(sess: requests.Session, cfg: Dict[str, Any], deployment_name: str, request_id: str, report_b64: str) -> Dict[str, Any]:
    url = build_server_url(cfg, deployment_name)
    payload = {
        "stage": "attest",
        "request_id": request_id,  # session id, NOT the nonce
        "requester_name": str(cfg.get("requester_name", "")).strip(),
        "attestation_report_b64": report_b64,
    }
    timeout = int(cfg.get("timeout_seconds", 25))
    verify = bool(cfg.get("tls_verify", False))

    r = sess.post(url, json=payload, timeout=timeout, verify=verify)
    out: Dict[str, Any] = {"http_status": r.status_code, "text": r.text, "headers": dict(r.headers)}
    try:
        out["json"] = r.json()
    except Exception:
        out["json"] = None
    return out


def build_report_b64_and_measurement(
    snpguest_path: str,
    nonce_64: bytes,
    work_dir: Path,
    verbose: bool,
) -> Tuple[str, Dict[str, Any], str]:
    """
    Uses client.py's snpguest runner to generate a report for the given nonce,
    then returns (report_b64, snp_meta, measurement_hex).
    """
    work_dir.mkdir(parents=True, exist_ok=True)
    report_path = work_dir / "attestation_report.bin"
    request_path = work_dir / "attestation_request.bin"

    client_mod.run_snpguest_report(snpguest_path, nonce_64, report_path, request_path, verbose)
    report_bytes = report_path.read_bytes()
    report_b64 = base64.b64encode(report_bytes).decode("ascii")

    snp_meta = {
        "report_path": str(report_path),
        "request_file_path": str(request_path),
        "report_size_bytes": len(report_bytes),
    }

    measurement_hex = extract_measurement_hex(report_bytes)
    return report_b64, snp_meta, measurement_hex


# http handler

class Handler(BaseHTTPRequestHandler):
    server_version = "client-frontend/5.0"

    def _send(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, obj: Any) -> None:
        body = json.dumps(obj, indent=2).encode("utf-8")
        self._send(status, "application/json; charset=utf-8", body)

    def do_GET(self) -> None:
        st = self.server.state  # type: ignore[attr-defined]
        web_root: Path = st["web_root"]

        # API
        if self.path.split("?", 1)[0] == "/api/config":
            self._json(200, {
                "ok": True,
                "requester_name": st["client_cfg"].get("requester_name", ""),
                "deployment_name": st["client_cfg"].get("deployment_name", ""),
                "server_base_url": st.get("server_base_url"),
                "actual_measurement_hex": st["actual_measurement_hex"],
                "actual_measurement_error": st["actual_measurement_error"]
            })
            return

        # Static
        path = self.path.split("?", 1)[0]
        if path == "/":
            path = "/index.html"

        try:
            body, ctype = safe_read_asset(web_root, path)
            self._send(200, ctype, body)
        except FileNotFoundError:
            self._json(404, {"ok": False, "error": "not found"})
        except Exception as e:
            self._json(500, {"ok": False, "error": f"failed to serve asset: {e}"})

    def do_POST(self) -> None:
        try:
            st = self.server.state  # type: ignore[attr-defined]

            if self.path == "/api/init":
                clen = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(clen) if clen > 0 else b"{}"
                body = json.loads(raw.decode("utf-8"))
                deployment_name = str(body.get("deployment_name") or st["client_cfg"].get("deployment_name", "")).strip()
                if not deployment_name:
                    self._json(400, {"ok": False, "error": "deployment_name missing (no override and not in config)"})
                    return

                sess: requests.Session = st["http_session"]
                res = call_init(
                    sess=sess,
                    cfg=st["client_cfg"],
                    deployment_name=deployment_name,
                )


                j = res.get("json") if isinstance(res.get("json"), dict) else {}
                self._json(200, {
                    "ok": (res.get("http_status") == 200),
                    "deployment_name": deployment_name,
                    "request_id": j.get("request_id"),
                    "nonce_b64": j.get("nonce_b64"),
                    "init": res,
                })
                return

            if self.path == "/api/attest":
                clen = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(clen) if clen > 0 else b"{}"
                body = json.loads(raw.decode("utf-8"))

                request_id = str(body.get("request_id", "")).strip()
                nonce_b64 = str(body.get("nonce_b64", "")).strip()

                deployment_name = str(body.get("deployment_name") or st["client_cfg"].get("deployment_name", "")).strip()
                if not deployment_name:
                    self._json(400, {"ok": False, "error": "deployment_name missing (no override and not in config)"})
                    return

                if not request_id:
                    self._json(400, {"ok": False, "error": "missing request_id"})
                    return
                if not nonce_b64:
                    self._json(400, {"ok": False, "error": "missing nonce_b64"})
                    return

                try:
                    nonce = base64.b64decode(nonce_b64, validate=True)
                except Exception as e:
                    self._json(400, {"ok": False, "error": f"invalid base64 nonce_b64: {e}"})
                    return

                if len(nonce) != 64:
                    self._json(400, {"ok": False, "error": f"nonce must decode to 64 bytes; got {len(nonce)}"})
                    return

                # Report generation reuses client.py's snpguest function
                report_b64, snp_meta, measurement_hex = build_report_b64_and_measurement(
                    st["snpguest_path"],
                    nonce,
                    st["work_dir"],
                    st["verbose"],
                )

                # Submit stage=attest (request_id is session id)
                sess: requests.Session = st["http_session"]
                att = call_attest(sess, st["client_cfg"], deployment_name, request_id, report_b64)

                secret = None
                secret_ok = False
                if att.get("http_status") == 200 and isinstance(att.get("json"), dict):
                    v = att["json"].get("secret")
                    if isinstance(v, str) and v:
                        secret = v
                        secret_ok = True

                out = {
                    "ok": (att.get("http_status") == 200),
                    "request_id": request_id,
                    "nonce_b64": nonce_b64,
                    "measurement_hex": measurement_hex,
                    "snpguest": snp_meta,
                    "attest": att,
                    "secret_ok": secret_ok,
                    "secret": secret,
                }
                self._json(200, out)
                return

            self._json(404, {"ok": False, "error": "not found"})

        except Exception as e:
            self._json(500, {"ok": False, "error": str(e), "traceback": traceback.format_exc()})

def main() -> None:
    ap = argparse.ArgumentParser(description="Minimal HTTPS frontend for attestation client")
    ap.add_argument("--client-config", default="./client_config.json", help="Path to client_config.json")
    ap.add_argument("--web-root", default=None, help="Directory containing index.html, app.js, styles.css (default: ./web)")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=9443)
    ap.add_argument("--tls-cert", required=True)
    ap.add_argument("--tls-key", required=True)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    # snpguest generally requires privileged access
    try:
        import os
        if os.geteuid() != 0:
            raise SystemExit("ERROR: run with sudo/root (snpguest requires privileged access).")
    except Exception:
        pass

    script_dir = Path(__file__).resolve().parent

    client_cfg_path = Path(args.client_config)
    if not client_cfg_path.is_absolute():
        client_cfg_path = (script_dir / client_cfg_path).resolve()
    else:
        client_cfg_path = client_cfg_path.resolve()

    web_root = Path(args.web_root) if args.web_root is not None else (script_dir / "web")
    if not web_root.is_absolute():
        web_root = (script_dir / web_root).resolve()
    else:
        web_root = web_root.resolve()

    if not client_cfg_path.exists():
        raise SystemExit(f"ERROR: missing client config: {client_cfg_path}")
    if not web_root.exists() or not web_root.is_dir():
        raise SystemExit(f"ERROR: web-root must be an existing directory: {web_root}")

    for fn in ("index.html", "app.js", "styles.css"):
        fp = web_root / fn
        if not fp.exists() or not fp.is_file():
            raise SystemExit(f"ERROR: missing required web asset: {fp}")

    # Reuse config loader from client.py
    client_cfg = client_mod.load_config(str(client_cfg_path))

    requester_name = str(client_cfg.get("requester_name", "")).strip()
    if not requester_name:
        raise SystemExit("ERROR: client config missing requester_name")

    default_deployment_name = str(client_cfg.get("deployment_name", "")).strip()
    if not default_deployment_name:
        raise SystemExit("ERROR: client config missing deployment_name")

    server_base_url = build_server_base_url(client_cfg)

    # Reuse snpguest path resolution from client.py
    snpguest_path = client_mod.ensure_snpguest_present(client_cfg, args.verbose)

    work_dir = Path(client_cfg.get("work_dir", "/tmp/snp_client")).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)

    # Compute actual measurement once
    actual_measurement_hex = None
    actual_measurement_error = None
    try:
        actual_measurement_hex = compute_actual_measurement_hex(client_cfg, snpguest_path, work_dir, args.verbose)
    except Exception as e:
        actual_measurement_error = str(e)

    http_session = requests.Session()

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    httpd.state = {  # type: ignore[attr-defined]
        "client_cfg": client_cfg,
        "requester_name": requester_name,
        "default_deployment_name": default_deployment_name,
        "server_base_url": server_base_url,
        "snpguest_path": snpguest_path,
        "work_dir": work_dir,
        "http_session": http_session,
        "web_root": web_root,
        "actual_measurement_hex": actual_measurement_hex,
        "actual_measurement_error": actual_measurement_error,
        "verbose": args.verbose,
    }

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.tls_cert, args.tls_key)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    print(f"[INFO] Frontend listening on https://{args.host}:{args.port}/")
    print(f"[INFO] Web root: {web_root}")
    print(f"[INFO] Attestation server base: {server_base_url}")
    print(f"[INFO] requester_name: {requester_name}")
    print(f"[INFO] default deployment_name: {default_deployment_name}")
    if actual_measurement_hex:
        print(f"[INFO] Actual measurement (hex): {actual_measurement_hex}")
    else:
        print(f"[WARN] Could not compute actual measurement at startup: {actual_measurement_error}")
    print(f"[INFO] Using snpguest: {snpguest_path}")

    httpd.serve_forever()


if __name__ == "__main__":
    main()
