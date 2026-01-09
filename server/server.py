#!/usr/bin/env python3
"""
HTTPS AMD SEV-SNP attestation + secret release server.

Endpoints:
  GET  /                  - barebones HTML log view (live via SSE when possible)
  POST /<deployment_name> - stage=init   -> returns 64-byte nonce (base64) and a request_id
                          - stage=attest -> verifies nonce+policy+signature, returns secret

Dependencies:
  pip install aiohttp cryptography
"""

import argparse
import asyncio
import base64
import binascii
import datetime as dt
import functools
import json
import logging
import os
import signal
import ssl
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, List

import aiohttp
from aiohttp import web

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils


# ----------------------------
# Constants / Report Layout
# ----------------------------
# NOTE: This the currently (as time of writing) referenced SNP report layout.
# If your environment uses a different report format/size, adjust these values.
REPORT_SIZE = 0x4A0  # 1184 bytes

OFF_VERSION = 0x00
OFF_POLICY = 0x08
OFF_FLAGS = 0x48          # 4 bytes (raw u32)
OFF_REPORT_DATA = 0x50    # 64 bytes
OFF_MEASUREMENT = 0x90    # 48 bytes (SHA-384)
OFF_REPORTED_TCB = 0x180  # 8 bytes (TCB_VERSION)
OFF_CHIP_ID = 0x1A0       # 64 bytes

OFF_SIGN_START = 0x00
LEN_SIGNED = 0x2A0        # bytes 0x00..0x29F
OFF_SIGNATURE = 0x2A0
LEN_SIGNATURE_BLOB = 0x200  # 0x2A0..0x49F

LEN_REPORT_DATA = 64
LEN_MEASUREMENT = 48
LEN_CHIP_ID = 64

AMD_KDS_BASE = "https://kdsintf.amd.com"


# ----------------------------
# Data models
# ----------------------------
@dataclass
class Session:
    request_id: str             # session identifier, not nonce!
    nonce: bytes                    # 64-byte nonce to be embedded in the attestation report
    deployment_name: str
    requester_name: str
    created_utc: str
    used: bool = False


@dataclass
class ParsedReport:
    raw: bytes
    version: int
    policy: int
    flags_u32: int
    report_data: bytes
    measurement: bytes
    reported_tcb_u64: int
    chip_id: bytes
    signature_r: int
    signature_s: int


# ----------------------------
# Utility helpers
# ----------------------------
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


def now_utc_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def le_u32(b: bytes) -> int:
    return int.from_bytes(b, "little", signed=False)


def le_u64(b: bytes) -> int:
    return int.from_bytes(b, "little", signed=False)


def safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def load_json_file(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_json_file_if_exists(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return load_json_file(path)


def constant_time_eq(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    r = 0
    for x, y in zip(a, b):
        r |= x ^ y
    return r == 0

def parse_mask(mask: Any) -> int:
    # mask can be str ("123"), hex str ("0x30000") or actual int
    if mask is None:
        return 0
    if isinstance(mask, int):
        return mask
    if isinstance(mask, str):
        s = mask.strip().lower()
        if not s:
            return 0
        return int(mask, base=0)  # auto base
    else:
        return int(mask)

def parse_iso_utc(s: str) -> dt.datetime:
    # tolerant ISO parsing; assumes UTC if missing tz
    try:
        d = dt.datetime.fromisoformat(s)
        if d.tzinfo is None:
            d = d.replace(tzinfo=dt.timezone.utc)
        return d.astimezone(dt.timezone.utc)
    except Exception:
        return dt.datetime.now(dt.timezone.utc)

def trunc_hex(b: bytes, n: int = 32) -> str:
    # Return first n bytes as hex (safe-ish for logging).
    return b[:n].hex()

def sha256_hex(b: bytes) -> str:
    # Small helper to avoid logging raw sensitive bytes (nonce/report_data).
    h = hashes.Hash(hashes.SHA256())
    h.update(b)
    return h.finalize().hex()

def sha384_hex(b: bytes) -> str:
    h = hashes.Hash(hashes.SHA384())
    h.update(b)
    return h.finalize().hex()

def policy_summary(policy: Dict[str, Any]) -> Dict[str, Any]:
    # Compact summary of what checks are configured, for logging.
    return {
        "allowed_report_versions": policy.get("allowed_report_versions"),
        "expected_measurement_set": bool(policy.get("expected_measurement_hex")),
        "required_policy_bits_set": policy.get("required_policy_bits_set", 0),
        "forbidden_policy_bits_set": policy.get("forbidden_policy_bits_set", 0),
        "required_flags_bits_set": policy.get("required_flags_bits_set", 0),
        "forbidden_flags_bits_set": policy.get("forbidden_flags_bits_set", 0),
        "chip_id_allowlist_len": len(policy.get("chip_id_allowlist_hex", []) or []),
        "min_tcb": policy.get("min_tcb"),
        "expected_fields_len": len(policy.get("expected_fields", []) or []),
        "delete_session_after_success": bool(policy.get("delete_session_after_success", True)),
        "nonce_ttl_seconds": int(policy.get("nonce_ttl_seconds", 300)),
    }


# ----------------------------
# Cryptography helpers
# ----------------------------

PEM_CERT_RE = re.compile(
    b"-----BEGIN CERTIFICATE-----\\s+.*?\\s+-----END CERTIFICATE-----",
    re.DOTALL,
)

def extract_pem_cert_blocks(pem_bytes: bytes) -> List[bytes]:
    blocks = [m.group(0) + b"\n" for m in PEM_CERT_RE.finditer(pem_bytes)]
    if not blocks:
        raise ValueError("No PEM certificate blocks found")
    return blocks


def run_openssl(args: List[str], input_bytes: Optional[bytes] = None, timeout_s: int = 20) -> Tuple[int, str, str]:
    """
    Run openssl and return (rc, stdout, stderr) as text.
    """
    p = subprocess.run(
        ["openssl"] + args,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_s,
    )
    out = p.stdout.decode("utf-8", errors="replace")
    err = p.stderr.decode("utf-8", errors="replace")
    return p.returncode, out, err


def openssl_subject_of_pem_cert(cert_pem: bytes) -> str:
    """
    Uses openssl to extract subject without parsing ASN.1 in Python.
    """
    with tempfile.NamedTemporaryFile(prefix="cert_", suffix=".pem", delete=True) as tf:
        tf.write(cert_pem)
        tf.flush()
        rc, out, err = run_openssl(["x509", "-in", tf.name, "-noout", "-subject"])
        if rc != 0:
            raise ValueError(f"openssl x509 -subject failed: {err.strip() or out.strip()}")
        return out.strip()

def ensure_ark_ask_pems_from_chain(
    cache_dir: Path,
    product_name: str,
    chain_pem_text: str,
    logger: logging.Logger,
) -> Tuple[Path, Path]:
    """
    Extract ARK and ASK certs (as PEM files) from the AMD cert_chain response using openssl subject inspection.
    Avoids cryptography's ASN.1 parsing entirely for the chain.
    """
    product_dir = cache_dir / "certs" / product_name
    safe_mkdir(product_dir)

    ark_path = product_dir / "ark.pem"
    ask_path = product_dir / "ask.pem"

    # If already extracted, trust cache.
    if ark_path.exists() and ask_path.exists():
        logger.info("ARK/ASK PEM cache hit: ark=%s ask=%s", ark_path, ask_path)
        return ark_path, ask_path

    blocks = extract_pem_cert_blocks(chain_pem_text.encode("utf-8"))
    logger.info("Extracted %d cert blocks from cert_chain for %s", len(blocks), product_name)

    ark_block = None
    ask_block = None

    # Identify by subject string.
    for b in blocks:
        subj = openssl_subject_of_pem_cert(b)
        logger.info("cert_chain block subject: %s", subj)
        if "ARK" in subj and ark_block is None:
            ark_block = b
        elif "SEV" in subj and ask_block is None:
            ask_block = b

    # Fallback: if heuristic didn't find them, take first two
    if ark_block is None or ask_block is None:
        logger.warning("Could not confidently identify ARK/ASK by subject; falling back to first two certs")
        if len(blocks) < 2:
            raise ValueError("cert_chain did not contain at least 2 certificates")
        # In many chains, order is ASK then ARK, but not guaranteed.
        # We still write both; verification below will catch mismatches.
        ask_block = blocks[0]
        ark_block = blocks[1]

    ark_path.write_bytes(ark_block)
    ask_path.write_bytes(ask_block)
    logger.info("Saved ARK/ASK PEMs: ark=%s ask=%s", ark_path, ask_path)
    return ark_path, ask_path


def openssl_verify_chain(
    ark_pem: Path,
    ask_pem: Path,
    leaf_pem: Path,
    logger: logging.Logger,
) -> None:
    # Verify ASK against ARK
    args1 = ["verify", "-CAfile", str(ark_pem), str(ask_pem)]
    rc, out, err = run_openssl(args1)
    logger.info("openssl %s rc=%d out=%s err=%s", " ".join(args1), rc, out.strip(), err.strip())
    if rc != 0 or "OK" not in out:
        raise ValueError(f"OpenSSL verify failed for ASK<-ARK: {err.strip() or out.strip()}")

    # Verify VCEK against ARK with ASK as intermediate
    args2 = ["verify", "-CAfile", str(ark_pem), "-untrusted", str(ask_pem), str(leaf_pem)]
    rc, out, err = run_openssl(args2)
    logger.info("openssl %s rc=%d out=%s err=%s", " ".join(args2), rc, out.strip(), err.strip())
    if rc != 0 or "OK" not in out:
        raise ValueError(f"OpenSSL verify failed for leaf chain: {err.strip() or out.strip()}")

# ----------------------------
# Report parsing
# ----------------------------
def parse_snp_report(report_bytes: bytes, logger: logging.Logger) -> ParsedReport:
    if len(report_bytes) < REPORT_SIZE:
        raise ValueError(f"Attestation report too small: {len(report_bytes)} bytes (need >= {REPORT_SIZE})")

    raw = report_bytes[:REPORT_SIZE]

    version = le_u32(raw[OFF_VERSION:OFF_VERSION + 4])
    policy = le_u64(raw[OFF_POLICY:OFF_POLICY + 8])
    flags_u32 = le_u32(raw[OFF_FLAGS:OFF_FLAGS + 4])
    report_data = raw[OFF_REPORT_DATA:OFF_REPORT_DATA + LEN_REPORT_DATA]
    measurement = raw[OFF_MEASUREMENT:OFF_MEASUREMENT + LEN_MEASUREMENT]
    reported_tcb_u64 = le_u64(raw[OFF_REPORTED_TCB:OFF_REPORTED_TCB + 8])
    chip_id = raw[OFF_CHIP_ID:OFF_CHIP_ID + LEN_CHIP_ID]

    sig_blob = raw[OFF_SIGNATURE:OFF_SIGNATURE + LEN_SIGNATURE_BLOB]

    # Spec Table 136:
    # R @ 0x000, 72 bytes, little-endian, zero-extended
    # S @ 0x048, 72 bytes, little-endian, zero-extended
    R_LEN = 72
    S_LEN = 72
    R_OFF = 0x000
    S_OFF = 0x048

    r_bytes_le = sig_blob[R_OFF:R_OFF + R_LEN]
    s_bytes_le = sig_blob[S_OFF:S_OFF + S_LEN]

    if len(r_bytes_le) != R_LEN or len(s_bytes_le) != S_LEN:
        raise ValueError("Signature blob too small for R/S fields")

    signature_r = int.from_bytes(r_bytes_le, "little", signed=False)
    signature_s = int.from_bytes(s_bytes_le, "little", signed=False)

    r_high = r_bytes_le[48:72]   # bytes 48..71 (MSB area for a 384-bit scalar)
    s_high = s_bytes_le[48:72]

    logger.info("SIG raw R_le_head=%s R_le_tail=%s", r_bytes_le[:16].hex(), r_bytes_le[-16:].hex())
    logger.info("SIG raw S_le_head=%s S_le_tail=%s", s_bytes_le[:16].hex(), s_bytes_le[-16:].hex())
    logger.info("SIG high24 R=%s S=%s", r_high.hex(), s_high.hex())
    logger.info("SIG scalars r_bits=%d s_bits=%d", signature_r.bit_length(), signature_s.bit_length())

    return ParsedReport(
        raw=raw,
        version=version,
        policy=policy,
        flags_u32=flags_u32,
        report_data=report_data,
        measurement=measurement,
        reported_tcb_u64=reported_tcb_u64,
        chip_id=chip_id,
        signature_r=signature_r,
        signature_s=signature_s,
    )


def decode_reported_tcb_components(tcb_u64: int) -> Dict[str, int]:
    # Common mapping used by AMD VCEK/KDS:
    # bits  7:0   blSPL
    # bits 15:8   teeSPL
    # bits 55:48  snpSPL
    # bits 63:56  ucodeSPL
    return {
        "blSPL": (tcb_u64 >> 0) & 0xFF,
        "teeSPL": (tcb_u64 >> 8) & 0xFF,
        "snpSPL": (tcb_u64 >> 48) & 0xFF,
        "ucodeSPL": (tcb_u64 >> 56) & 0xFF,
    }


# ----------------------------
# AMD KDS fetching + caching
# ----------------------------
async def fetch_text(session: aiohttp.ClientSession, url: str) -> str:
    async with session.get(url, timeout=aiohttp.ClientTimeout(total=25)) as resp:
        resp.raise_for_status()
        return await resp.text()


async def fetch_bytes(session: aiohttp.ClientSession, url: str) -> bytes:
    async with session.get(url, timeout=aiohttp.ClientTimeout(total=25)) as resp:
        resp.raise_for_status()
        return await resp.read()

async def ensure_cert_chain(cache_dir: Path, http: aiohttp.ClientSession, product_name: str, logger: logging.Logger) -> Path:
    product_dir = cache_dir / "certs" / product_name
    safe_mkdir(product_dir)
    chain_path = product_dir / "cert_chain.pem"
    if chain_path.exists():
        logger.info("KDS cert_chain cache hit: %s", chain_path)
        return chain_path

    url = f"{AMD_KDS_BASE}/vcek/v1/{product_name}/cert_chain"
    logger.info("Fetching AMD cert_chain: %s", url)
    chain_pem = await fetch_text(http, url)
    chain_path.write_text(chain_pem, encoding="utf-8")
    logger.info("Saved AMD cert_chain: %s", chain_path)
    return chain_path


async def ensure_vcek_cert(
    cache_dir: Path,
    http: aiohttp.ClientSession,
    product_name: str,
    chip_id: bytes,
    tcb_components: Dict[str, int],
    logger: logging.Logger,
) -> Path:
    vcek_dir = cache_dir / "vcek" / product_name
    safe_mkdir(vcek_dir)

    hwid_hex = chip_id.hex()
    qs = "&".join([f"{k}={int(v):d}" for k, v in tcb_components.items()])
    fname = f"{hwid_hex}_{tcb_components['blSPL']:02x}_{tcb_components['teeSPL']:02x}_{tcb_components['snpSPL']:02x}_{tcb_components['ucodeSPL']:02x}.der"
    vcek_path = vcek_dir / fname

    if vcek_path.exists():
        logger.info("VCEK cache hit: %s", vcek_path)
        return vcek_path

    url = f"{AMD_KDS_BASE}/vcek/v1/{product_name}/{hwid_hex}?{qs}"
    logger.info("Fetching VCEK: %s", url)
    pem = await fetch_bytes(http, url)
    vcek_path.write_bytes(pem)
    logger.info("Saved VCEK cert: %s", vcek_path)
    return vcek_path

# ----------------------------
# Signature verification
# ----------------------------
def verify_report_signature(parsed: ParsedReport, vcek_cert: x509.Certificate, logger: Optional[logging.Logger] = None) -> None:
    pub = vcek_cert.public_key()

    if logger:
        logger.info("SIG pubkey_type=%s", type(pub).__name__)

    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise ValueError(f"VCEK public key is not EC; got {type(pub).__name__}")

    if logger:
        logger.info("SIG curve=%s key_size=%s", pub.curve.name, pub.key_size)

    # Basic sanity
    if len(parsed.raw) < OFF_SIGN_START + LEN_SIGNED:
        raise ValueError(f"Report too small for signed region: len={len(parsed.raw)} need={OFF_SIGN_START+LEN_SIGNED}")
    if parsed.signature_r <= 0 or parsed.signature_s <= 0:
        raise ValueError(f"Invalid ECDSA r/s (non-positive): r={parsed.signature_r} s={parsed.signature_s}")

    try:
        n = pub.curve.key_size  # bits
        if logger:
            logger.info("SIG r_bits=%d s_bits=%d curve_bits=%d",
                        parsed.signature_r.bit_length(), parsed.signature_s.bit_length(), n)
    except Exception:
        pass

    signed_bytes = parsed.raw[OFF_SIGN_START:OFF_SIGN_START + LEN_SIGNED]

    # Hash for log correlation without dumping bytes
    if logger:
        logger.info("SIG signed_bytes_len=%d signed_bytes_sha384=%s signed_bytes_head=%s",
                    len(signed_bytes), sha384_hex(signed_bytes), trunc_hex(signed_bytes, 16))

    der_sig = utils.encode_dss_signature(parsed.signature_r, parsed.signature_s)
    if logger:
        logger.info("SIG der_sig_len=%d der_sig_head=%s", len(der_sig), trunc_hex(der_sig, 16))

    pub.verify(
        der_sig,
        signed_bytes,
        ec.ECDSA(hashes.SHA384()),
    )


# ----------------------------
# Policy evaluation
# ----------------------------
def evaluate_policy(parsed: ParsedReport, policy: Dict[str, Any]) -> None:
    """
    Supported policy keys (all optional unless noted):
      - product_name: str (REQUIRED overall, checked outside)
      - allowed_report_versions: list[int]
      - expected_measurement_hex: str (48 bytes / 96 hex chars)
      - required_policy_bits_set: int
      - forbidden_policy_bits_set: int
      - required_flags_bits_set: int
      - forbidden_flags_bits_set: int
      - chip_id_allowlist_hex: list[str] (each 64 bytes hex)
      - min_tcb: { blSPL, teeSPL, snpSPL, ucodeSPL } minimum values (0-255)
      - expected_fields: list of { "name": str, "offset": int, "length": int, "expected_hex": str }
          -> generic byte-range checks against parsed.raw (enables checking additional SNP fields safely)
    """
    if "allowed_report_versions" in policy:
        allowed = set(int(x) for x in policy["allowed_report_versions"])
        if parsed.version not in allowed:
            raise ValueError(f"Report version {parsed.version} not allowed (allowed: {sorted(allowed)})")

    if "expected_measurement_hex" in policy:
        exp = bytes.fromhex(policy["expected_measurement_hex"])
        if len(exp) != LEN_MEASUREMENT:
            raise ValueError("expected_measurement_hex must be 48 bytes (SHA-384)")
        if not constant_time_eq(parsed.measurement, exp):
            raise ValueError("Launch measurement mismatch")

    if "required_policy_bits_set" in policy:
        mask = parse_mask(policy["required_policy_bits_set"])
        if (parsed.policy & mask) != mask:
            raise ValueError(f"Policy bits check failed: required mask 0x{mask:x} not fully set in report")

    if "forbidden_policy_bits_set" in policy:
        mask = parse_mask(policy["forbidden_policy_bits_set"])
        if (parsed.policy & mask) != 0:
            raise ValueError(f"Policy bits check failed: forbidden mask 0x{mask:x} is set in report")

    if "required_flags_bits_set" in policy:
        mask = parse_mask(policy["required_flags_bits_set"])
        if (parsed.flags_u32 & mask) != mask:
            raise ValueError(f"Flags check failed: required mask 0x{mask:x} not fully set in report")

    if "forbidden_flags_bits_set" in policy:
        mask = parse_mask(policy["forbidden_flags_bits_set"])
        if (parsed.flags_u32 & mask) != 0:
            raise ValueError(f"Flags check failed: forbidden mask 0x{mask:x} is set in report")

    if "chip_id_allowlist_hex" in policy:
        allow = [bytes.fromhex(x) for x in policy["chip_id_allowlist_hex"]]
        ok = any(constant_time_eq(parsed.chip_id, a) for a in allow)
        if not ok:
            raise ValueError("Chip ID not in allowlist")

    if "min_tcb" in policy:
        tcb = decode_reported_tcb_components(parsed.reported_tcb_u64)
        mins = policy["min_tcb"] or {}
        for k in ("blSPL", "teeSPL", "snpSPL", "ucodeSPL"):
            if k in mins:
                if int(tcb[k]) < int(mins[k]):
                    raise ValueError(f"TCB component {k} too low: {tcb[k]} < {int(mins[k])}")

    if "expected_fields" in policy:
        fields = policy["expected_fields"]
        if not isinstance(fields, list):
            raise ValueError("expected_fields must be a list")
        for item in fields:
            name = str(item.get("name", "field"))
            offset = int(item["offset"])
            length = int(item["length"])
            expected_hex = str(item["expected_hex"])
            expected = bytes.fromhex(expected_hex)
            if len(expected) != length:
                raise ValueError(f"expected_fields[{name}] length mismatch: expected_hex is {len(expected)} bytes, length={length}")
            if offset < 0 or offset + length > len(parsed.raw):
                raise ValueError(f"expected_fields[{name}] out of bounds: offset={offset} length={length}")
            actual = parsed.raw[offset:offset + length]
            if not constant_time_eq(actual, expected):
                raise ValueError(f"expected_fields[{name}] mismatch")


# ----------------------------
# Server state + logging to UI
# ----------------------------
class LiveLog:
    def __init__(self, max_lines: int = 2000) -> None:
        self.max_lines = max_lines
        self._lines: list[str] = []
        self._subs: set[asyncio.Queue[str]] = set()
        self._lock = asyncio.Lock()

    async def append(self, line: str) -> None:
        async with self._lock:
            self._lines.append(line)
            if len(self._lines) > self.max_lines:
                self._lines = self._lines[-self.max_lines:]
            for q in list(self._subs):
                try:
                    q.put_nowait(line)
                except asyncio.QueueFull:
                    pass

    async def snapshot(self) -> list[str]:
        async with self._lock:
            return list(self._lines)

    def subscribe(self) -> asyncio.Queue[str]:
        q: asyncio.Queue[str] = asyncio.Queue(maxsize=200)
        self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[str]) -> None:
        self._subs.discard(q)


class UILogHandler(logging.Handler):
    def __init__(self, live: LiveLog) -> None:
        super().__init__()
        self.live = live

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            asyncio.get_event_loop().create_task(self.live.append(msg))
        except Exception:
            pass


def build_logger(log_dir: Path) -> Tuple[logging.Logger, Path, LiveLog]:
    safe_mkdir(log_dir)
    start_ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    logfile = log_dir / f"{start_ts}.log"

    logger = logging.getLogger("attestation_server")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    fmt = logging.Formatter("%(asctime)sZ %(levelname)s %(message)s")
    fileh = logging.FileHandler(logfile, encoding="utf-8")
    fileh.setFormatter(fmt)
    logger.addHandler(fileh)

    live = LiveLog(max_lines=2000)
    uih = UILogHandler(live)
    uih.setFormatter(fmt)
    logger.addHandler(uih)

    logger.info("Server logger initialized; logfile=%s", logfile)
    return logger, logfile, live


# ----------------------------
# Web handlers
# ----------------------------
async def handle_get_root(request: web.Request) -> web.StreamResponse:
    state = request.app["state"]
    live: LiveLog = state["live_log"]

    accept = request.headers.get("Accept", "")

    # SSE (still GET /)
    if "text/event-stream" in accept:
        resp = web.StreamResponse(
            status=200,
            reason="OK",
            headers={
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
            },
        )
        await resp.prepare(request)

        q = live.subscribe()
        try:
            snap = await live.snapshot()
            for line in snap[-400:]:
                data = line.replace("\n", "\\n")
                await resp.write(f"data: {data}\n\n".encode("utf-8"))

            while True:
                line = await q.get()
                data = line.replace("\n", "\\n")
                await resp.write(f"data: {data}\n\n".encode("utf-8"))
        except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            live.unsubscribe(q)
        return resp

    # Default: HTML
    html = """<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Attestation Server Log</title>
  <style>
    body { font-family: monospace; margin: 0; padding: 0; }
    header { padding: 12px 16px; border-bottom: 1px solid #ddd; }
    #log { white-space: pre-wrap; padding: 12px 16px; }
    .muted { color: #666; }
  </style>
</head>
<body>
  <header>
    <div><strong>Attestation Server Log</strong></div>
    <div class="muted">Live updates via SSE (EventSource)</div>
  </header>
  <div id="log">Connecting...</div>

  <script>
    const logEl = document.getElementById('log');
    const lines = [];
    const maxLines = 1500;

    function appendLine(s) {
      lines.push(s);
      while (lines.length > maxLines) lines.shift();
      logEl.textContent = lines.join('\\n');
      window.scrollTo(0, document.body.scrollHeight);
    }

    function startSSE() {
      const es = new EventSource('/', { withCredentials: false });
      logEl.textContent = '';
      es.onmessage = (ev) => appendLine(ev.data.replaceAll('\\\\n','\\n'));
      es.onerror = () => {
        appendLine('[SSE disconnected] Retrying in 2s...');
        es.close();
        setTimeout(startSSE, 2000);
      };
    }

    startSSE();
  </script>
</body>
</html>
"""
    return web.Response(text=html, content_type="text/html")


async def handle_post_deployment(request: web.Request) -> web.Response:
    state = request.app["state"]
    logger: logging.Logger = state["logger"]
    sessions: Dict[str, Session] = state["sessions"]
    cache_dir: Path = state["cache_dir"]
    policies_path: Path = state["policies_path"]
    secrets_path: Path = state["secrets_path"]

    deployment_name = request.match_info.get("deployment_name", "")
    if not deployment_name:
        return web.json_response({"error": "missing deployment_name in path"}, status=400)

    try:
        body = await request.json()
    except Exception:
        return web.json_response({"error": "invalid JSON"}, status=400)

    stage = body.get("stage")
    requester_name = str(body.get("requester_name", "")).strip()

    logger.info(
        "POST /%s stage=%s requester_name=%s",
        deployment_name, stage, requester_name
    )

    # Load policy + secrets
    try:
        policies = load_json_file_if_exists(policies_path, default={})
        secrets_list = load_json_file_if_exists(secrets_path, default=[])
    except Exception as e:
        logger.exception("Failed to load policies/secrets")
        return web.json_response({"error": f"server config load failed: {e}"}, status=500)

    policy = policies.get(deployment_name)
    if policy is None:
        logger.warning("No policy found for deployment_name=%s", deployment_name)
        return web.json_response({"error": "unknown deployment_name (no policy)"}, status=404)

    product_name = policy.get("product_name")
    if not product_name:
        logger.error("Policy missing product_name for deployment=%s", deployment_name)
        return web.json_response({"error": "policy missing required field: product_name"}, status=500)

    ttl = int(policy.get("nonce_ttl_seconds", 300))

    if stage == "init":
        nonce = os.urandom(64)
        nonce_b64 = base64.b64encode(nonce).decode("ascii")

        request_id = base64.urlsafe_b64encode(os.urandom(24)).decode("ascii")

        sess = Session(
            request_id=request_id,
            nonce=nonce,
            deployment_name=deployment_name,
            requester_name=requester_name,
            created_utc=now_utc_iso(),
            used=False,
        )
        sessions[request_id] = sess

        logger.info(
            "Issued nonce request_id=%s ttl=%ds deployment=%s requester=%s, nonce_b64=%s",
            request_id, ttl, deployment_name, requester_name, nonce_b64
        )

        return web.json_response({
            "request_id": request_id,
            "nonce_b64": nonce_b64,
            "expires_in_seconds": ttl,
            "deployment_name": deployment_name,
            "note": "Embed this 64-byte nonce into SNP report_data (offset 0x50, length 64). Then POST stage=attest."
        })

    if stage != "attest":
        return web.json_response({"error": "stage must be 'init' or 'attest'"}, status=400)

    # ---- ATTEST stage verbose logging begins ----
    def sha256_hex(b: bytes) -> str:
        h = hashes.Hash(hashes.SHA256())
        h.update(b)
        return h.finalize().hex()

    def policy_summary(pol: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "allowed_report_versions": pol.get("allowed_report_versions"),
            "expected_measurement_set": bool(pol.get("expected_measurement_hex")),
            "required_policy_bits_set": pol.get("required_policy_bits_set", 0),
            "forbidden_policy_bits_set": pol.get("forbidden_policy_bits_set", 0),
            "required_flags_bits_set": pol.get("required_flags_bits_set", 0),
            "forbidden_flags_bits_set": pol.get("forbidden_flags_bits_set", 0),
            "chip_id_allowlist_len": len(pol.get("chip_id_allowlist_hex", []) or []),
            "min_tcb": pol.get("min_tcb"),
            "expected_fields_len": len(pol.get("expected_fields", []) or []),
            "delete_session_after_success": bool(pol.get("delete_session_after_success", True)),
            "nonce_ttl_seconds": int(pol.get("nonce_ttl_seconds", 300)),
        }

    logger.info(
        "ATTEST begin deployment=%s requester_name=%s policy_summary=%s",
        deployment_name, requester_name, policy_summary(policy)
    )

    request_id = body.get("request_id")
    report_b64 = body.get("attestation_report_b64")

    if not isinstance(request_id, str) or not request_id:
        logger.warning("ATTEST missing request_id deployment=%s requester=%s", deployment_name, requester_name)
        return web.json_response({"error": "missing request_id"}, status=400)

    if not isinstance(report_b64, str) or not report_b64:
        logger.warning("ATTEST missing attestation_report_b64 deployment=%s requester=%s", deployment_name, requester_name)
        return web.json_response({"error": "missing attestation_report_b64"}, status=400)

    logger.info("ATTEST inputs request_id=%s report_b64_len=%d", request_id, len(report_b64))

    sess = sessions.get(request_id)
    if sess is None:
        logger.warning("ATTEST unknown request_id=%s (init required)", request_id)
        return web.json_response({"error": "unknown request_id (init required)"}, status=400)

    if sess.deployment_name != deployment_name:
        logger.warning("ATTEST deployment mismatch request_id=%s session_dep=%s url_dep=%s requester=%s", request_id, sess.deployment_name, deployment_name, requester_name)
        return web.json_response({"error": "request_id was not issued for this deployment"}, status=400)

    body_dep = body.get("deployment_name")
    if body_dep is not None and str(body_dep).strip() and str(body_dep).strip() != deployment_name:
        logger.warning(
            "ATTEST body deployment differs from URL deployment request_id=%s body_dep=%s url_dep=%s",
            request_id, body_dep, deployment_name
        )
        return web.json_response({"error": "deployment must be selected by URL path"}, status=400)

    created = parse_iso_utc(sess.created_utc)
    age = (dt.datetime.now(dt.timezone.utc) - created).total_seconds()
    logger.info("ATTEST session found created_utc=%s age_s=%.1f ttl_s=%d used=%s",
                sess.created_utc, age, ttl, sess.used)

    if age > ttl:
        logger.warning("ATTEST expired request_id=%s age=%.1fs ttl=%ds", request_id, age, ttl)
        sessions.pop(request_id, None)
        return web.json_response({"error": "request_id expired (re-init)"}, status=400)

    if sess.used:
        logger.warning("ATTEST replay attempt request_id=%s", request_id)
        return web.json_response({"error": "request_id already used"}, status=400)

    try:
        report_bytes = b64d(report_b64)
    except binascii.Error:
        logger.warning("ATTEST invalid base64 report_b64 (decode failed) request_id=%s", request_id)
        return web.json_response({"error": "attestation_report_b64 is not valid base64"}, status=400)

    logger.info("ATTEST report decoded report_bytes_len=%d", len(report_bytes))

    try:
        parsed = parse_snp_report(report_bytes, logger)
    except Exception as e:
        logger.exception("ATTEST failed to parse report request_id=%s", request_id)
        return web.json_response({"error": f"failed to parse report: {e}"}, status=400)

    tcb_components = decode_reported_tcb_components(parsed.reported_tcb_u64)

    logger.info(
        "ATTEST parsed version=%d policy_u64=0x%x flags_u32=0x%x reported_tcb_u64=0x%x tcb=%s",
        parsed.version, parsed.policy, parsed.flags_u32, parsed.reported_tcb_u64, tcb_components
    )
    logger.info("ATTEST parsed measurement_sha384_hex=%s", parsed.measurement.hex())
    logger.info("ATTEST parsed chip_id_hex=%s", parsed.chip_id.hex())
    logger.info("ATTEST parsed report_data_sha256=%s", sha256_hex(parsed.report_data))
    logger.info("ATTEST session nonce_sha256=%s", sha256_hex(sess.nonce))

    # Nonce check
    if not constant_time_eq(parsed.report_data, sess.nonce):
        logger.warning(
            "ATTEST nonce mismatch request_id=%s report_data_sha256=%s nonce_sha256=%s",
            request_id, sha256_hex(parsed.report_data), sha256_hex(sess.nonce)
        )
        return web.json_response({"error": "nonce mismatch (report_data != issued nonce)"}, status=401)

    logger.info("ATTEST nonce verified request_id=%s", request_id)

    # Policy evaluation
    logger.info("ATTEST policy evaluation begin deployment=%s", deployment_name)
    try:
        evaluate_policy(parsed, policy)
    except Exception as e:
        logger.warning("ATTEST policy evaluation FAILED deployment=%s: %s", deployment_name, e)
        return web.json_response({"error": f"policy check failed: {e}"}, status=403)
    logger.info("ATTEST policy evaluation PASSED deployment=%s", deployment_name)

    logger.info("ATTEST cert verification begin product_name=%s hwid(chip_id)=%s tcb=%s", product_name, parsed.chip_id.hex(), tcb_components)

    async with aiohttp.ClientSession() as http:
        try:
            chain_path = await ensure_cert_chain(cache_dir, http, product_name, logger)
            chain_pem = chain_path.read_text(encoding="utf-8")

            # Extract ARK/ASK as PEM files using openssl (no cryptography parsing of chain)
            ark_pem_path, ask_pem_path = ensure_ark_ask_pems_from_chain(cache_dir, product_name, chain_pem, logger)

            tcb = decode_reported_tcb_components(parsed.reported_tcb_u64)
            vcek_path = await ensure_vcek_cert(cache_dir, http, product_name, parsed.chip_id, tcb, logger)

            # Verify ASK<-ARK and VCEK<-ASK<-ARK via openssl verify
            openssl_verify_chain(
                ark_pem=ark_pem_path,
                ask_pem=ask_pem_path,
                leaf_pem=vcek_path,
                logger=logger
            )

            logger.info("OpenSSL chain verification OK (product=%s)", product_name)

            vcek_cert = x509.load_der_x509_certificate(vcek_path.read_bytes())
            pub = vcek_cert.public_key()
            logger.info("VCEK loaded: subject=%s issuer=%s pubkey_type=%s",
                        vcek_cert.subject.rfc4514_string(),
                        vcek_cert.issuer.rfc4514_string(),
                        type(pub).__name__)
            if isinstance(pub, ec.EllipticCurvePublicKey):
                logger.info("VCEK pubkey curve=%s key_size=%d", pub.curve.name, pub.key_size)

        except Exception as e:
            logger.exception("ATTEST certificate retrieval or verification failed request_id=%s", request_id)
            return web.json_response({"error": f"certificate verification failed: {e}"}, status=502)

    # Verify report signature
    logger.info("ATTEST report signature verify begin request_id=%s", request_id)

    # Pre-log the exact bytes
    try:
        signed_bytes = parsed.raw[OFF_SIGN_START:OFF_SIGN_START + LEN_SIGNED]
        logger.info(
            "ATTEST sig inputs: report_raw_len=%d signed_region_off=0x%x signed_region_len=%d sig_blob_off=0x%x sig_blob_len=%d",
            len(parsed.raw), OFF_SIGN_START, LEN_SIGNED, OFF_SIGNATURE, LEN_SIGNATURE_BLOB
        )
        logger.info("ATTEST sig inputs: signed_bytes_sha384=%s", sha384_hex(signed_bytes))
        logger.info("ATTEST sig inputs: r=%d (bits=%d) s=%d (bits=%d)",
                    parsed.signature_r, parsed.signature_r.bit_length(),
                    parsed.signature_s, parsed.signature_s.bit_length())
    except Exception as e:
        logger.warning("ATTEST sig prelog failed: %s", e)

    try:
        # Pass logger into verifier for deep detail
        verify_report_signature(parsed, vcek_cert, logger=logger)
    except Exception as e:
        # Many cryptography exceptions (e.g., InvalidSignature) stringify to empty.
        logger.warning(
            "ATTEST report signature INVALID request_id=%s exc_type=%s exc_repr=%r",
            request_id, type(e).__name__, e
        )
        logger.error("ATTEST report signature exception traceback:\n%s", traceback.format_exc())
        return web.json_response(
            {
                "error": "invalid report signature",
                "details": {
                    "exception_type": type(e).__name__,
                    "exception_repr": repr(e),
                },
            },
            status=401
        )

    logger.info("ATTEST report signature VERIFIED request_id=%s", request_id)

    # Mark nonce used (replay protection)
    sess.used = True
    logger.info("ATTEST session marked used request_id=%s", request_id)

    # Release secret
    logger.info("ATTEST secret lookup begin deployment=%s", deployment_name)
    secret = None
    for item in secrets_list:
        if item.get("deployment_name") == deployment_name:
            secret = item.get("secret")
            break

    if secret is None:
        logger.warning("ATTEST no secret configured for deployment_name=%s", deployment_name)
        return web.json_response({"error": "no secret configured for deployment"}, status=404)

    logger.info("ATTEST secret lookup success deployment=%s (secret not logged)", deployment_name)
    logger.info(
        "ATTEST success request_id=%s deployment=%s requester=%s delete_session_after_success=%s",
        request_id, deployment_name, requester_name,
        bool(policy.get("delete_session_after_success", True))
    )

    if bool(policy.get("delete_session_after_success", True)):
        sessions.pop(request_id, None)
        logger.info("ATTEST session deleted request_id=%s", request_id)

    return web.json_response({
        "deployment_name": deployment_name,
        "requester_name": requester_name,
        "request_id": request_id,
        "secret": secret,
        "report": {
            "version": parsed.version,
            "policy_u64": f"0x{parsed.policy:x}",
            "flags_u32": f"0x{parsed.flags_u32:x}",
            "measurement_hex": parsed.measurement.hex(),
            "chip_id_hex": parsed.chip_id.hex(),
            "reported_tcb_u64": f"0x{parsed.reported_tcb_u64:x}",
        }
    })

# ----------------------------
# Startup validation + background tasks
# ----------------------------
def validate_policies_structure(policies: Any) -> List[str]:
    warnings: List[str] = []
    if not isinstance(policies, dict):
        return ["policies.json root must be an object/dict"]
    for dep, pol in policies.items():
        if not isinstance(pol, dict):
            warnings.append(f"policy for '{dep}' is not a dict")
            continue
        if "product_name" not in pol:
            warnings.append(f"policy for '{dep}' missing product_name")
    return warnings


def validate_secrets_structure(secrets: Any) -> List[str]:
    warnings: List[str] = []
    if not isinstance(secrets, list):
        return ["secrets.json root must be a list"]
    for i, item in enumerate(secrets):
        if not isinstance(item, dict):
            warnings.append(f"secrets[{i}] is not a dict")
            continue
        if "deployment_name" not in item or "secret" not in item:
            warnings.append(f"secrets[{i}] missing deployment_name or secret")
    return warnings


async def session_janitor(app: web.Application) -> None:
    state = app["state"]
    logger: logging.Logger = state["logger"]
    sessions: Dict[str, Session] = state["sessions"]

    try:
        while True:
            await asyncio.sleep(30)
            # Policies loaded dynamically in handler; janitor needs a default TTL.
            default_ttl = int(state.get("default_nonce_ttl_seconds", 300))
            now = dt.datetime.now(dt.timezone.utc)
            to_delete = []
            for rid, sess in sessions.items():
                created = parse_iso_utc(sess.created_utc)
                if (now - created).total_seconds() > default_ttl * 2:
                    to_delete.append(rid)
            for rid in to_delete:
                sessions.pop(rid, None)
            if to_delete:
                logger.info("Janitor removed %d stale sessions", len(to_delete))
    except asyncio.CancelledError:
        logger.info("Janitor task cancelled; exiting")


async def warmup_kds(cache_dir: Path, policies: Dict[str, Any], logger: logging.Logger) -> None:
    # Optional warm-up: fetch cert_chain for all unique product_name values.
    products = sorted({str(pol.get("product_name")) for pol in policies.values() if isinstance(pol, dict) and pol.get("product_name")})
    if not products:
        logger.info("Warm-up skipped: no product_name values found in policies")
        return

    logger.info("Warm-up: will check KDS availability for products=%s", products)
    async with aiohttp.ClientSession() as http:
        for product in products:
            try:
                await ensure_cert_chain(cache_dir, http, product, logger)

            except Exception as e:
                logger.warning("Warm-up: cert_chain fetch failed for %s: %s", product, e)


# ----------------------------
# App bootstrap
# ----------------------------
async def start_server(args: argparse.Namespace) -> None:
    cache_dir = Path(args.cache_dir).resolve()
    log_dir = Path(args.log_dir).resolve()
    policies_path = Path(args.policies).resolve()
    secrets_path = Path(args.secrets).resolve()

    safe_mkdir(cache_dir)
    safe_mkdir(log_dir)

    logger, logfile, live_log = build_logger(log_dir)

    logger.info("Startup configuration:")
    logger.info("  bind_host=%s bind_port=%d", args.host, args.port)
    logger.info("  tls_cert=%s", args.tls_cert)
    logger.info("  tls_key=%s", args.tls_key)
    logger.info("  policies=%s", policies_path)
    logger.info("  secrets=%s", secrets_path)
    logger.info("  cache_dir=%s", cache_dir)
    logger.info("  log_dir=%s", log_dir)

    # Validate TLS files early
    for p in (Path(args.tls_cert), Path(args.tls_key)):
        if not p.exists():
            logger.error("TLS file does not exist: %s", p)
            raise SystemExit(2)
        if not p.is_file():
            logger.error("TLS path is not a file: %s", p)
            raise SystemExit(2)
        try:
            _ = p.read_bytes()
        except Exception as e:
            logger.error("TLS file not readable: %s (%s)", p, e)
            raise SystemExit(2)

    # Load and validate policies/secrets early (startup logging)
    policies = load_json_file_if_exists(policies_path, default={})
    secrets = load_json_file_if_exists(secrets_path, default=[])

    for w in validate_policies_structure(policies):
        logger.warning("Policy validation: %s", w)
    for w in validate_secrets_structure(secrets):
        logger.warning("Secrets validation: %s", w)

    # TLS context load (logs success/failure)
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ssl_ctx.load_cert_chain(args.tls_cert, args.tls_key)
        logger.info("TLS certificate and key loaded successfully")
    except Exception as e:
        logger.error("Failed to load TLS cert/key: %s", e)
        raise SystemExit(2)

    app = web.Application(client_max_size=8 * 1024 * 1024)
    app["state"] = {
        "logger": logger,
        "logfile": str(logfile),
        "live_log": live_log,
        "sessions": {},
        "cache_dir": cache_dir,
        "policies_path": policies_path,
        "secrets_path": secrets_path,
        # used by janitor; per-deployment TTL still applied in handler
        "default_nonce_ttl_seconds": 300,
    }

    app.router.add_get("/", handle_get_root)
    app.router.add_post("/{deployment_name}", handle_post_deployment)

    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, host=args.host, port=args.port, ssl_context=ssl_ctx)

    stop_event = asyncio.Event()

    def _signal_handler(sig: int, _frame: Any = None) -> None:
        logger.info("Received signal %s; initiating graceful shutdown", sig)
        stop_event.set()

    loop = asyncio.get_running_loop()
    for s in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(s, functools.partial(_signal_handler, s))
        except NotImplementedError:
            signal.signal(s, _signal_handler)

    # Start background janitor
    janitor_task = asyncio.create_task(session_janitor(app))

    # Optional warm-up
    if args.warmup_kds:
        try:
            await warmup_kds(cache_dir, policies if isinstance(policies, dict) else {}, logger)
        except Exception as e:
            logger.warning("Warm-up encountered an error (continuing): %s", e)

    # Start listening
    try:
        await site.start()
        logger.info("Server started successfully")
    except Exception as e:
        logger.error("Failed to start listening socket: %s", e)
        janitor_task.cancel()
        await runner.cleanup()
        raise

    logger.info("Listening on https://%s:%d/", args.host, args.port)
    logger.info("Log UI: open https://<host-or-ip>:%d/ in a browser", args.port)
    logger.info("Ready to accept requests")

    await stop_event.wait()

    logger.info("Stopping server (graceful)...")
    janitor_task.cancel()
    try:
        await janitor_task

    except Exception:
        pass
    await runner.cleanup()
    logger.info("Server stopped.")


def main() -> None:
    p = argparse.ArgumentParser(description="HTTPS AMD SEV-SNP attestation + secret release server")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", default=8443, type=int)
    p.add_argument("--tls-cert", required=True, help="Path to TLS certificate PEM (server cert)")
    p.add_argument("--tls-key", required=True, help="Path to TLS private key PEM")
    p.add_argument("--policies", default="policies.json", help="Path to policies JSON")
    p.add_argument("--secrets", default="secrets.json", help="Path to secrets JSON")
    p.add_argument("--cache-dir", default="./cache", help="Cache dir for AMD certs/VCEKs")
    p.add_argument("--log-dir", default="./logs", help="Directory for log files")
    p.add_argument("--warmup-kds", action="store_true", help="Warm-up KDS caches at startup (cert_chain)")
    args = p.parse_args()

    try:
        asyncio.run(start_server(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
