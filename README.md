# Simple Attestation Verifier Service (SAVS)

SAVS is a lightweight verification + secret-release service for AMD SEV-SNP. A workload (“Attester”) requests a challenge nonce, generates an SNP attestation report that embeds this nonce, and submits the report to SAVS. SAVS verifies freshness (nonce), evaluates a deployment policy, validates the report’s certificate chain + signature via AMD’s Key Distribution Service (KDS), and—on success—returns the deployment’s secret.

Mapping to [RFC 9334](https://www.ietf.org/rfc/rfc9334.html), SAVS takes the role of a Verfier and Relying party. The Reference Values are provided in the form of a JSON file, but can be generated from tools like [ALman](https://github.com/salzg/attestation-level-manager).

SAVS is split into a Server component, which implements the main logic, and a complementary Client which can be baked into SEV-SNP CVMs. Alternatively, Workload Owners are free to use their own Client and simply interact with the Server via REST API. The SAVS Client comes in a CLI variant or a more interactive web variant (you can edit nonces, for example).

---

## General Flow

1. **Init phase**  
   The Client requests a fresh nonce for a given deployment (characterized by the endpoint the request is submitted to).
2. **Attestation phase**  
   The Client generates an SNP attestation report embedding the nonce and submits it to SAVS.
3. **Verification**  
   SAVS validates:
   * nonce freshness
   * report structure and version
   * deployment policy (Measurement, flags, TCB, etc.)
   * certificate chain and signature via AMD KDS
4. **Secret release**  
   If verification succeeds, SAVS returns the configured secret.

## Repository structure

```
.
├── server/
│ ├── server.py             # HTTPS SAVS server
│ ├── policies.json         # Deployment policies
│ ├── secrets.json          # Deployment secrets
│ └── cache/                # Cached AMD certs (runtime)
├── client/
│ ├── client.py             # CLI client
│ ├── client_config.json    # Client configuration
│ ├── client-frontend.py    # Optional web frontend
│ └── web/                  # Static frontend assets
```

---

## Prerequisites

### Hardware / Platform

* Client must run inside an AMD SEV-SNP enabled guest
* `snpguest` must be available inside the guest

### Software

* Python 3
* `openssl` (server side)

### Python dependencies

* Server:
  * `aiohttp`
  * `cryptography`
* Client:
  * `requests`

Example:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install aiohttp cryptography requests
```

---

## Quickstart

### 1. TLS certificates

SAVS **requires HTTPS**.

For testing, generate a self-signed certificate:

```bash
openssl req -x509 -newkey rsa:2048 \
    -keyout server.key -out server.crt \
    -days 365 -nodes \
    -subj "/CN=savs-server"
```


### 2. Configure deployments

#### server/secrets.json

Maps deployment names to secrets returned after successful attestation. Adjust to your preference.

```JSON
[
    {
        "deployment_name": "my-deployment",
        "secret": "super-secret-value"
    }
]
```


#### server/policies.json

Each top-level key defines one deployment policy.

Minimal example:

```JSON
{
    "my-deployment": {
        "product_name": "Milan",
        "nonce_ttl_seconds": 300,
        "allowed_report_versions": [4],
        "expected_measurement_hex": "A5E1C7754D10F9CD6F86262421DBB7C1AB425F91C3F815B05B543506AE062574C5D2176C972AE9383EEC80CDF8D26C28",
        "delete_session_after_success": true
    }
}
```

*Commonly used policy fields:*

* product_name  
  AMD product line used for KDS lookup (e.g. Milan)
* allowed_report_versions  
  Accepted SNP report versions
* expected_measurement_hex  
  Expected launch measurement (primary identity check)
* nonce_ttl_seconds  
  Validity of issued nonces
* delete_session_after_success  
  Whether to remove the request session after success

*Optional hardening*

* chip_id_allowlist_hex  
  List of the only accepted ChipIDs
* min_tcb `"min_tcb": { "blSPL": 0, "teeSPL": 0, "snpSPL": 0, "ucodeSPL": 0 }`  
  minimum TCB
* required_(flags|bits)_bits_set / forbidden_(flags|bits)_bits_set  
  masks for flags (see offset 48h in SNP attestation report) and policy (Guest Policy, 08h offset) checking
* expected_fields (byte-range checks in the report)  
  custom by-range checks

---

### 3. Run the server

From the repository root:

```bash
python3 server/server.py \
    --host 0.0.0.0 \
    --port 8443 \
    --tls-cert ./server.crt \
    --tls-key ./server.key \
    --policies ./server/policies.json \
    --secrets ./server/secrets.json \
    --cache-dir ./server/cache \
    --log-dir ./server/logs
```

Log UI (server-side): *https://\<server-ip\>:8443/*


---

### 4. Configure the client

Edit client/client_config.json:

```JSON
{
"server_ip": "include server IP here",
"server_port": 8443,
"deployment_name": "my-deployment",
"requester_name": "alice",

"tls_verify": false,
"timeout_seconds": 25,

"work_dir": "/tmp/snp_client",
"keep_artifacts": false,

"snpguest_path": "/usr/local/bin/snpguest"
}
```

Notes:
* Client typically needs **root privileges** (for snpguest)
* Set tls_verify to true if using a trusted CA certificate

---

### 5. Run the client

Inside the SEV-SNP guest:

```
sudo python3 client/client.py client/client_config.json
```

On success, the secret is printed to stdout.

---

## Using the REST API directly

You can implement your own client using the REST interface.

### Init phase

Request:
```http
POST /<deployment_name>
````
```JSON
{
"stage": "init",
"requester_name": "alice"
}
```

Response:

```JSON
{
"request_id": "...",
"nonce_b64": "...",
"expires_in_seconds": 300,
"deployment_name": "my-deployment"
}
```


The decoded nonce must be embedded into the SNP report’s REPORT_DATA field.

---

### Attestation phase

Request:

```http
POST /<deployment_name>
````
```JSON
{
"stage": "attest",
"request_id": "...",
"requester_name": "alice",
"attestation_report_b64": "..."
}
```

Successful Response:

```JSON
{
    "deployment_name": "my-deployment",
    "request_id": "...",
    "secret": "super-secret-value",
    "report": {
        "version": 4,
        "measurement_hex": "...",
        "chip_id_hex": "...",
        "reported_tcb_u64": "0x..."
    }
}
```


Failures return a JSON error and an appropriate HTTP status code.

---

## Optional web frontend

The repository includes a minimal HTTPS frontend that wraps the client workflow.

Generate a certificate:

```bash
openssl req -x509 -newkey rsa:2048 \
    -keyout frontend.key -out frontend.crt \
    -days 365 -nodes \
    -subj "/CN=savs-client-frontend" 
```

Run inside the SEV-SNP guest:

```bash
sudo python3 client/client-frontend.py \
    --tls-cert ./frontend.crt \
    --tls-key ./frontend.key \
    --client-config ./client/client_config.json \
    --host 0.0.0.0 \
    --port 9443
```

---

## Operational notes

* Nonce freshness prevents replay attacks
* Policies are the security boundary: Attestation is only meaningful when coupled with strict policy enforcement
* Measurement updates require updating expected_measurement_hex
* Certificate caching reduces repeated AMD KDS lookups
