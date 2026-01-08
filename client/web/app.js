const vmName = document.getElementById('vmName');
const serverUrl = document.getElementById('serverUrl');
const actualMeas = document.getElementById('actualMeas');

const requestId = document.getElementById('requestId');
const nonceB64 = document.getElementById('nonceB64');

const statusBox = document.getElementById('statusBox');
const fullResp = document.getElementById('fullResp');

function setStatus(cls, msg) {
  statusBox.className = cls || '';
  statusBox.innerHTML = msg || '';
}

function pretty(x) {
  return JSON.stringify(x, null, 2);
}

async function loadConfig() {
  const r = await fetch('/api/config');
  const j = await r.json();

  vmName.textContent = j.vm_name || '';
  serverUrl.textContent = j.server_url || '';

  if (j.actual_measurement_hex) {
    actualMeas.textContent = j.actual_measurement_hex;
  } else {
    actualMeas.textContent = '(unavailable)';
    if (j.actual_measurement_error) {
      fullResp.value = pretty({ actual_measurement_error: j.actual_measurement_error });
    }
  }
}

async function initNonce() {
  setStatus('', 'Working...');
  fullResp.value = '';

  const r = await fetch('/api/init', { method: 'POST' });
  const j = await r.json();

  fullResp.value = pretty(j);

  if (j.ok) {
    requestId.value = j.request_id || '';
    nonceB64.value = j.nonce_b64 || '';
    setStatus('ok', 'Init successful.');
  } else {
    setStatus('bad', 'Init failed. See full response below.');
  }
}

async function doAttest() {
  setStatus('', 'Working...');
  fullResp.value = '';

  const body = {
    request_id: requestId.value.trim(),
    nonce_b64: nonceB64.value.trim()
  };

  const r = await fetch('/api/attest', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });

  const j = await r.json();
  fullResp.value = pretty(j);

  if (j.secret_ok && j.secret) {
    setStatus('secret', 'Secret: <span class="mono"></span>');
    statusBox.querySelector('span').textContent = j.secret;
  } else if (j.ok) {
    setStatus('bad', 'Attest completed but no secret was returned.');
  } else {
    setStatus('bad', 'Attestation failed. See full response below.');
  }
}

document.getElementById('btnInit').onclick = initNonce;
document.getElementById('btnAttest').onclick = doAttest;

loadConfig().catch(e => setStatus('bad', 'Failed to load config: ' + e));
