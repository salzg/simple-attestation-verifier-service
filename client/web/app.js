const requesterName = document.getElementById('requesterName');
const deploymentName = document.getElementById('deploymentName');
const defaultDeploymentName = document.getElementById('defaultDeploymentName');
const serverBaseUrl = document.getElementById('serverBaseUrl');
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

function currentDeployment() {
  return (deploymentName.value || '').trim();
}

async function loadConfig() {
  const r = await fetch('/api/config');
  const j = await r.json();

  requesterName.textContent = j.requester_name || '';
  serverBaseUrl.textContent = j.server_base_url || '';

  // default deployment from config, but user can override
  const cfgDep = (j.deployment_name || '').trim();
  if (defaultDeploymentName) defaultDeploymentName.textContent = cfgDep;

  if (!deploymentName.value) {
    deploymentName.value = cfgDep;
  }

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

  const dep = currentDeployment();
  if (!dep) {
    setStatus('bad', 'Deployment name is required.');
    return;
  }

  const r = await fetch('/api/init', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ deployment_name: dep })
  });

  const j = await r.json();

  fullResp.value = pretty(j);

  if (j.ok) {
    requestId.value = j.request_id || '';
    nonceB64.value = j.nonce_b64 || '';
    setStatus('ok', `Init successful (deployment=${dep}).`);
  } else {
    setStatus('bad', 'Init failed. See full response below.');
  }
}

async function doAttest() {
  setStatus('', 'Working...');
  fullResp.value = '';

  const dep = currentDeployment();
  if (!dep) {
    setStatus('bad', 'Deployment name is required.');
    return;
  }

  const body = {
    deployment_name: dep,
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
