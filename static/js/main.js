/* ====================================================
   QR SHIELD — app.js
   Backend: Flask API at /api/v1/check  (POST, JSON body: {url})
   ==================================================== */

// ── CONFIG ──────────────────────────────────────────
// In production: same origin → leave as-is
// For local dev, change to: 'http://localhost:10000'
const API_BASE = '';

// ── STATE ───────────────────────────────────────────
let activeMode     = 'camera';
let cameraStream   = null;
let scanInterval   = null;
let scanning       = false;

// ── PARTICLES ───────────────────────────────────────
(function initParticles() {
  const canvas = document.getElementById('particles');
  const ctx    = canvas.getContext('2d');
  let W, H, pts;

  function resize() {
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }

  function makeParticles() {
    pts = Array.from({ length: 60 }, () => ({
      x:  Math.random() * W,
      y:  Math.random() * H,
      vx: (Math.random() - .5) * .4,
      vy: (Math.random() - .5) * .4,
      r:  Math.random() * 1.5 + .5,
      a:  Math.random()
    }));
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);
    pts.forEach(p => {
      p.x += p.vx; p.y += p.vy;
      p.a = Math.abs(Math.sin(Date.now() * .001 + p.x));
      if (p.x < 0) p.x = W;
      if (p.x > W) p.x = 0;
      if (p.y < 0) p.y = H;
      if (p.y > H) p.y = 0;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(0,255,65,${p.a * .35})`;
      ctx.fill();
    });
    requestAnimationFrame(draw);
  }

  resize();
  makeParticles();
  draw();
  window.addEventListener('resize', () => { resize(); makeParticles(); });
})();

// ── FOOTER CLOCK ───────────────────────────────────
setInterval(() => {
  const el = document.getElementById('ftr-time');
  if (el) el.textContent = new Date().toLocaleTimeString('en-GB');
}, 1000);

// ── MODE SWITCH ────────────────────────────────────
function switchMode(mode) {
  activeMode = mode;
  document.querySelectorAll('.mode-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.mode === mode);
  });
  document.querySelectorAll('.panel').forEach(p => {
    p.classList.toggle('active', p.id === `panel-${mode}`);
  });
  if (mode !== 'camera') stopCamera();
}

// ── TOAST ──────────────────────────────────────────
function toast(msg, type = '') {
  let el = document.getElementById('toast-el');
  if (!el) {
    el = document.createElement('div');
    el.id = 'toast-el';
    el.className = 'toast';
    document.body.appendChild(el);
  }
  el.textContent = msg;
  el.className = `toast ${type ? 'toast-' + type : ''}`;
  void el.offsetWidth;
  el.classList.add('show');
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('show'), 3200);
}

// ── CAMERA ─────────────────────────────────────────
async function startCamera() {
  try {
    const stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: 'environment', width: { ideal: 1280 }, height: { ideal: 720 } }
    });
    cameraStream = stream;
    const video = document.getElementById('video');
    video.srcObject = stream;

    // hide overlay, show controls
    document.getElementById('cam-overlay').style.display = 'none';
    document.getElementById('scan-line').style.display   = 'block';
    document.getElementById('cam-reticle').style.display = 'block';
    document.getElementById('btn-start-cam').style.display = 'none';
    document.getElementById('btn-stop-cam').style.display  = '';

    toast('Camera initialized — scanning for QR codes', 'ok');
    startQrLoop();
  } catch (e) {
    toast('Camera access denied or unavailable', 'err');
  }
}

function stopCamera() {
  if (cameraStream) {
    cameraStream.getTracks().forEach(t => t.stop());
    cameraStream = null;
  }
  clearInterval(scanInterval);
  scanInterval = null;
  const video = document.getElementById('video');
  video.srcObject = null;
  document.getElementById('cam-overlay').style.display = '';
  document.getElementById('scan-line').style.display   = 'none';
  document.getElementById('cam-reticle').style.display = 'none';
  document.getElementById('btn-start-cam').style.display = '';
  document.getElementById('btn-stop-cam').style.display  = 'none';
}

function startQrLoop() {
  const video  = document.getElementById('video');
  const canvas = document.getElementById('cam-canvas');
  const ctx    = canvas.getContext('2d', { willReadFrequently: true });

  scanInterval = setInterval(() => {
    if (video.readyState !== video.HAVE_ENOUGH_DATA) return;
    canvas.width  = video.videoWidth;
    canvas.height = video.videoHeight;
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
    const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const code = jsQR(img.data, img.width, img.height, { inversionAttempts: 'dontInvert' });
    if (code && code.data) {
      toast('QR detected! Scanning...', 'ok');
      stopCamera();
      submitUrl(code.data);
    }
  }, 300);
}

// ── FILE UPLOAD ────────────────────────────────────
function handleDrop(e) {
  e.preventDefault();
  document.getElementById('drop-zone').classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file && file.type.startsWith('image/')) handleFile(file);
  else toast('Please drop an image file', 'err');
}

function handleFile(file) {
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (ev) => {
    const img = new Image();
    img.onload = () => {
      const canvas = document.getElementById('file-canvas');
      canvas.width  = img.naturalWidth;
      canvas.height = img.naturalHeight;
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      ctx.drawImage(img, 0, 0);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: 'attemptBoth' });

      // show preview
      const prev = document.getElementById('preview-img');
      const content = document.getElementById('drop-content');
      prev.src = ev.target.result;
      prev.style.display = 'block';
      content.style.display = 'none';

      if (code && code.data) {
        toast('QR decoded: ' + code.data.slice(0, 40) + '…', 'ok');
        submitUrl(code.data);
      } else {
        toast('No QR code found in image', 'err');
        setTimeout(() => {
          prev.style.display = 'none';
          content.style.display = '';
        }, 2000);
      }
    };
    img.src = ev.target.result;
  };
  reader.readAsDataURL(file);
}

// ── URL DIRECT ─────────────────────────────────────
function scanUrl() {
  const raw = document.getElementById('url-input').value.trim();
  if (!raw) { toast('Enter a URL to scan', 'err'); return; }
  submitUrl(raw);
}

// ── SUBMIT URL TO BACKEND ──────────────────────────
async function submitUrl(rawUrl) {
  if (scanning) return;
  scanning = true;

  hideResult();
  showScanning();
  animateLogs();

  try {
    const res = await fetch(`${API_BASE}/api/v1/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: rawUrl })
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `HTTP ${res.status}`);
    }

    const data = await res.json();
    hideScanning();
    showResult(data);
  } catch (err) {
    hideScanning();
    toast('Scan failed: ' + err.message, 'err');
  } finally {
    scanning = false;
  }
}

// ── SCAN LOG ANIMATION ────────────────────────────
let logTimer = null;
function animateLogs() {
  const ids = ['log1','log2','log3','log4'];
  ids.forEach(id => {
    const el = document.getElementById(id);
    el.classList.remove('active','done');
  });
  let i = 0;
  clearInterval(logTimer);
  logTimer = setInterval(() => {
    if (i > 0) document.getElementById(ids[i-1]).classList.replace('active','done');
    if (i < ids.length) {
      document.getElementById(ids[i]).classList.add('active');
      i++;
    } else {
      clearInterval(logTimer);
    }
  }, 900);
}

// ── SHOW / HIDE STATES ─────────────────────────────
function showScanning() {
  document.getElementById('scanning-state').style.display = '';
  document.querySelectorAll('.panel').forEach(p => p.style.opacity = '.4');
}
function hideScanning() {
  document.getElementById('scanning-state').style.display = 'none';
  document.querySelectorAll('.panel').forEach(p => p.style.opacity = '');
  clearInterval(logTimer);
}
function hideResult() {
  document.getElementById('result-card').style.display = 'none';
}

// ── RENDER RESULT ─────────────────────────────────
function showResult(data) {
  const card = document.getElementById('result-card');
  card.style.display = '';

  // Scroll into view
  setTimeout(() => card.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100);

  // Status + color class
  const statusMap = {
    'SAFE':        { cls: 'status-safe',   ringCls: 'ring-safe',   icon: '✔' },
    'LOW RISK':    { cls: 'status-low',    ringCls: 'ring-low',    icon: '⚠' },
    'MEDIUM RISK': { cls: 'status-medium', ringCls: 'ring-medium', icon: '⚠' },
    'HIGH RISK':   { cls: 'status-high',   ringCls: 'ring-high',   icon: '✖' },
    'DANGER':      { cls: 'status-danger', ringCls: 'ring-danger', icon: '☠' },
  };
  const s = statusMap[data.status] || statusMap['SAFE'];

  document.getElementById('result-icon').textContent = s.icon;

  const statusEl = document.getElementById('result-status');
  statusEl.textContent = data.status;
  statusEl.className = `result-status ${s.cls}`;

  document.getElementById('result-url').textContent = data.url || '—';
  document.getElementById('result-advice').textContent = '▶ ' + (data.advice || '—');

  // Score ring
  const ringFill = document.getElementById('ring-fill');
  const scoreVal = document.getElementById('score-val');
  const circumf  = 213.6;
  const score    = Math.min(data.risk_score || 0, 100);
  ringFill.className = `ring-fill ${s.ringCls}`;

  scoreVal.textContent = '0';
  requestAnimationFrame(() => {
    ringFill.style.strokeDashoffset = circumf - (score / 100) * circumf;
    let cur = 0;
    const step = score / 60;
    const t = setInterval(() => {
      cur = Math.min(cur + step, score);
      scoreVal.textContent = Math.round(cur);
      if (cur >= score) clearInterval(t);
    }, 20);
  });

  // Threat list
  const list = document.getElementById('threat-list');
  list.innerHTML = '';
  const reasons = data.reasons || [];
  if (reasons.length) {
    reasons.forEach(r => {
      const li = document.createElement('li');
      li.textContent = r;
      list.appendChild(li);
    });
  } else {
    const li = document.createElement('li');
    li.textContent = 'No threat indicators detected';
    li.style.borderLeftColor = 'var(--safe)';
    li.style.background = 'rgba(0,255,136,.05)';
    li.style.color = 'var(--safe)';
    li.querySelector = () => {}; // dummy
    list.appendChild(li);
  }

  // Meta
  const meta = document.getElementById('meta-grid');
  meta.innerHTML = '';
  const rows = [
    ['RISK SCORE',  data.risk_percent || score + '%'],
    ['STATUS',      data.status],
    ['SCAN TIME',   data.scan_time ? new Date(data.scan_time).toLocaleTimeString() : new Date().toLocaleTimeString()],
    ['CACHED',      data.cached ? 'YES' : 'NO'],
  ];
  rows.forEach(([k, v]) => {
    const row = document.createElement('div');
    row.className = 'meta-row';
    row.innerHTML = `<span class="meta-key">${k}</span><span class="meta-val">${v}</span>`;
    meta.appendChild(row);
  });
}

// ── RESET ─────────────────────────────────────────
function resetScan() {
  hideResult();
  scanning = false;

  // reset file preview
  document.getElementById('preview-img').style.display = 'none';
  document.getElementById('drop-content').style.display = '';
  document.getElementById('file-input').value = '';

  // reset url
  document.getElementById('url-input').value = '';

  switchMode('camera');
  window.scrollTo({ top: 0, behavior: 'smooth' });
}
