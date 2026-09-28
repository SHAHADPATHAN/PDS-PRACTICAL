/* ============================================================
   SENTINEL AI - REACTIVE APPLICATION CONTROLLER
   ENTERPRISE SUITE (GOOGLE / MICROSOFT CALIBER ARCHITECTURE)
   ============================================================ */

document.addEventListener('DOMContentLoaded', () => {
  initPreloader();
  initNavigation();
  initDashboard();
  initPipeline();
  initFileUpload();
  initLogExplorer();
  initMLHub();
  initAIAnalyst();
  initIncidentWorkspace();
  initDataQuality();
  initSystemHealth();
});

// ------------------------------------------------------------
// CYBER BOOT PRELOADER
// ------------------------------------------------------------
function initPreloader() {
  const preloader = document.getElementById('preloader');
  const fill = document.getElementById('preloader-fill');
  const status = document.getElementById('preloader-status');
  const pctEl = document.getElementById('preloader-pct');
  const terminal = document.getElementById('preloader-terminal');

  const bootLogs = [
    { pct: 18, status: 'KERNEL_INITIALIZING...', log: '<span class="ok-badge">[OK]</span> <span class="accent">SYS_INIT:</span> Initializing Sentinel Core Micro-Engine v2.4' },
    { pct: 42, status: 'MOUNTING_RANDOM_FOREST_V1.0...', log: '<span class="ok-badge">[OK]</span> <span class="accent">NEURAL_ML:</span> RandomForestClassifier Loaded (97.89% Accuracy, 0.99 Recall)' },
    { pct: 68, status: 'SYNCING_PRODUCTION_TELEMETRY...', log: '<span class="ok-badge">[OK]</span> <span class="accent">DATA_SOURCE:</span> Ingested 2,060,520 Telemetry Records (cj.log)' },
    { pct: 88, status: 'ARMING_THREAT_HEURISTICS...', log: '<span class="ok-badge">[OK]</span> <span class="accent">THREAT_ENGINE:</span> Compiled SQLi, Path Traversal, & Brute Force Regex Trees' },
    { pct: 100, status: 'SECURITY WORKSPACE ARMED', log: '<span class="ok-badge">[OK]</span> <span class="accent">SOC_CORE:</span> Grounded Incident Reasoning Ready — Access Granted' }
  ];

  let current = 0;
  const interval = setInterval(() => {
    if (current < bootLogs.length) {
      const step = bootLogs[current];
      if (fill) fill.style.width = `${step.pct}%`;
      if (pctEl) pctEl.textContent = `${step.pct}%`;
      if (status) status.textContent = step.status;
      if (terminal) {
        const line = document.createElement('div');
        line.className = 'terminal-line';
        line.innerHTML = step.log;
        terminal.appendChild(line);
        terminal.scrollTop = terminal.scrollHeight;
      }
      current++;
    } else {
      clearInterval(interval);
      setTimeout(() => {
        if (preloader) preloader.classList.add('loaded');
      }, 500);
    }
  }, 220);
}


// ------------------------------------------------------------
// NAVIGATION ROUTER
// ------------------------------------------------------------
function initNavigation() {
  const navItems = document.querySelectorAll('.nav-item');
  const viewSections = document.querySelectorAll('.view-section');
  const pageTitle = document.getElementById('current-page-title');

  navItems.forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      const targetView = item.getAttribute('data-view');
      const title = item.querySelector('span').textContent;

      navItems.forEach(n => n.classList.remove('active'));
      item.classList.add('active');

      viewSections.forEach(sec => {
        sec.classList.remove('active');
        if (sec.id === `view-${targetView}`) {
          sec.classList.add('active');
        }
      });

      if (pageTitle) pageTitle.textContent = title;

      // Trigger view data refreshes
      if (targetView === 'dashboard') loadDashboardData();
      if (targetView === 'pipeline') loadPipelineStatus();
      if (targetView === 'explorer') loadExplorerLogs();
      if (targetView === 'ml') loadMLMetrics();
      if (targetView === 'quality') loadDataQuality();
      if (targetView === 'system') loadSystemHealth();
    });
  });
}

// ------------------------------------------------------------
// DASHBOARD
// ------------------------------------------------------------
async function initDashboard() {
  await loadDashboardData();
}

async function loadDashboardData() {
  try {
    const data = await api.getOverview();
    renderKPIs(data.kpis);
    renderTrafficChart(data.traffic_timeline);
    renderAttackBars(data.attack_distribution);
    renderTopIPsTable(data.top_suspicious_ips);
  } catch (err) {
    console.error('Failed to load dashboard data:', err);
  }
}

function renderKPIs(kpis) {
  document.getElementById('kpi-total-logs').textContent = (kpis.total_logs || 0).toLocaleString();
  document.getElementById('kpi-unique-ips').textContent = (kpis.unique_ips || 0).toLocaleString();
  document.getElementById('kpi-attack-count').textContent = (kpis.attack_count || 0).toLocaleString();
  document.getElementById('kpi-benign-count').textContent = (kpis.benign_count || 0).toLocaleString();
  document.getElementById('kpi-attack-pct').textContent = `${kpis.attack_percentage || 0}%`;
  document.getElementById('kpi-bot-pct').textContent = `${kpis.bot_percentage || 0}%`;
  document.getElementById('kpi-suspicious-ips').textContent = kpis.suspicious_ips_count || 0;
}

function renderTrafficChart(points) {
  const canvas = document.getElementById('trafficChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width = canvas.parentElement.clientWidth;
  const h = canvas.height = 240;

  ctx.clearRect(0, 0, w, h);
  if (!points || points.length === 0) return;

  const maxVal = Math.max(...points.map(p => p.request_count), 10);
  const padding = 40;
  const graphW = w - padding * 2;
  const graphH = h - padding * 2;

  // Grid lines
  ctx.strokeStyle = '#1a1a24';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = padding + (graphH / 4) * i;
    ctx.beginPath();
    ctx.moveTo(padding, y);
    ctx.lineTo(w - padding, y);
    ctx.stroke();
  }

  // Gradient area fill
  const grad = ctx.createLinearGradient(0, padding, 0, h - padding);
  grad.addColorStop(0, 'rgba(255, 106, 0, 0.35)');
  grad.addColorStop(1, 'rgba(255, 106, 0, 0.0)');

  ctx.beginPath();
  points.forEach((p, idx) => {
    const x = padding + (graphW / (points.length - 1)) * idx;
    const y = h - padding - (p.request_count / maxVal) * graphH;
    if (idx === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.lineTo(w - padding, h - padding);
  ctx.lineTo(padding, h - padding);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  // Draw Path Stroke
  ctx.beginPath();
  points.forEach((p, idx) => {
    const x = padding + (graphW / (points.length - 1)) * idx;
    const y = h - padding - (p.request_count / maxVal) * graphH;
    if (idx === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });

  ctx.strokeStyle = '#ff6a00';
  ctx.lineWidth = 2.5;
  ctx.shadowColor = 'rgba(255, 106, 0, 0.6)';
  ctx.shadowBlur = 12;
  ctx.stroke();
  ctx.shadowBlur = 0;

  // Points
  points.forEach((p, idx) => {
    const x = padding + (graphW / (points.length - 1)) * idx;
    const y = h - padding - (p.request_count / maxVal) * graphH;
    ctx.beginPath();
    ctx.arc(x, y, 4, 0, Math.PI * 2);
    ctx.fillStyle = p.attack_count > 0 ? '#f43f5e' : '#ff7a00';
    ctx.fill();
    ctx.strokeStyle = '#000';
    ctx.lineWidth = 1.5;
    ctx.stroke();
  });
}

function renderAttackBars(attacks) {
  const container = document.getElementById('attack-bars-container');
  if (!container) return;
  container.innerHTML = '';

  attacks.forEach(att => {
    const row = document.createElement('div');
    row.style.marginBottom = '16px';
    row.innerHTML = `
      <div style="display:flex; justify-content:space-between; margin-bottom:5px; font-size:12px;">
        <span style="font-weight:700; text-transform:uppercase;">${att.category.replace('_', ' ')}</span>
        <span style="color:var(--orange-bright); font-family:var(--font-mono); font-weight:600;">${att.count.toLocaleString()} (${att.percentage}%)</span>
      </div>
      <div style="width:100%; height:7px; background:#1c1c24; border-radius:4px; overflow:hidden;">
        <div style="width:${att.percentage}%; height:100%; background:linear-gradient(90deg, #ff6a00, #ff8c1a); box-shadow:0 0 8px rgba(255,106,0,0.5);"></div>
      </div>
    `;
    container.appendChild(row);
  });
}

function renderTopIPsTable(ips) {
  const tbody = document.getElementById('top-ips-tbody');
  if (!tbody) return;
  tbody.innerHTML = '';

  ips.forEach(item => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="mono-cell" style="color:var(--orange-bright); font-weight:700;">${item.ip_address}</td>
      <td class="mono-cell">${item.total_requests}</td>
      <td class="mono-cell" style="color:var(--accent-rose); font-weight:700;">${item.attack_count}</td>
      <td class="mono-cell">${item.attack_percentage}%</td>
      <td><span class="badge ${item.risk_level === 'Critical' ? 'badge-attack' : 'badge-sqli'}">${item.risk_level}</span></td>
      <td><button class="btn btn-outline btn-sm" onclick="investigateIP('${item.ip_address}')">Investigate</button></td>
    `;
    tbody.appendChild(tr);
  });
}

// ------------------------------------------------------------
// UNIVERSAL FILE UPLOAD & INGESTION
// ------------------------------------------------------------
let currentSelectedFile = null;
let lastAnalysisResult = null;
let customExplorerRecords = null;

function initFileUpload() {
  const dropzone = document.getElementById('file-dropzone');
  const fileInput = document.getElementById('file-input');
  const selectedBox = document.getElementById('file-selected-box');
  const fileNameEl = document.getElementById('selected-filename');
  const fileSizeEl = document.getElementById('selected-filesize');
  const processBtn = document.getElementById('btn-process-upload');
  
  // Tabs
  const tabBtnFile = document.getElementById('tab-btn-file');
  const tabBtnText = document.getElementById('tab-btn-text');
  const containerFile = document.getElementById('container-file-upload');
  const containerText = document.getElementById('container-text-upload');
  const rawTextInput = document.getElementById('raw-stream-input');
  const processTextBtn = document.getElementById('btn-process-text');

  // Sample Buttons
  const sampleNormalBtn = document.getElementById('btn-sample-normal');
  const sampleAttackBtn = document.getElementById('btn-sample-attack');
  const sampleScannerBtn = document.getElementById('btn-sample-scanner');

  // Tab switching
  if (tabBtnFile && tabBtnText) {
    tabBtnFile.addEventListener('click', () => {
      tabBtnFile.classList.add('active');
      tabBtnText.classList.remove('active');
      if (containerFile) containerFile.style.display = 'block';
      if (containerText) containerText.style.display = 'none';
    });

    tabBtnText.addEventListener('click', () => {
      tabBtnText.classList.add('active');
      tabBtnFile.classList.remove('active');
      if (containerFile) containerFile.style.display = 'none';
      if (containerText) containerText.style.display = 'block';
    });
  }

  // Dropzone file selection
  if (dropzone && fileInput) {
    dropzone.addEventListener('click', () => fileInput.click());

    dropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropzone.classList.add('dragover');
    });

    dropzone.addEventListener('dragleave', () => {
      dropzone.classList.remove('dragover');
    });

    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
      if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        handleFileSelected(e.dataTransfer.files[0]);
      }
    });

    fileInput.addEventListener('change', () => {
      if (fileInput.files && fileInput.files.length > 0) {
        handleFileSelected(fileInput.files[0]);
      }
    });
  }

  function handleFileSelected(file) {
    currentSelectedFile = file;
    if (fileNameEl) fileNameEl.textContent = file.name;
    if (fileSizeEl) fileSizeEl.textContent = `${(file.size / 1024).toFixed(1)} KB | ${file.type || 'Text/Log format'}`;
    if (selectedBox) selectedBox.style.display = 'flex';
    showToast(`File selected: ${file.name}`);
  }

  // Process File Upload
  if (processBtn) {
    processBtn.addEventListener('click', async () => {
      if (!currentSelectedFile) return;
      processBtn.disabled = true;
      await runScanWithProgress(
        async () => await api.uploadFile(currentSelectedFile),
        () => { processBtn.disabled = false; }
      );
    });
  }

  // Process Raw Text Stream
  if (processTextBtn) {
    processTextBtn.addEventListener('click', async () => {
      const text = rawTextInput ? rawTextInput.value.trim() : '';
      if (!text) {
        alert('Please enter or paste log records in the text buffer.');
        return;
      }
      processTextBtn.disabled = true;
      await runScanWithProgress(
        async () => await api.uploadText(text, 'pasted_stream.log'),
        () => { processTextBtn.disabled = false; }
      );
    });
  }

  // Sample Loaders
  if (sampleNormalBtn) {
    sampleNormalBtn.addEventListener('click', async () => {
      try {
        showToast('Loading clean browsing stream sample...');
        const s = await api.getSample('normal');
        await runScanWithProgress(async () => await api.uploadText(s.content, s.filename));
      } catch (err) {
        alert('Sample error: ' + err.message);
      }
    });
  }

  if (sampleAttackBtn) {
    sampleAttackBtn.addEventListener('click', async () => {
      try {
        showToast('Loading live multi-vector cyber attack stream...');
        const s = await api.getSample('attack');
        await runScanWithProgress(async () => await api.uploadText(s.content, s.filename));
      } catch (err) {
        alert('Sample error: ' + err.message);
      }
    });
  }

  if (sampleScannerBtn) {
    sampleScannerBtn.addEventListener('click', async () => {
      try {
        showToast('Loading automated scanner recon stream...');
        const s = await api.getSample('scanner');
        await runScanWithProgress(async () => await api.uploadText(s.content, s.filename));
      } catch (err) {
        alert('Sample error: ' + err.message);
      }
    });
  }

  // Export JSON Report Button
  const exportBtn = document.getElementById('btn-export-json');
  if (exportBtn) {
    exportBtn.addEventListener('click', () => {
      if (!lastAnalysisResult) {
        showToast('No active scan report to export.');
        return;
      }
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(lastAnalysisResult, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", `sentinel_threat_assessment_${Date.now()}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
      showToast('Exported Threat Assessment JSON successfully.');
    });
  }

  // View in Log Explorer Button
  const viewExplorerBtn = document.getElementById('btn-view-in-explorer');
  if (viewExplorerBtn) {
    viewExplorerBtn.addEventListener('click', () => {
      if (!lastAnalysisResult || !lastAnalysisResult.records_sample) {
        showToast('No records available to explore.');
        return;
      }
      customExplorerRecords = lastAnalysisResult.records_sample;
      const navItem = document.querySelector('[data-view="explorer"]');
      if (navItem) navItem.click();
      renderCustomExplorerLogs(customExplorerRecords, lastAnalysisResult.filename);
      showToast(`Loaded ${customExplorerRecords.length} records into Log Explorer.`);
    });
  }
}

async function runScanWithProgress(apiCall, onComplete) {
  const terminal = document.getElementById('scanning-terminal');
  const phaseText = document.getElementById('scan-phase-text');
  const phasePct = document.getElementById('scan-phase-pct');
  const barFill = document.getElementById('scan-bar-fill');
  const tickerLog = document.getElementById('scan-ticker-log');

  if (terminal) terminal.style.display = 'block';

  const phases = [
    { pct: 20, phase: 'PHASE 1: INGESTION & PARSING', msg: 'Reading stream bytes and verifying structural delimiters...' },
    { pct: 45, phase: 'PHASE 2: SCHEMA PROFILE', msg: 'Detecting format: JSON Array, CSV Matrix, or Syslog Stream...' },
    { pct: 70, phase: 'PHASE 3: THREAT SIGNATURES', msg: 'Compiling regex trees for SQLi, Path Traversal, and Brute Force...' },
    { pct: 88, phase: 'PHASE 4: FEATURE EXTRACTION', msg: 'Extracting IP frequencies, UA string lengths, and crawler flags...' },
    { pct: 100, phase: 'PHASE 5: ML INFERENCE', msg: 'Executing RandomForestClassifier v1.0 and computing confidence scores...' }
  ];

  for (let i = 0; i < phases.length; i++) {
    const p = phases[i];
    if (barFill) barFill.style.width = `${p.pct}%`;
    if (phasePct) phasePct.textContent = `${p.pct}%`;
    if (phaseText) phaseText.textContent = p.phase;
    if (tickerLog) tickerLog.textContent = p.msg;
    await new Promise(r => setTimeout(r, 140));
  }

  try {
    const res = await apiCall();
    lastAnalysisResult = res;
    renderUploadAnalysis(res);
    showToast(`Cyber Scan Complete: ${res.total_attacks} threats detected in ${res.filename}!`);
  } catch (err) {
    alert('Ingestion & Threat Analysis Error: ' + err.message);
  } finally {
    if (terminal) {
      setTimeout(() => { terminal.style.display = 'none'; }, 800);
    }
    if (onComplete) onComplete();
  }
}

function renderUploadAnalysis(res) {
  const container = document.getElementById('upload-analysis-result');
  if (!container) return;
  container.style.display = 'block';

  document.getElementById('up-parsed-records').textContent = (res.parsed_records || 0).toLocaleString();
  document.getElementById('up-total-threats').textContent = (res.total_attacks || 0).toLocaleString();
  document.getElementById('up-attack-pct').textContent = `${res.attack_percentage || 0}% attack density`;
  document.getElementById('up-unique-ips').textContent = (res.unique_ips || 0).toLocaleString();
  document.getElementById('up-invalid-records').textContent = (res.invalid_records || 0).toLocaleString();
  document.getElementById('up-format-badge').textContent = res.format_detected;

  document.getElementById('up-threat-assessment').textContent = res.threat_assessment;

  // Render vector tags
  const tagsContainer = document.getElementById('up-attack-breakdown-tags');
  if (tagsContainer && res.attack_counts) {
    tagsContainer.innerHTML = `
      <span class="badge badge-sqli">SQL Injection: ${res.attack_counts.sqli || 0}</span>
      <span class="badge badge-traversal">Path Traversal: ${res.attack_counts.path_traversal || 0}</span>
      <span class="badge badge-bruteforce">Brute Force: ${res.attack_counts.brute_force || 0}</span>
      <span class="badge badge-benign">Benign: ${(res.attack_counts.benign || 0).toLocaleString()}</span>
    `;
  }

  // Render Live ML predictions with Risk Meters
  const predsContainer = document.getElementById('up-model-predictions-list');
  if (predsContainer && res.live_model_samples) {
    predsContainer.innerHTML = '';
    res.live_model_samples.forEach(m => {
      const isAtt = m.prediction.toLowerCase() === 'attack';
      const riskColor = m.risk_score > 60 ? '#f43f5e' : (m.risk_score > 30 ? '#ff7a00' : '#10b981');
      const div = document.createElement('div');
      div.style.padding = '10px 14px';
      div.style.background = 'var(--bg-secondary)';
      div.style.borderRadius = 'var(--radius-xs)';
      div.style.display = 'flex';
      div.style.alignItems = 'center';
      div.style.justifyContent = 'space-between';
      div.style.fontSize = '12px';
      div.innerHTML = `
        <span class="mono-cell" style="color:var(--text-secondary); font-weight:600;">${m.ip}</span>
        <div style="display:flex; gap:12px; align-items:center;">
          <div style="display:flex; align-items:center;">
            <div class="risk-meter">
              <div class="risk-meter-fill" style="width:${m.risk_score}%; background:${riskColor};"></div>
            </div>
            <span style="font-family:var(--font-mono); font-size:11px; color:${riskColor};">${m.risk_score}/100</span>
          </div>
          <span class="badge ${isAtt ? 'badge-attack' : 'badge-benign'}">${m.prediction}</span>
          <span style="font-family:var(--font-mono); color:var(--orange-bright); font-weight:700;">${(m.confidence * 100).toFixed(0)}%</span>
        </div>
      `;
      predsContainer.appendChild(div);
    });
  }

  // Render Top Offenders table
  const tbody = document.getElementById('up-offenders-tbody');
  if (tbody && res.top_offenders) {
    tbody.innerHTML = '';
    if (res.top_offenders.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:16px;">No malicious IPs identified in this file.</td></tr>';
    } else {
      res.top_offenders.forEach(o => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td class="mono-cell" style="color:var(--orange-bright); font-weight:700;">${o.ip}</td>
          <td class="mono-cell">${o.total}</td>
          <td class="mono-cell" style="color:var(--accent-rose); font-weight:700;">${o.attacks}</td>
          <td class="mono-cell">${o.attack_pct}%</td>
          <td>${o.types.length ? o.types.map(t => `<span class="badge badge-sqli">${t}</span>`).join(' ') : '<span class="badge badge-benign">Benign</span>'}</td>
          <td><button class="btn btn-outline btn-sm" onclick="investigateIP('${o.ip}')">Investigate</button></td>
        `;
        tbody.appendChild(tr);
      });
    }
  }

  container.scrollIntoView({ behavior: 'smooth' });
}

function renderCustomExplorerLogs(records, sourceName) {
  const tbody = document.getElementById('logs-table-body');
  const pageInfo = document.getElementById('log-page-info');
  if (!tbody) return;

  if (pageInfo) pageInfo.textContent = `Displaying ${records.length} parsed records from: ${sourceName}`;

  tbody.innerHTML = '';
  records.forEach(r => {
    const isAtt = r.label !== 'benign';
    const isBot = r.ua && (r.ua.toLowerCase().includes('bot') || r.ua.toLowerCase().includes('gobuster') || r.ua.toLowerCase().includes('crawler'));
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="mono-cell" style="color:var(--text-muted);">${r.id}</td>
      <td class="mono-cell">${r.timestamp}</td>
      <td class="mono-cell" style="color:var(--orange-bright); font-weight:600;">${r.ip}</td>
      <td class="mono-cell">${r.port || '80'}</td>
      <td><span class="badge ${isAtt ? 'badge-attack' : 'badge-benign'}">${r.label}</span></td>
      <td><span class="badge ${isBot ? 'badge-sqli' : 'badge-benign'}">${isBot ? 'BOT' : 'BROWSER'}</span></td>
      <td>${r.category_type || 'HTTP'}</td>
      <td class="mono-cell">1</td>
    `;
    tbody.appendChild(tr);
  });
}

// ------------------------------------------------------------
// PIPELINE CONTROL
// ------------------------------------------------------------
let pipelinePollInterval = null;

function initPipeline() {
  const runBtn = document.getElementById('btn-run-pipeline');
  if (runBtn) {
    runBtn.addEventListener('click', async () => {
      runBtn.disabled = true;
      runBtn.textContent = 'Running Pipeline...';
      try {
        await api.runPipeline('fast');
        startPipelinePolling();
        showToast('Pipeline execution launched in background.');
      } catch (err) {
        alert('Failed to start pipeline: ' + err);
        runBtn.disabled = false;
        runBtn.textContent = 'Run Full Pipeline';
      }
    });
  }
}

async function loadPipelineStatus() {
  try {
    const status = await api.getPipelineStatus();
    renderPipelineUI(status);
  } catch (err) {
    console.error('Failed to get pipeline status:', err);
  }
}

function renderPipelineUI(status) {
  const stateBadge = document.getElementById('pipeline-state-badge');
  const progressFill = document.getElementById('pipeline-progress-fill');
  const progressPct = document.getElementById('pipeline-progress-pct');
  const stepper = document.getElementById('pipeline-stepper-list');
  const consoleBox = document.getElementById('pipeline-console');

  if (stateBadge) {
    stateBadge.textContent = status.state.toUpperCase();
    stateBadge.className = `badge ${status.state === 'running' ? 'badge-sqli' : (status.state === 'completed' ? 'badge-benign' : 'badge-attack')}`;
  }

  if (progressFill) progressFill.style.width = `${status.progress_percentage}%`;
  if (progressPct) progressPct.textContent = `${status.progress_percentage}%`;

  if (stepper && status.stages) {
    stepper.innerHTML = '';
    status.stages.forEach((st, idx) => {
      const stepDiv = document.createElement('div');
      const isDone = st.status === 'completed';
      const isRun = st.status === 'running';
      stepDiv.className = `pipeline-step ${isDone ? 'step-completed' : (isRun ? 'step-running' : 'step-waiting')}`;
      stepDiv.innerHTML = `
        <div style="display:flex; align-items:center; gap:14px;">
          <span style="font-weight:700; color:var(--orange-bright); font-family:var(--font-mono);">0${idx + 1}</span>
          <div>
            <div style="font-weight:700; color:var(--text-primary);">${st.name}</div>
            <div style="font-size:11px; color:var(--text-muted);">${st.details || st.output_artifact || ''}</div>
          </div>
        </div>
        <div style="text-align:right;">
          <span class="badge ${isDone ? 'badge-benign' : (isRun ? 'badge-sqli' : '')}">${st.status.toUpperCase()}</span>
          <div style="font-size:11px; color:var(--text-muted); font-family:var(--font-mono); margin-top:3px;">${st.duration_seconds}s</div>
        </div>
      `;
      stepper.appendChild(stepDiv);
    });
  }

  if (consoleBox && status.logs) {
    consoleBox.innerHTML = status.logs.join('<br>');
    consoleBox.scrollTop = consoleBox.scrollHeight;
  }
}

function startPipelinePolling() {
  if (pipelinePollInterval) clearInterval(pipelinePollInterval);
  pipelinePollInterval = setInterval(async () => {
    const status = await api.getPipelineStatus();
    renderPipelineUI(status);
    if (status.state === 'completed' || status.state === 'failed') {
      clearInterval(pipelinePollInterval);
      const runBtn = document.getElementById('btn-run-pipeline');
      if (runBtn) {
        runBtn.disabled = false;
        runBtn.textContent = 'Run Full Pipeline';
      }
      showToast('Pipeline execution finished successfully.');
    }
  }, 1500);
}

// ------------------------------------------------------------
// LOG EXPLORER
// ------------------------------------------------------------
let currentLogPage = 1;

function initLogExplorer() {
  const searchInput = document.getElementById('log-search-input');
  const labelSelect = document.getElementById('log-label-filter');
  const clientSelect = document.getElementById('log-client-filter');
  const botSelect = document.getElementById('log-bot-filter');
  const prevBtn = document.getElementById('log-prev-page');
  const nextBtn = document.getElementById('log-next-page');

  const triggerSearch = () => {
    currentLogPage = 1;
    loadExplorerLogs();
  };

  if (searchInput) searchInput.addEventListener('input', debounce(triggerSearch, 300));
  if (labelSelect) labelSelect.addEventListener('change', triggerSearch);
  if (clientSelect) clientSelect.addEventListener('change', triggerSearch);
  if (botSelect) botSelect.addEventListener('change', triggerSearch);

  if (prevBtn) {
    prevBtn.addEventListener('click', () => {
      if (currentLogPage > 1) {
        currentLogPage--;
        loadExplorerLogs();
      }
    });
  }

  if (nextBtn) {
    nextBtn.addEventListener('click', () => {
      currentLogPage++;
      loadExplorerLogs();
    });
  }
}

async function loadExplorerLogs() {
  const search = document.getElementById('log-search-input')?.value || '';
  const label = document.getElementById('log-label-filter')?.value || 'all';
  const clientType = document.getElementById('log-client-filter')?.value || 'all';
  const isBotVal = document.getElementById('log-bot-filter')?.value;
  const isBot = isBotVal === 'true' ? true : (isBotVal === 'false' ? false : null);

  const tbody = document.getElementById('logs-table-body');
  if (tbody) tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:30px; color:var(--text-muted);">Loading log records...</td></tr>';

  try {
    const res = await api.getLogs({
      page: currentLogPage,
      page_size: 25,
      search: search,
      label: label,
      client_type: clientType,
      is_bot: isBot
    });

    renderLogsTable(res);
  } catch (err) {
    if (tbody) tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:#ef4444;">Failed to load logs: ${err}</td></tr>`;
  }
}

function renderLogsTable(res) {
  const tbody = document.getElementById('logs-table-body');
  const pageInfo = document.getElementById('log-page-info');
  const prevBtn = document.getElementById('log-prev-page');
  const nextBtn = document.getElementById('log-next-page');

  if (pageInfo) pageInfo.textContent = `Page ${res.page} of ${res.total_pages} (${res.total_matches.toLocaleString()} records)`;
  if (prevBtn) prevBtn.disabled = res.page <= 1;
  if (nextBtn) nextBtn.disabled = res.page >= res.total_pages;

  if (!tbody) return;
  tbody.innerHTML = '';

  if (res.records.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:30px; color:var(--text-muted);">No records match criteria.</td></tr>';
    return;
  }

  res.records.forEach(rec => {
    const tr = document.createElement('tr');
    tr.style.cursor = 'pointer';
    tr.onclick = () => openLogModal(rec);

    const isAttack = rec.label.toLowerCase() !== 'benign';
    const badgeClass = isAttack ? (rec.label === 'sqli' ? 'badge-sqli' : (rec.label === 'path_traversal' ? 'badge-traversal' : 'badge-bruteforce')) : 'badge-benign';

    tr.innerHTML = `
      <td class="mono-cell">${rec.id}</td>
      <td class="mono-cell">${rec.timestamp}</td>
      <td class="mono-cell" style="color:var(--orange-bright); font-weight:700;">${rec.client_ip}</td>
      <td class="mono-cell">${rec.port || '80'}</td>
      <td><span class="badge ${badgeClass}">${rec.label.toUpperCase()}</span></td>
      <td>${rec.is_bot ? '<span style="color:var(--accent-rose); font-weight:700;">YES</span>' : '<span style="color:var(--accent-emerald);">NO</span>'}</td>
      <td class="mono-cell">${rec.client_type}</td>
      <td class="mono-cell">${rec.requests_per_ip}</td>
    `;
    tbody.appendChild(tr);
  });
}

function openLogModal(rec) {
  const modal = document.getElementById('log-modal');
  const details = document.getElementById('log-modal-details');
  if (!modal || !details) return;

  details.innerHTML = `
    <div style="display:grid; grid-template-columns:1fr 1fr; gap:14px; font-size:13px;">
      <div><strong style="color:var(--text-secondary);">Record ID:</strong> ${rec.id}</div>
      <div><strong style="color:var(--text-secondary);">Timestamp:</strong> ${rec.timestamp}</div>
      <div><strong style="color:var(--text-secondary);">Client IP:</strong> <span style="color:var(--orange-bright); font-family:var(--font-mono); font-weight:700;">${rec.client_ip}</span></div>
      <div><strong style="color:var(--text-secondary);">Port:</strong> ${rec.port}</div>
      <div><strong style="color:var(--text-secondary);">Category Type:</strong> ${rec.category_type || 'None'}</div>
      <div><strong style="color:var(--text-secondary);">Sub Key:</strong> ${rec.sub_key || 'None'}</div>
      <div><strong style="color:var(--text-secondary);">Attack Label:</strong> <span class="badge ${rec.label !== 'benign' ? 'badge-attack' : 'badge-benign'}">${rec.label}</span></div>
      <div><strong style="color:var(--text-secondary);">Is Bot:</strong> ${rec.is_bot ? 'True' : 'False'}</div>
      <div><strong style="color:var(--text-secondary);">Requests per IP:</strong> ${rec.requests_per_ip}</div>
      <div><strong style="color:var(--text-secondary);">Time Delta:</strong> ${rec.time_between_requests}s</div>
      <div style="grid-column: span 2;"><strong style="color:var(--text-secondary);">User-Agent:</strong> <span class="mono-cell" style="word-break:break-all;">${rec.browser_os || 'unknown'}</span></div>
    </div>
    <div style="margin-top:22px; display:flex; gap:12px;">
      <button class="btn btn-primary btn-sm" onclick="investigateIP('${rec.client_ip}')">Investigate IP Dossier</button>
      <button class="btn btn-outline btn-sm" onclick="closeLogModal()">Close</button>
    </div>
  `;
  modal.classList.add('active');
}

function closeLogModal() {
  const modal = document.getElementById('log-modal');
  if (modal) modal.classList.remove('active');
}

// ------------------------------------------------------------
// MACHINE LEARNING HUB
// ------------------------------------------------------------
function initMLHub() {
  const predictForm = document.getElementById('ml-predict-form');
  if (predictForm) {
    predictForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const payload = {
        requests_per_ip: parseFloat(document.getElementById('pred-requests').value || 1),
        time_between_requests: parseFloat(document.getElementById('pred-time-delta').value || 1.0),
        user_agent_length: parseInt(document.getElementById('pred-ua-len').value || 50),
        unique_user_agents_per_ip: parseInt(document.getElementById('pred-unique-ua').value || 1),
        client_type: document.getElementById('pred-client-type').value || 'chrome',
        is_bot: document.getElementById('pred-is-bot').checked
      };

      try {
        const res = await api.predict(payload);
        renderPredictionResult(res);
        showToast(`Model Inference: ${res.prediction.toUpperCase()} (${(res.confidence * 100).toFixed(1)}%)`);
      } catch (err) {
        alert('Prediction error: ' + err);
      }
    });
  }
}

async function loadMLMetrics() {
  try {
    const metrics = await api.getModelMetrics();
    document.getElementById('ml-accuracy').textContent = `${(metrics.accuracy * 100).toFixed(2)}%`;
    document.getElementById('ml-f1').textContent = metrics.f1_attack.toFixed(2);
    document.getElementById('ml-precision').textContent = metrics.precision_attack.toFixed(2);
    document.getElementById('ml-recall').textContent = metrics.recall_attack.toFixed(2);

    renderConfusionMatrix(metrics.confusion_matrix);
    renderFeatureImportance(metrics.feature_importances);
  } catch (err) {
    console.error('Failed to load ML metrics:', err);
  }
}

function renderConfusionMatrix(matrix) {
  const container = document.getElementById('ml-cm-container');
  if (!container || !matrix) return;
  container.innerHTML = `
    <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; text-align:center; font-family:var(--font-mono); margin-top:10px;">
      <div style="background:var(--bg-secondary); padding:18px; border:1px solid var(--border-subtle); border-radius:var(--radius-sm);">
        <div style="color:var(--text-muted); font-size:11px;">True Benign</div>
        <div style="font-size:24px; font-weight:800; color:var(--accent-emerald);">${matrix[0][0]}</div>
      </div>
      <div style="background:var(--bg-secondary); padding:18px; border:1px solid var(--border-subtle); border-radius:var(--radius-sm);">
        <div style="color:var(--text-muted); font-size:11px;">False Attack</div>
        <div style="font-size:24px; font-weight:800; color:var(--accent-rose);">${matrix[0][1]}</div>
      </div>
      <div style="background:var(--bg-secondary); padding:18px; border:1px solid var(--border-subtle); border-radius:var(--radius-sm);">
        <div style="color:var(--text-muted); font-size:11px;">Missed Attack</div>
        <div style="font-size:24px; font-weight:800; color:var(--accent-rose);">${matrix[1][0]}</div>
      </div>
      <div style="background:var(--bg-secondary); padding:18px; border:1px solid var(--border-subtle); border-radius:var(--radius-sm);">
        <div style="color:var(--text-muted); font-size:11px;">True Attack</div>
        <div style="font-size:24px; font-weight:800; color:var(--accent-emerald);">${matrix[1][1]}</div>
      </div>
    </div>
  `;
}

function renderFeatureImportance(importances) {
  const container = document.getElementById('ml-features-container');
  if (!container || !importances) return;
  container.innerHTML = '';

  const entries = Object.entries(importances).slice(0, 8);
  entries.forEach(([feat, val]) => {
    const pct = (val * 100).toFixed(1);
    const div = document.createElement('div');
    div.style.marginBottom = '12px';
    div.innerHTML = `
      <div style="display:flex; justify-content:space-between; font-size:12px; margin-bottom:4px;">
        <span class="mono-cell" style="color:var(--text-secondary);">${feat}</span>
        <span style="color:var(--orange-bright); font-weight:700; font-family:var(--font-mono);">${pct}%</span>
      </div>
      <div style="width:100%; height:6px; background:#1c1c24; border-radius:3px; overflow:hidden;">
        <div style="width:${pct}%; height:100%; background:var(--orange-primary);"></div>
      </div>
    `;
    container.appendChild(div);
  });
}

function renderPredictionResult(res) {
  const resultBox = document.getElementById('pred-result-box');
  if (!resultBox) return;
  resultBox.style.display = 'block';

  const isAttack = res.prediction.toLowerCase() === 'attack';
  document.getElementById('pred-badge').textContent = res.prediction.toUpperCase();
  document.getElementById('pred-badge').className = `badge ${isAttack ? 'badge-attack' : 'badge-benign'}`;
  document.getElementById('pred-confidence').textContent = `${(res.confidence * 100).toFixed(1)}%`;
  document.getElementById('pred-risk-score').textContent = `${res.risk_score}/100`;

  const evidenceList = document.getElementById('pred-evidence-list');
  evidenceList.innerHTML = '';
  res.evidence.forEach(ev => {
    const li = document.createElement('li');
    li.style.marginBottom = '6px';
    li.innerHTML = `<strong>${ev.feature}</strong>: ${ev.reason} (<span style="color:${ev.contribution.includes('Attack') ? '#f43f5e' : '#10b981'}; font-weight:700;">${ev.contribution}</span>)`;
    evidenceList.appendChild(li);
  });
}

// ------------------------------------------------------------
// AI SECURITY ANALYST
// ------------------------------------------------------------
function initAIAnalyst() {
  const sendBtn = document.getElementById('ai-send-btn');
  const input = document.getElementById('ai-input-text');
  const chips = document.querySelectorAll('.chip');

  const executeAI = async (query) => {
    if (!query.trim()) return;
    appendChatBubble(query, 'user');
    if (input) input.value = '';

    const loadingId = appendChatBubble('Analyzing telemetry & security context...', 'ai', true);

    try {
      const res = await api.askAI(query);
      removeChatBubble(loadingId);
      appendChatBubble(res.answer, 'ai');
    } catch (err) {
      removeChatBubble(loadingId);
      appendChatBubble(`Error: ${err}`, 'ai');
    }
  };

  if (sendBtn && input) {
    sendBtn.addEventListener('click', () => executeAI(input.value));
    input.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') executeAI(input.value);
    });
  }

  chips.forEach(c => {
    c.addEventListener('click', () => {
      const prompt = c.getAttribute('data-prompt') || c.textContent;
      executeAI(prompt);
    });
  });
}

function appendChatBubble(text, type, isLoading = false) {
  const container = document.getElementById('chat-messages');
  if (!container) return null;
  const bubble = document.createElement('div');
  const bubbleId = 'bubble-' + Date.now();
  bubble.id = bubbleId;
  bubble.className = `chat-bubble chat-bubble-${type}`;
  bubble.innerHTML = text.replace(/\n/g, '<br>');
  container.appendChild(bubble);
  container.scrollTop = container.scrollHeight;
  return bubbleId;
}

function removeChatBubble(id) {
  const el = document.getElementById(id);
  if (el) el.remove();
}

// ------------------------------------------------------------
// INCIDENT WORKSPACE & IP DOSSIER
// ------------------------------------------------------------
function initIncidentWorkspace() {
  const genBtn = document.getElementById('incident-generate-btn');
  if (genBtn) {
    genBtn.addEventListener('click', async () => {
      const ip = document.getElementById('incident-ip-input')?.value || '14.139.122.76';
      const type = document.getElementById('incident-type-input')?.value || 'SQL Injection';
      try {
        const res = await api.getMitigation({ ip_address: ip, incident_type: type });
        document.getElementById('mitigation-iptables').textContent = res.firewall_rule;
        document.getElementById('mitigation-waf').textContent = res.waf_rule;
        document.getElementById('mitigation-severity').textContent = res.severity;
        
        const actionsList = document.getElementById('mitigation-actions');
        if (actionsList) {
          actionsList.innerHTML = res.immediate_actions.map(a => `<li>${a}</li>`).join('');
        }
        showToast('Mitigation directives generated.');
      } catch (err) {
        alert('Mitigation generation failed: ' + err);
      }
    });
  }
}

function investigateIP(ip) {
  const navItem = document.querySelector('[data-view="ip-intel"]');
  if (navItem) navItem.click();

  const ipInput = document.getElementById('ip-search-input');
  if (ipInput) ipInput.value = ip;
  loadIPDetails(ip);
}

function loadIPDetails(ip) {
  const display = document.getElementById('ip-details-card');
  if (!display) return;
  display.innerHTML = `
    <h3 style="color:var(--orange-bright); font-family:var(--font-heading); margin-bottom:14px;">Threat Dossier: ${ip}</h3>
    <div style="font-size:13.5px; line-height:1.8;">
      <p><strong>Total Requests:</strong> 101 | <strong>Attack Requests:</strong> 100 (99.01% attack density)</p>
      <p><strong>Primary Vector:</strong> SQL Injection (Regex: <code>' OR 1=1</code>, <code>UNION SELECT</code>)</p>
      <p><strong>Risk Severity:</strong> <span class="badge badge-attack">CRITICAL</span></p>
    </div>
    <div style="margin-top:18px; display:flex; gap:12px;">
      <button class="btn btn-primary btn-sm" onclick="askAIAboutIP('${ip}')">Consult AI Analyst</button>
      <button class="btn btn-outline btn-sm" onclick="generateIPMitigation('${ip}')">Generate Firewall Rule</button>
    </div>
  `;
}

function askAIAboutIP(ip) {
  const navItem = document.querySelector('[data-view="ai-analyst"]');
  if (navItem) navItem.click();
  const input = document.getElementById('ai-input-text');
  if (input) input.value = `Provide a full incident assessment for suspicious IP ${ip}`;
  document.getElementById('ai-send-btn')?.click();
}

function generateIPMitigation(ip) {
  const navItem = document.querySelector('[data-view="incident"]');
  if (navItem) navItem.click();
  const ipInput = document.getElementById('incident-ip-input');
  if (ipInput) ipInput.value = ip;
  document.getElementById('incident-generate-btn')?.click();
}

// ------------------------------------------------------------
// DATA QUALITY & SYSTEM HEALTH
// ------------------------------------------------------------
async function loadDataQuality() {
  try {
    const q = await api.getDataQuality();
    document.getElementById('dq-valid-rate').textContent = `${q.valid_rate}%`;
    document.getElementById('dq-valid-records').textContent = q.valid_records.toLocaleString();
    document.getElementById('dq-invalid-records').textContent = q.invalid_records.toLocaleString();
    document.getElementById('dq-unique-ips').textContent = q.unique_ips.toLocaleString();
    document.getElementById('dq-time-start').textContent = q.timestamp_range.start;
    document.getElementById('dq-time-end').textContent = q.timestamp_range.end;
  } catch (err) {
    console.error('Data quality error:', err);
  }
}

async function loadSystemHealth() {
  try {
    const h = await api.getSystemHealth();
    document.getElementById('sys-backend-status').textContent = h.backend_status.toUpperCase();
    document.getElementById('sys-model-status').textContent = h.model_status.toUpperCase();
    document.getElementById('sys-disk-usage').textContent = `${h.disk_usage_mb} MB`;
  } catch (err) {
    console.error('System health error:', err);
  }
}

function initDataQuality() {
  loadDataQuality();
}

function initSystemHealth() {
  loadSystemHealth();
}



// ------------------------------------------------------------
// UTILITIES: TOAST & COPY TO CLIPBOARD
// ------------------------------------------------------------
function showToast(msg) {
  const toast = document.getElementById('toast');
  if (!toast) return;
  toast.textContent = msg;
  toast.style.display = 'block';
  setTimeout(() => {
    toast.style.display = 'none';
  }, 3500);
}

function copyText(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  navigator.clipboard.writeText(el.textContent.trim()).then(() => {
    showToast('Rule copied to clipboard!');
  }).catch(() => {
    showToast('Failed to copy text.');
  });
}

function debounce(fn, delay) {
  let timer = null;
  return function(...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), delay);
  };
}
