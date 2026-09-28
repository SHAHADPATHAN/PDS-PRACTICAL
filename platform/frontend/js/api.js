/* ============================================================
   API CLIENT - BACKEND CONNECTIVITY ENGINE
   ============================================================ */

const API_BASE = window.location.origin.includes('8000') 
  ? '' 
  : 'http://127.0.0.1:8000';

const api = {
  async getHealth() {
    const res = await fetch(`${API_BASE}/api/health`);
    return await res.json();
  },

  async getOverview() {
    const res = await fetch(`${API_BASE}/api/analytics/overview`);
    return await res.json();
  },

  async getKPIs() {
    const res = await fetch(`${API_BASE}/api/analytics/kpis`);
    return await res.json();
  },

  async getTraffic() {
    const res = await fetch(`${API_BASE}/api/analytics/traffic`);
    return await res.json();
  },

  async getAttacks() {
    const res = await fetch(`${API_BASE}/api/analytics/attacks`);
    return await res.json();
  },

  async getTopIPs() {
    const res = await fetch(`${API_BASE}/api/analytics/ip-analysis`);
    return await res.json();
  },

  async getLogs(params = {}) {
    const url = new URL(`${API_BASE || window.location.origin}/api/logs/records`, window.location.origin);
    Object.keys(params).forEach(key => {
      if (params[key] !== null && params[key] !== undefined && params[key] !== '') {
        url.searchParams.append(key, params[key]);
      }
    });
    const res = await fetch(url);
    return await res.json();
  },

  async getModelMetrics() {
    const res = await fetch(`${API_BASE}/api/model/metrics`);
    return await res.json();
  },

  async predict(payload) {
    const res = await fetch(`${API_BASE}/api/model/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return await res.json();
  },

  async askAI(query, targetPrediction = null) {
    const res = await fetch(`${API_BASE}/api/ai/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        query: query,
        context_type: targetPrediction ? 'prediction' : 'general',
        target_prediction: targetPrediction
      })
    });
    return await res.json();
  },

  async getMitigation(payload) {
    const res = await fetch(`${API_BASE}/api/ai/mitigation`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return await res.json();
  },

  async getPipelineStatus() {
    const res = await fetch(`${API_BASE}/api/pipeline/status`);
    return await res.json();
  },

  async runPipeline(mode = 'fast') {
    const res = await fetch(`${API_BASE}/api/pipeline/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: mode, include_training: true })
    });
    return await res.json();
  },

  async getDataQuality() {
    const res = await fetch(`${API_BASE}/api/system/quality`);
    return await res.json();
  },

  async uploadFile(fileObj) {
    const formData = new FormData();
    formData.append('file', fileObj);
    const res = await fetch(`${API_BASE}/api/upload/file`, {
      method: 'POST',
      body: formData
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Upload failed');
    }
    return await res.json();
  },

  async uploadText(textContent, filename = 'pasted_stream.log') {
    const res = await fetch(`${API_BASE}/api/upload/text`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: textContent, filename: filename })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Text analysis failed');
    }
    return await res.json();
  },

  async getSample(sampleType) {
    const res = await fetch(`${API_BASE}/api/upload/samples/${sampleType}`);
    if (!res.ok) throw new Error('Failed to load sample');
    return await res.json();
  },

  async getSystemHealth() {
    const res = await fetch(`${API_BASE}/api/system/health`);
    return await res.json();
  }
};

