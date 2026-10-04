let currentMode = 'email';

const SAMPLES = {
  high: {
    type: 'email',
    content: `Subject: Urgent: Your Account Will Be Suspended

Dear Customer,

Your account will be suspended today due to unusual activity. Verify your account immediately using the link below:

https://secure-account-verification.example.com/login

Failure to verify will result in permanent suspension.`
  },
  medium: {
    type: 'email',
    content: `Subject: Account Security Review Notification

Hello user,

We noticed a login from an unfamiliar device. Please review your account activity. 
Click here to update your information if this was not you:
https://portal-notice.example.com/security/review`
  },
  low: {
    type: 'email',
    content: `Subject: Weekly Engineering Newsletter #42

Hello team,

Sprint planning is scheduled for Tuesday morning at 10 AM.
Please review the attached roadmap document before the sync.

Best regards,
Engineering Team`
  }
};

function switchInputMode(mode) {
  currentMode = mode;
  const tabEmail = document.getElementById('tabEmail');
  const tabUrl = document.getElementById('tabUrl');
  const emailGroup = document.getElementById('emailInputGroup');
  const urlGroup = document.getElementById('urlInputGroup');

  if (mode === 'email') {
    tabEmail?.classList.add('active');
    tabUrl?.classList.remove('active');
    emailGroup?.classList.remove('hidden');
    urlGroup?.classList.add('hidden');
  } else {
    tabUrl?.classList.add('active');
    tabEmail?.classList.remove('active');
    urlGroup?.classList.remove('hidden');
    emailGroup?.classList.add('hidden');
  }
}

function loadSample(key) {
  const sample = SAMPLES[key];
  if (!sample) return;
  switchInputMode(sample.type);
  if (sample.type === 'email') {
    const el = document.getElementById('emailInput');
    if (el) el.value = sample.content;
  } else {
    const el = document.getElementById('urlInput');
    if (el) el.value = sample.content;
  }
}

function clearInput() {
  const emailEl = document.getElementById('emailInput');
  const urlEl = document.getElementById('urlInput');
  if (emailEl) emailEl.value = '';
  if (urlEl) urlEl.value = '';
  const results = document.getElementById('resultsSection');
  if (results) results.classList.add('hidden');
}

async function runAnalysis() {
  const btn = document.getElementById('btnAnalyze');
  if (btn) btn.disabled = true;

  try {
    let endpoint = currentMode === 'email' ? '/api/analyze/email' : '/api/analyze/url';
    let payload = {};

    if (currentMode === 'email') {
      const text = document.getElementById('emailInput')?.value;
      if (!text || !text.strip?.() && !text.trim()) {
        alert('Please enter email content to analyze.');
        return;
      }
      payload = { content: text };
    } else {
      const url = document.getElementById('urlInput')?.value;
      if (!url || !url.trim()) {
        alert('Please enter a target URL to analyze.');
        return;
      }
      payload = { url: url };
    }

    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await res.json();
    if (!res.ok) {
      alert(data.error || 'Analysis failed');
      return;
    }

    renderResults(data);
  } catch (err) {
    console.error('Error running analysis:', err);
    alert('Communication error with investigation API.');
  } finally {
    if (btn) btn.disabled = false;
  }
}

function renderResults(data) {
  const results = document.getElementById('resultsSection');
  if (!results) return;
  results.classList.remove('hidden');

  // Scores
  document.getElementById('riskScore').innerText = data.risk_score;
  const levelEl = document.getElementById('riskLevel');
  levelEl.innerText = data.risk_level;
  
  // Colorize level
  const colors = {
    LOW: '#10b981',
    MEDIUM: '#f59e0b',
    HIGH: '#f97316',
    CRITICAL: '#ef4444'
  };
  levelEl.style.color = colors[data.risk_level] || '#fff';

  // Breakdown
  const breakdownEl = document.getElementById('breakdownList');
  if (breakdownEl) {
    breakdownEl.innerHTML = '';
    data.score_breakdown.forEach(item => {
      const row = document.createElement('div');
      row.className = 'breakdown-row';
      row.innerHTML = `
        <span>${item.indicator}</span>
        <span style="font-family: monospace; color: #38bdf8;">+${item.points} pts</span>
      `;
      breakdownEl.appendChild(row);
    });
    const totalRow = document.createElement('div');
    totalRow.className = 'breakdown-row';
    totalRow.style.fontWeight = '700';
    totalRow.innerHTML = `
      <span>Total Risk Score (Capped at 100)</span>
      <span style="font-family: monospace; color: ${colors[data.risk_level]};">${data.risk_score}/100</span>
    `;
    breakdownEl.appendChild(totalRow);
  }

  // Indicators
  const cardsEl = document.getElementById('indicatorCards');
  if (cardsEl) {
    cardsEl.innerHTML = '';
    if (!data.indicators || data.indicators.length === 0) {
      cardsEl.innerHTML = '<p style="color: #94a3b8;">No suspicious indicators detected.</p>';
    } else {
      data.indicators.forEach(ind => {
        const card = document.createElement('div');
        card.className = 'ind-card';
        card.innerHTML = `
          <div class="ind-top">
            <span class="ind-name">${ind.indicator}</span>
            <span class="ind-points">+${ind.points} pts</span>
          </div>
          <p style="font-size: 13px; color: #94a3b8; margin-bottom: 6px;">${ind.description}</p>
          <div class="ind-evidence"><strong>Evidence:</strong> ${ind.evidence}</div>
        `;
        cardsEl.appendChild(card);
      });
    }
  }

  // URL Details if present
  const urlPanel = document.getElementById('urlAnalysisPanel');
  const urlBody = document.getElementById('urlMetricsBody');
  if (data.url_analysis && urlPanel && urlBody) {
    urlPanel.classList.remove('hidden');
    const u = data.url_analysis;
    const metrics = [
      { name: 'Protocol / HTTPS', value: u.is_https ? 'HTTPS (Secure)' : 'HTTP (Insecure)', assess: u.is_https ? 'Standard' : 'Unencrypted Warning' },
      { name: 'Host / Domain', value: u.domain, assess: u.has_ip_address ? 'High Risk (IP address host)' : 'Standard' },
      { name: 'Subdomain Count', value: u.subdomain_count, assess: u.subdomain_count >= 2 ? 'Stacking Suspicion' : 'Normal' },
      { name: 'Hyphen Count', value: u.hyphen_count, assess: u.has_excessive_hyphens ? 'Deceptive Stacking' : 'Normal' },
      { name: 'Matched Security Keywords', value: u.matched_keywords.join(', ') || 'None', assess: u.matched_keywords.length > 0 ? 'Targeting Authentication' : 'Clean' }
    ];
    urlBody.innerHTML = metrics.map(m => `
      <tr>
        <td><strong>${m.name}</strong></td>
        <td><code>${m.value}</code></td>
        <td>${m.assess}</td>
      </tr>
    `).join('');
  } else if (urlPanel) {
    urlPanel.classList.add('hidden');
  }

  // AI Forensics
  const ai = data.ai_explanation || {};
  const shortEl = document.getElementById('aiShortExp');
  if (shortEl) shortEl.innerText = ai.short_explanation || '';
  const behEl = document.getElementById('aiBehavior');
  if (behEl) behEl.innerText = ai.main_suspicious_behavior || '';
  const provEl = document.getElementById('aiProvider');
  if (provEl) provEl.innerText = ai.provider || 'AI Analyst';

  const signalsEl = document.getElementById('aiKeySignals');
  if (signalsEl && ai.most_important_indicators) {
    signalsEl.innerHTML = ai.most_important_indicators.map(sig => `<li>${sig}</li>`).join('');
  }

  // Recommendation
  const recEl = document.getElementById('recommendationText');
  if (recEl) recEl.innerText = data.recommendation || '';

  results.scrollIntoView({ behavior: 'smooth' });
}

async function loadHistory() {
  const tbody = document.getElementById('historyBody');
  if (!tbody) return;

  try {
    const res = await fetch('/api/history');
    const records = await res.json();
    if (!records || records.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-center" style="padding: 24px; color: #94a3b8;">No investigations recorded yet.</td></tr>';
      return;
    }

    tbody.innerHTML = records.map(r => `
      <tr>
        <td>#${r.id}</td>
        <td>${r.created_at || 'Just now'}</td>
        <td><span style="font-family: monospace; text-transform: uppercase;">${r.input_type}</span></td>
        <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(r.input_data)}</td>
        <td><strong style="font-family: monospace;">${r.risk_score}/100</strong></td>
        <td><span>${r.risk_level}</span></td>
        <td><button class="btn btn-outline" onclick="deleteHistory(${r.id})">Delete</button></td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Failed to load history:', err);
  }
}

async function deleteHistory(id) {
  if (!confirm(`Delete investigation #${id}?`)) return;
  try {
    await fetch(`/api/history/${id}`, { method: 'DELETE' });
    loadHistory();
  } catch (err) {
    alert('Failed to delete item');
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
