let currentAuditData = null;

async function fetchAuditData(dataset) {
  try {
    const res = await fetch(`/api/audit-report?dataset=${dataset}`);
    const data = await res.json();
    currentAuditData = data;
    renderDashboard(data);
  } catch (err) {
    console.error("Failed to load audit data", err);
  }
}

function renderDashboard(data) {
  // 1. Score Meter & Gate Status
  const score = data.score;
  document.getElementById('score-num').innerText = score;

  const meterCircle = document.getElementById('meter-circle');
  const gateBadge = document.getElementById('gate-badge');

  if (data.gate_status === "APPROVED") {
    meterCircle.style.background = `conic-gradient(var(--color-pass) ${score}%, rgba(255,255,255,0.08) ${score}%)`;
    gateBadge.innerText = "RELEASE APPROVED";
    gateBadge.className = "gate-badge gate-approved";
  } else {
    meterCircle.style.background = `conic-gradient(var(--color-block) ${score}%, rgba(255,255,255,0.08) ${score}%)`;
    gateBadge.innerText = "RELEASE BLOCKED";
    gateBadge.className = "gate-badge gate-blocked";
  }

  // 2. Application Profile Meta
  const prof = data.app_profile;
  const metaContainer = document.getElementById('profile-meta-container');
  metaContainer.innerHTML = `
    <div class="meta-row">
      <span class="meta-key">Application Name</span>
      <span class="meta-val">${prof.name}</span>
    </div>
    <div class="meta-row">
      <span class="meta-key">Dataset Evaluated</span>
      <span class="meta-val"><span class="pill" style="border: 1px solid var(--accent-cyan); color: var(--accent-cyan);">${data.summary.dataset_evaluated}</span></span>
    </div>
    <div class="meta-row">
      <span class="meta-key">Architecture Type</span>
      <span class="meta-val"><span class="pill">${prof.kind}</span> (${prof.audit_level})</span>
    </div>
    <div class="meta-row">
      <span class="meta-key">Data Handled</span>
      <span class="meta-val">${prof.data_handled.map(d => `<span class="pill">${d}</span>`).join('')}</span>
    </div>
    <div class="meta-row">
      <span class="meta-key">Active User Roles</span>
      <span class="meta-val">${prof.roles.map(r => `<span class="pill">${r}</span>`).join('')}</span>
    </div>
    <div class="meta-row">
      <span class="meta-key">Policy Location</span>
      <span class="meta-val">${prof.policy_locations.map(p => `<span class="pill">${p}</span>`).join('')}</span>
    </div>
  `;

  // 3. Findings Table
  document.getElementById('findings-count').innerText = data.findings.length;
  const tbody = document.getElementById('findings-table-body');
  tbody.innerHTML = '';

  if (data.findings.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--color-pass); padding: 24px;">No compliance or quality violations detected! All policies satisfied. System is 100% compliant.</td></tr>`;
  } else {
    data.findings.forEach(f => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><span class="severity-badge sev-${f.severity}">${f.severity}</span></td>
        <td><strong>${f.title}</strong><br><span style="font-size:12px; color: var(--text-muted);">${f.description}</span></td>
        <td><span class="pill" style="border: 1px solid var(--accent-blue);">${f.control_mapped}</span></td>
        <td><span class="code-box">${f.evidence_cited}</span></td>
        <td style="color: var(--color-pass); font-size:13px;">${f.suggested_fix}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  // 4. Agent Audit Log
  const agentLog = data.agent_audit_log;
  document.getElementById('agent-log-hash').innerText = agentLog.log_hash;
  const agentContainer = document.getElementById('agent-decisions-list');
  agentContainer.innerHTML = agentLog.decisions.map(d => `
    <div class="agent-log-item">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 6px;">
        <strong>${d.test_name}</strong>
        <span class="pill" style="background: ${d.status === 'SELECTED' ? 'rgba(0, 242, 254, 0.2)' : 'rgba(255,255,255,0.05)'}; color: ${d.status === 'SELECTED' ? 'var(--accent-cyan)' : 'var(--text-muted)'}">${d.status}</span>
      </div>
      <p style="font-size: 13px; color: var(--text-muted);">${d.justification}</p>
      <div style="margin-top: 6px;">
        <span style="font-size: 11px; color: var(--text-muted);">Controls: </span>
        ${d.applicable_controls.map(c => `<span class="pill">${c}</span>`).join('')}
      </div>
    </div>
  `).join('');

  // 5. Evidence Store Chain
  const evContainer = document.getElementById('evidence-chain-list');
  evContainer.innerHTML = `<p style="font-size:14px; color: var(--text-muted);">Total Evidence Records Recorded: <strong>${data.summary.total_evidence_records}</strong></p>
    <div style="margin-top: 12px; font-family: monospace; font-size: 12px;">
      ${data.findings.map(f => `<div class="agent-log-item">
        <div><strong style="color: var(--accent-cyan);">Exchange ID: ${f.exchange_id || 'N/A'}</strong></div>
        <div>Evidence Record: ${f.evidence_cited}</div>
        <div style="color: var(--text-muted);">Control: ${f.control_mapped}</div>
      </div>`).join('')}
    </div>
  `;
}

function switchDataset(dataset) {
  document.querySelectorAll('.app-selector button').forEach(b => b.classList.remove('btn-active'));
  if (dataset === 'dataset_a') document.getElementById('btn-ds-a').classList.add('btn-active');
  if (dataset === 'dataset_b') document.getElementById('btn-ds-b').classList.add('btn-active');
  if (dataset === 'dataset_c') document.getElementById('btn-ds-c').classList.add('btn-active');
  if (dataset === 'rag_a') document.getElementById('btn-rag-a').classList.add('btn-active');
  if (dataset === 'rag_b') document.getElementById('btn-rag-b').classList.add('btn-active');

  fetchAuditData(dataset);
}

function switchTab(tabName) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-findings').style.display = 'none';
  document.getElementById('tab-agent-log').style.display = 'none';
  document.getElementById('tab-evidence').style.display = 'none';

  if (tabName === 'findings') {
    document.getElementById('tab-findings').style.display = 'block';
    event.target.classList.add('active');
  } else if (tabName === 'agent-log') {
    document.getElementById('tab-agent-log').style.display = 'block';
    event.target.classList.add('active');
  } else if (tabName === 'evidence') {
    document.getElementById('tab-evidence').style.display = 'block';
    event.target.classList.add('active');
  }
}

// Initial fetch on page load
document.addEventListener('DOMContentLoaded', () => {
  fetchAuditData('dataset_a');
});
