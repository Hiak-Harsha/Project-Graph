/**
 * Antigravity Project Graph — Production Engineering Auditor Client
 */

let AUDIT_DATA = null;
let GRAPH_DATA = null;
let CURRENT_FILTER = 'all';

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initFilters();
  initModal();
  fetchAuditData();

  document.getElementById('btn-re-audit')?.addEventListener('click', () => {
    reAudit();
  });
});

function initTabs() {
  const tabBtns = document.querySelectorAll('.tab-btn');
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const targetId = `pane-${btn.dataset.tab}`;
      document.getElementById(targetId)?.classList.add('active');

      if (btn.dataset.tab === 'graph' && GRAPH_DATA) {
        renderProjectGraph(GRAPH_DATA);
      }
    });
  });
}

function initFilters() {
  const chips = document.querySelectorAll('.filter-chip');
  chips.forEach(chip => {
    chip.addEventListener('click', () => {
      chips.forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      CURRENT_FILTER = chip.dataset.filter;
      renderFindings(AUDIT_DATA?.findings || []);
    });
  });
}

function initModal() {
  const overlay = document.getElementById('modal-overlay');
  const closeBtn = document.getElementById('modal-close');

  closeBtn?.addEventListener('click', () => overlay.classList.remove('active'));
  overlay?.addEventListener('click', (e) => {
    if (e.target === overlay) overlay.classList.remove('active');
  });
}

async function fetchAuditData() {
  try {
    const res = await fetch('/api/audits/latest');
    if (!res.ok) throw new Error('Failed to fetch audit');
    AUDIT_DATA = await res.json();
    populateDashboard(AUDIT_DATA);

    // Also fetch graph
    const graphRes = await fetch('/api/audits/graph');
    if (graphRes.ok) {
      GRAPH_DATA = await graphRes.json();
    }
  } catch (err) {
    console.error('Error loading audit data:', err);
  }
}

async function reAudit() {
  const btn = document.getElementById('btn-re-audit');
  const origText = btn.innerHTML;
  btn.innerHTML = `<span>Auditing...</span>`;
  btn.disabled = true;

  try {
    const res = await fetch('/api/audits/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    if (!res.ok) throw new Error('Audit run failed');
    AUDIT_DATA = await res.json();
    populateDashboard(AUDIT_DATA);

    const graphRes = await fetch('/api/audits/graph');
    if (graphRes.ok) {
      GRAPH_DATA = await graphRes.json();
      renderProjectGraph(GRAPH_DATA);
    }
  } catch (err) {
    console.error(err);
  } finally {
    btn.innerHTML = origText;
    btn.disabled = false;
  }
}

function populateDashboard(data) {
  const v = data.verdict;
  const c = data.completeness;
  const prod = data.product_understanding;

  document.getElementById('overall-score').textContent = v.overall_score;
  document.getElementById('verdict-pill').textContent = v.verdict_status;
  document.getElementById('verdict-pill').className = `status-pill status-${v.status_badge.toLowerCase()}`;

  document.getElementById('product-archetype').textContent = prod.product_archetype;
  document.getElementById('p1-status').textContent = `PASS (${c.terminal_entities + c.unverified_entities}/${c.discovered_entities})`;
  document.getElementById('coverage-pct').textContent = `${c.audit_coverage_pct}%`;
  document.getElementById('exec-time').textContent = `${data.elapsed_seconds}s`;

  // Domain scores
  const scores = v.domain_scores;
  setDomainScore('security', scores.Security);
  setDomainScore('ux', scores['User Experience (UX)']);
  setDomainScore('req', scores['Product Requirements']);
  setDomainScore('arch', scores.Architecture);

  // Tab counts
  document.getElementById('tab-findings-count').textContent = data.findings.length;
  document.getElementById('tab-tasks-count').textContent = data.verification_stats.total_tasks;
  document.getElementById('tab-evidence-count').textContent = data.evidence_records.length;

  // Filter badge counts
  const fSummary = v.findings_summary;
  document.getElementById('count-crit').textContent = fSummary.critical;
  document.getElementById('count-high').textContent = fSummary.high;
  document.getElementById('count-med').textContent = fSummary.medium;
  document.getElementById('count-low').textContent = fSummary.low;

  renderFindings(data.findings);
  renderTasks();
  renderEvidence(data.evidence_records);
  renderCoverage(c.by_category);
}

function setDomainScore(id, score) {
  const el = document.getElementById(`score-${id}`);
  const bar = document.getElementById(`bar-${id}`);
  if (el && bar) {
    el.textContent = score;
    bar.style.width = `${Math.min(100, score * 10)}%`;
  }
}

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function renderFindings(findings) {
  const container = document.getElementById('findings-container');
  container.innerHTML = '';

  const filtered = findings.filter(f => {
    if (CURRENT_FILTER === 'all') return true;
    return f.severity === CURRENT_FILTER;
  });

  if (filtered.length === 0) {
    container.innerHTML = `<div class="empty-state">No findings matching active filter.</div>`;
    return;
  }

  filtered.forEach(f => {
    const card = document.createElement('div');
    card.className = `finding-card glass-panel severity-${escapeHtml(f.severity)}`;
    card.innerHTML = `
      <div class="finding-header">
        <div class="finding-badges">
          <span class="sev-tag sev-${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span>
          <span class="cat-tag">${escapeHtml(f.category)}</span>
          <span class="cat-tag">• ${escapeHtml(f.affected_feature)}</span>
        </div>
        <span class="status-pill status-${f.status === 'CONFIRMED' ? 'failed' : 'passed'}">${escapeHtml(f.status)}</span>
      </div>
      <h3 class="finding-title">${escapeHtml(f.title)}</h3>
      <p class="finding-desc">${escapeHtml(f.description)}</p>
      <div class="finding-footer">
        <span>Evidence: <span class="evidence-pill">${f.evidence_ids.map(escapeHtml).join(', ')}</span></span>
        <span>Confidence: ${Math.round(f.confidence * 100)}%</span>
      </div>
    `;
    card.addEventListener('click', () => showFindingModal(f));
    container.appendChild(card);
  });
}

function showFindingModal(f) {
  const modal = document.getElementById('modal-content');
  modal.innerHTML = `
    <div style="margin-bottom: 20px;">
      <span class="sev-tag sev-${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span>
      <span style="margin-left: 8px; color: var(--text-dim);">${escapeHtml(f.category)}</span>
      <h2 style="font-size: 1.3rem; margin-top: 10px; color: #fff;">${escapeHtml(f.title)}</h2>
    </div>

    <div style="margin-bottom: 16px;">
      <h4 style="font-size: 0.8rem; color: var(--text-dim); text-transform: uppercase;">Observed Flaw / Behavior</h4>
      <p style="color: var(--text-main); margin-top: 4px; line-height: 1.5;">${escapeHtml(f.observed_behavior)}</p>
    </div>

    <div style="margin-bottom: 16px;">
      <h4 style="font-size: 0.8rem; color: var(--text-dim); text-transform: uppercase;">Expected Invariant / Contract</h4>
      <p style="color: var(--text-main); margin-top: 4px; line-height: 1.5;">${escapeHtml(f.expected_behavior)}</p>
    </div>

    <div style="margin-bottom: 16px;">
      <h4 style="font-size: 0.8rem; color: var(--text-dim); text-transform: uppercase;">Reproduction Steps</h4>
      <ol style="margin-left: 20px; margin-top: 4px; color: var(--text-muted); line-height: 1.6;">
        ${(f.reproduction_steps || []).map(s => `<li>${escapeHtml(s)}</li>`).join('')}
      </ol>
    </div>

    <div style="margin-bottom: 16px; padding: 14px; background: rgba(0,0,0,0.3); border-radius: 8px; border-left: 3px solid var(--accent);">
      <h4 style="font-size: 0.8rem; color: var(--accent); text-transform: uppercase;">Recommended Remediation</h4>
      <p style="color: #fff; margin-top: 4px;">${escapeHtml(f.recommendation)}</p>
    </div>

    <div style="display: flex; justify-content: space-between; font-size: 0.8rem; color: var(--text-dim); border-top: 1px solid var(--border-color); padding-top: 12px;">
      <span>Adversarial Review: <strong>${escapeHtml(f.adversarial_verdict || 'VERIFIED')}</strong></span>
      <span>Evidence Links: <strong>${(f.evidence_ids || []).map(escapeHtml).join(', ')}</strong></span>
    </div>
  `;
  document.getElementById('modal-overlay').classList.add('active');
}

async function renderTasks() {
  const tbody = document.getElementById('tasks-tbody');
  tbody.innerHTML = '<tr><td colspan="5">Loading tasks...</td></tr>';
  try {
    const res = await fetch('/api/audits/tasks');
    const tasks = await res.json();
    tbody.innerHTML = '';
    tasks.forEach(t => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="font-family: var(--font-mono);">${escapeHtml(t.id)}</td>
        <td>${escapeHtml(t.task_type)}</td>
        <td style="font-family: var(--font-mono); color: var(--accent);">${escapeHtml(t.target_id)}</td>
        <td>${escapeHtml((t.required_checks || []).slice(0, 3).join(', '))}...</td>
        <td><span class="status-pill status-${t.status === 'COMPLETED' ? 'passed' : 'failed'}">${escapeHtml(t.status)}</span></td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.error(e);
  }
}

function renderEvidence(records) {
  const tbody = document.getElementById('evidence-tbody');
  tbody.innerHTML = '';
  records.forEach(e => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="font-family: var(--font-mono); color: var(--accent);">${escapeHtml(e.id)}</td>
      <td>${escapeHtml(e.evidence_type)}</td>
      <td style="font-family: var(--font-mono);">${escapeHtml(e.target_id)}</td>
      <td style="font-family: var(--font-mono);">${escapeHtml(e.source_location || '—')}</td>
      <td style="font-family: var(--font-mono); color: var(--text-dim);">${escapeHtml((e.sha256_hash || '').slice(0, 12))}...</td>
      <td>${escapeHtml(e.summary)}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderCoverage(byCat) {
  const tbody = document.getElementById('coverage-tbody');
  tbody.innerHTML = '';
  if (!byCat) return;

  Object.entries(byCat).forEach(([type, data]) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="font-weight: 600;">${escapeHtml(type)}</td>
      <td>${escapeHtml(data.total_discovered)}</td>
      <td style="color: #34d399;">${escapeHtml(data.verified)}</td>
      <td style="color: #f87171;">${escapeHtml(data.failed)}</td>
      <td>${escapeHtml(data.unverified)}</td>
      <td style="font-weight: 700; color: ${data.coverage_pct === 100 ? '#34d399' : '#fbbf24'}">${escapeHtml(data.coverage_pct)}%</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderProjectGraph(graph) {
  const svg = document.getElementById('project-graph-svg');
  svg.innerHTML = '';

  const width = svg.clientWidth || 900;
  const height = 560;

  const nodeColorMap = {
    REQUIREMENT: '#ec4899',
    FEATURE: '#8b5cf6',
    UI_ELEMENT: '#3b82f6',
    API_ENDPOINT: '#10b981',
    DATABASE_ENTITY: '#f59e0b',
    TEST: '#06b6d4',
    FILE: '#64748b',
    PACKAGE: '#a855f7',
  };

  // Filter main interesting nodes for clean visual topology
  const interestingTypes = new Set(['REQUIREMENT', 'FEATURE', 'UI_ELEMENT', 'API_ENDPOINT', 'DATABASE_ENTITY', 'TEST']);
  const visibleNodes = graph.nodes.filter(n => interestingTypes.has(n.node_type));
  const nodeMap = new Map();

  // Position nodes in columns by type
  const columns = {
    REQUIREMENT: { x: width * 0.12, nodes: [] },
    FEATURE: { x: width * 0.28, nodes: [] },
    UI_ELEMENT: { x: width * 0.48, nodes: [] },
    API_ENDPOINT: { x: width * 0.68, nodes: [] },
    DATABASE_ENTITY: { x: width * 0.88, nodes: [] },
    TEST: { x: width * 0.88, nodes: [] },
  };

  visibleNodes.forEach(n => {
    if (columns[n.node_type]) {
      columns[n.node_type].nodes.push(n);
    }
  });

  Object.values(columns).forEach(col => {
    const step = height / (col.nodes.length + 1);
    col.nodes.forEach((n, idx) => {
      const pos = { x: col.x, y: (idx + 1) * step };
      nodeMap.set(n.id, pos);
    });
  });

  // Render Edges
  graph.edges.forEach(e => {
    const src = nodeMap.get(e.source);
    const tgt = nodeMap.get(e.target);
    if (src && tgt) {
      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      const dx = tgt.x - src.x;
      const d = `M ${src.x} ${src.y} C ${src.x + dx/2} ${src.y}, ${src.x + dx/2} ${tgt.y}, ${tgt.x} ${tgt.y}`;
      path.setAttribute('d', d);
      path.setAttribute('fill', 'none');
      path.setAttribute('stroke', 'rgba(255, 255, 255, 0.18)');
      path.setAttribute('stroke-width', '1.5');
      path.setAttribute('stroke-dasharray', e.relationship === 'TESTED_BY' ? '4,4' : 'none');
      svg.appendChild(path);
    }
  });

  // Render Nodes
  visibleNodes.forEach(n => {
    const pos = nodeMap.get(n.id);
    if (!pos) return;

    const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    g.setAttribute('transform', `translate(${pos.x}, ${pos.y})`);
    g.style.cursor = 'pointer';

    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('r', '8');
    circle.setAttribute('fill', nodeColorMap[n.node_type] || '#6366f1');
    circle.setAttribute('stroke', n.audit_status === 'FAILED' ? '#ef4444' : 'rgba(255,255,255,0.6)');
    circle.setAttribute('stroke-width', n.audit_status === 'FAILED' ? '2.5' : '1.5');

    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    text.setAttribute('x', '12');
    text.setAttribute('y', '4');
    text.setAttribute('fill', '#e2e8f0');
    text.setAttribute('font-size', '11');
    text.setAttribute('font-family', 'Plus Jakarta Sans');
    text.textContent = n.name.slice(0, 24);

    g.appendChild(circle);
    g.appendChild(text);

    g.addEventListener('click', () => {
      alert(`Node ID: ${n.id}\nType: ${n.node_type}\nName: ${n.name}\nAudit Status: ${n.audit_status}`);
    });

    svg.appendChild(g);
  });
}
