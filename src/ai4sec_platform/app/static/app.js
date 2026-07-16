const state = { domain: 'news', ops: null, overview: null };

const domainConfig = {
  news: {
    label: '资讯洞察',
    desc: 'AI-for-Sec 旧数据导入生成的今日资讯、核心推荐和审阅证据。',
    today: '/api/news/today',
    detail: id => `/api/news/items/${id}`,
  },
  capabilities: {
    label: '能力洞察',
    desc: '来自高分论文/项目的能力候选；第一阶段只展示待复现状态，不触发 runner。',
    today: '/api/capabilities/today',
    detail: id => `/api/capabilities/items/${id}`,
  },
  threats: {
    label: '威胁洞察',
    desc: '华为 repo / 攻击面评分导入的目标库样例，先目标列表和证据详情，后续再做图谱。',
    today: '/api/threats/today',
    detail: id => `/api/threats/targets/${id}`,
  },
  vulnerabilities: {
    label: '漏洞洞察',
    desc: '漏洞素材旧报告导入的高相关素材、关键发现和知识提取候选。',
    today: '/api/vulnerabilities/today',
    detail: id => `/api/vulnerabilities/materials/${id}`,
  },
  operations: {
    label: '统一运营',
    desc: '查看采集任务、数据源、规则、质量审计和人工队列。',
  },
};

const opsEndpoints = {
  tasks: ['/api/operations/tasks', '采集任务'],
  sources: ['/api/operations/sources', '数据源'],
  rules: ['/api/operations/rules', '规则配置'],
  audits: ['/api/operations/audits', '质量审计'],
  'human-queue': ['/api/operations/human-queue', '人工队列'],
};

const $ = id => document.getElementById(id);

async function api(path) {
  const response = await fetch(path);
  if (!response.ok) throw new Error(`${path} ${response.status}`);
  return response.json();
}

async function loadOverview() {
  state.overview = await api('/api/dashboard/overview');
  $('systemStatus').textContent = 'API 已连接 · production_writes=false';
  $('overviewCards').innerHTML = state.overview.domains.map(domain => `
    <div class="mini-card"><b>${domain.item_count}</b><span>${domain.label}</span></div>
  `).join('') + `<div class="mini-card"><b>${state.overview.pending_queue_count}</b><span>待处理队列</span></div>`;
}

function setActiveTab() {
  document.querySelectorAll('[data-domain]').forEach(btn => btn.classList.toggle('active', btn.dataset.domain === state.domain));
  document.querySelectorAll('[data-ops]').forEach(btn => btn.classList.toggle('active', state.domain === 'operations' && btn.dataset.ops === state.ops));
}

async function render() {
  setActiveTab();
  const cfg = domainConfig[state.domain];
  $('sideTitle').textContent = cfg.label;
  $('sideDesc').textContent = cfg.desc;
  $('pageEyebrow').textContent = state.domain.toUpperCase();
  $('pageTitle').textContent = cfg.label;
  $('pageDesc').textContent = cfg.desc;

  if (state.domain === 'operations') {
    await renderOperations();
  } else {
    await renderDomain();
  }
}

async function renderDomain() {
  const cfg = domainConfig[state.domain];
  $('listTitle').textContent = `${cfg.label} · 今日关注`;
  const data = await api(cfg.today);
  $('listMeta').textContent = `${data.count} 条`;
  $('itemList').innerHTML = data.items.length ? data.items.map(renderCard).join('') : '<div class="empty">暂无数据，请先运行旧数据导入。</div>';
  document.querySelectorAll('[data-item-id]').forEach(card => card.addEventListener('click', () => openDetail(Number(card.dataset.itemId))));
}

async function renderOperations() {
  const opsKey = state.ops || 'tasks';
  state.ops = opsKey;
  setActiveTab();
  const [endpoint, label] = opsEndpoints[opsKey];
  $('listTitle').textContent = `统一运营 · ${label}`;
  const data = await api(endpoint);
  const items = Array.isArray(data.items) ? data.items : Object.entries(data.items || {}).flatMap(([domain, rules]) => rules.map(rule => ({ domain, ...rule })));
  $('listMeta').textContent = `${items.length} 条`;
  $('itemList').innerHTML = items.length ? items.map(renderOpsCard).join('') : '<div class="empty">暂无运营数据</div>';
}

function renderCard(item) {
  const score = item.score === null || item.score === undefined ? '--' : Number(item.score).toFixed(item.score > 1 ? 0 : 2);
  const tags = (item.tags || []).slice(0, 4).map(tag => `<span class="badge">${escapeHtml(tag)}</span>`).join('');
  return `
    <article class="card" data-item-id="${item.id}">
      <h4>${escapeHtml(item.title)}</h4>
      <p>${escapeHtml(item.summary || '暂无摘要')}</p>
      <div class="meta">
        <span class="badge score">评分 ${score}</span>
        <span class="badge">${escapeHtml(item.status || 'active')}</span>
        <span class="badge">${escapeHtml(item.source || 'legacy')}</span>
        ${tags}
      </div>
    </article>
  `;
}

function renderOpsCard(item) {
  const title = item.pipeline_name || item.name || item.audit_type || item.queue_type || item.step_name || item.domain || '运营项';
  const summary = item.summary || item.reason || item.status || item.description || JSON.stringify(item.summary || item.details || item.payload || item.metrics || {}).slice(0, 180);
  return `
    <article class="card">
      <h4>${escapeHtml(title)}</h4>
      <p>${escapeHtml(summary || '暂无说明')}</p>
      <div class="meta">
        <span class="badge">${escapeHtml(item.domain || 'all')}</span>
        <span class="badge">${escapeHtml(item.status || item.health || 'ok')}</span>
      </div>
    </article>
  `;
}

async function openDetail(id) {
  const cfg = domainConfig[state.domain];
  const item = await api(cfg.detail(id));
  $('detailTitle').textContent = item.title;
  const evidence = item.evidence || [];
  $('detailBody').innerHTML = `
    <section class="detail-section">
      <h4>摘要</h4>
      <p>${escapeHtml(item.summary || '暂无摘要')}</p>
      <div class="meta">
        <span class="badge score">评分 ${item.score ?? '--'}</span>
        <span class="badge">${escapeHtml(item.status || '')}</span>
        <span class="badge">${escapeHtml(item.source || '')}</span>
      </div>
    </section>
    ${evidence.map(ev => `
      <section class="detail-section">
        <h4>${escapeHtml(ev.title || ev.evidence_type)}</h4>
        <p>${escapeHtml(ev.content || '')}</p>
      </section>
    `).join('')}
    <section class="detail-section">
      <h4>原始字段</h4>
      <pre>${escapeHtml(JSON.stringify(item.payload || {}, null, 2).slice(0, 3000))}</pre>
    </section>
  `;
  $('detailDialog').showModal();
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[char]));
}

async function boot() {
  try {
    await loadOverview();
    await render();
  } catch (error) {
    $('systemStatus').textContent = `连接失败：${error.message}`;
    $('itemList').innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
  }
}

document.querySelectorAll('[data-domain]').forEach(btn => btn.addEventListener('click', () => {
  state.domain = btn.dataset.domain;
  state.ops = state.domain === 'operations' ? (state.ops || 'tasks') : null;
  render();
}));

document.querySelectorAll('[data-ops]').forEach(btn => btn.addEventListener('click', () => {
  state.domain = 'operations';
  state.ops = btn.dataset.ops;
  render();
}));

$('refreshBtn').addEventListener('click', async () => { await loadOverview(); await render(); });
$('closeDialog').addEventListener('click', () => $('detailDialog').close());

boot();
