/* Settings › AI — trang hợp nhất (PR-5, refs #109).
 *
 * Nói chuyện với API thật của PR-3/PR-4/PR-6 (docs/ai-settings-web-contract.md):
 *   GET/PUT /api/ai/settings · POST /api/ai/test · POST /api/ai/ollama/check · GET /api/ai/models
 *   /api/me/ai-credentials* · GET /api/ai/credentials · POST /api/ai/credentials/{id}/revoke · GET /api/ai/usage
 *   /api/ollama/* (danh sách model đã cài, health, pull, delete).
 * Bí mật: ô key là type=password (kể cả SA JSON của Vertex), đọc vào body request tại thời điểm gửi, xoá ô ngay sau khi
 * gửi; không giữ trong biến/State, không localStorage, không in ra toast/lỗi. Lỗi chỉ hiển thị mã chuẩn hoá đã map sang
 * chuỗi i18n — không bao giờ render text của server/provider.
 */
(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
  const val = (id) => { const e = $(id); return e ? e.value : ''; };
  const setVal = (id, v) => { const e = $(id); if (e) e.value = (v === null || v === undefined) ? '' : v; };
  const esc = (s) => (typeof escHtml === 'function' ? escHtml(String(s)) : String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])));

  // Tile provider của cấu hình TỔ CHỨC (ADMIN). Vertex + openai_compatible chỉ có ở cấp org (D4).
  const PROVIDERS = [
    { id: 'anthropic', name: 'Anthropic', sub: 'API key · WIF' },
    { id: 'bedrock', name: 'Amazon Bedrock', sub: 'IAM role · SSO profile · API key' },
    { id: 'openai', name: 'OpenAI', sub: 'API key' },
    { id: 'azure_openai', name: 'Azure OpenAI', sub: 'Key · Entra ID' },
    { id: 'gemini', name: 'Google Gemini', sub: 'API key' },
    { id: 'vertex', name: 'Vertex AI', sub: 'Service account' },
    { id: 'openai_compatible', name: 'OpenAI-compatible', sub: 'vLLM · LiteLLM · …' },
    { id: 'openrouter', name: 'OpenRouter', sub: 'API key' },
  ];
  const PROV_NAME = { anthropic: 'Anthropic', bedrock: 'Amazon Bedrock', openai: 'OpenAI', azure_openai: 'Azure OpenAI', gemini: 'Gemini', vertex: 'Vertex AI', openrouter: 'OpenRouter', openai_compatible: 'OpenAI-compatible' };
  const ORG_PROVIDERS = PROVIDERS.map((p) => p.id);
  const USER_PROVIDERS = ['anthropic', 'bedrock', 'openai', 'openrouter', 'azure_openai', 'gemini'];   // D4/PR-6: user không đặt base_url/endpoint → chỉ host cố định (Azure: chỉ tên resource)
  const KEY_PLACEHOLDER = { anthropic: 'sk-ant-…', bedrock: 'ABSK…', openai: 'sk-…', openrouter: 'sk-or-…', azure_openai: '••••••••', gemini: 'AIza…', vertex: '{ "type": "service_account", … }', openai_compatible: '••••••••' };
  const MODEL_SUGGEST = {
    anthropic: ['claude-opus-5-5', 'claude-sonnet-5-5', 'claude-haiku-5-5'],
    bedrock: ['us.anthropic.claude-sonnet-5-5', 'anthropic.claude-opus-5-5'],
    openai: ['gpt-4o'],
    openrouter: ['anthropic/claude-3.5-sonnet'],
    gemini: ['gemini-2.5-flash', 'gemini-2.5-pro'],
  };
  const SECRET_FIELDS = ORG_PROVIDERS;             // mọi section org có api_key (SA JSON của vertex cũng là "api_key")
  // Provider có ô key org luôn hiện hay phụ thuộc auth_mode (xem needsKey).
  const SECTION_OF = (k) => (k === 'mode' ? '1' : k.startsWith('ollama.') ? '2' : k.startsWith('hybrid.') ? '2b' : k.startsWith('policy.') ? '5' : '3');
  const HASH_MAP = {
    '#st-ollama': ['aiu-sec-ollama', '#ollama'], '#ollama': ['aiu-sec-ollama', '#ollama'],
    '#st-ai': ['aiu-sec-mode', '#mode'], '#mode': ['aiu-sec-mode', '#mode'],
    '#hybrid': ['aiu-sec-hybrid', '#hybrid'], '#cloud': ['aiu-sec-cloud', '#cloud'],
    '#my-keys': ['aiu-sec-mine', '#my-keys'], '#policy': ['aiu-sec-policy', '#policy'],
  };

  const S = {
    lang: 'vi', dict: { vi: {}, en: {} },
    data: null, base: null,
    sel: 'local_only', prov: 'anthropic',
    olCheck: null, lastTest: null,        // lastTest: {at, ok} của lần test cloud trong phiên này
    creds: null, credsState: 'idle',   // idle | ok | forbidden | error
    ukeys: null, usage: null, azMap: [],
    rotating: null,
    inited: false, loading: null, saving: false,
    pullAbort: null,
  };

  /* ───────── i18n ───────── */
  function pickLang() {
    try { const v = localStorage.getItem('vg-ai-lang'); if (v === 'vi' || v === 'en') return v; } catch (e) { /* storage có thể bị chặn */ }
    const n = (navigator.language || 'vi').toLowerCase();
    return n.startsWith('en') ? 'en' : 'vi';
  }
  function t(key, vars) {
    let s = S.dict[S.lang][key];
    if (s === undefined) s = S.dict.vi[key];
    if (s === undefined) return key;
    if (vars) s = s.replace(/\{(\w+)\}/g, (m, k) => (vars[k] === undefined || vars[k] === null ? '' : String(vars[k])));
    return s;
  }
  async function loadDict(lang) {
    if (Object.keys(S.dict[lang]).length) return;
    try {
      const r = await fetch('/static/i18n/ai.' + lang + '.json', { cache: 'no-cache' });
      if (r.ok) S.dict[lang] = await r.json();
    } catch (e) { /* rơi về VI/khoá */ }
  }
  function applyLang() {
    const root = $('st-ai'); if (!root) return;
    root.lang = S.lang;
    $$('[data-i18n]', root).forEach((e) => { e.textContent = t(e.dataset.i18n); });
    $$('[data-i18n-ph]', root).forEach((e) => { e.placeholder = t(e.dataset.i18nPh); });
    $$('#aiu-lang button', root).forEach((b) => b.classList.toggle('on', b.dataset.v === S.lang));
  }
  async function setLang(l) {
    S.lang = l; try { localStorage.setItem('vg-ai-lang', l); } catch (e) { /* ignore */ }
    await loadDict(l); applyLang(); $('aiu-cloud-res').classList.add('aiu-hide');   // kết quả test cũ đã render bằng ngôn ngữ trước
    if (S.data) { fillOllamaSelects(val('aiu-ol-model'), val('aiu-ol-vision')); renderAll(); updateDirty(); }
  }

  /* ───────── helpers ───────── */
  const role = () => (typeof currentUser !== 'undefined' && currentUser && currentUser.role) || 'ADMIN';   // auth tắt → như canAdmin()
  const isAdmin = () => role() === 'ADMIN';
  const isViewer = () => role() === 'VIEWER';

  async function aiApi(path, opts) {
    opts = opts || {};
    const init = { method: opts.method || 'GET', headers: { 'Content-Type': 'application/json' } };
    if (opts.body !== undefined) init.body = JSON.stringify(opts.body);
    const r = await fetch((typeof API === 'string' ? API : '') + path, init);
    if (typeof check401 === 'function') check401(r);
    let data = null;
    try { data = r.status === 204 ? null : await r.json(); } catch (e) { data = null; }
    return { ok: r.ok, status: r.status, data };
  }
  // CHỈ hiển thị mã lỗi đã map sang chuỗi i18n của UI; không bao giờ render text do server/provider trả về.
  const KNOWN_CODE = /^[A-Z][A-Z0-9_]{1,40}$/;
  function codeOf(r) {
    const d = r && r.data; if (!d || typeof d !== 'object') return null;
    let c = d.code || (d.detail && typeof d.detail === 'object' && d.detail.code) || null;
    if (!c && typeof d.error === 'string') { const m = /^\[([A-Za-z_]+)\]/.exec(d.error); if (m) c = m[1]; }   // tiền tố "[auth_failed] …" của PR-0: chỉ lấy mã
    if (!c && typeof d.detail === 'string') { const m = /^([A-Z][A-Z0-9_]{1,40}):/.exec(d.detail); if (m) c = m[1]; }       // PUT /api/ai/settings: "BAD_BASE_URL: …" → chỉ lấy mã, bỏ phần chữ
    c = typeof c === 'string' ? c.toUpperCase() : null;
    return c && KNOWN_CODE.test(c) ? c : null;
  }
  function errText(r) {
    if (!r) return t('err.generic');
    if (r.status === 429) return t('err.throttled');      // throttle của chính server (kể cả mã RATE_LIMITED) — không phải lỗi provider
    const code = codeOf(r);
    if (code && S.dict.vi['code.' + code] !== undefined) return t('code.' + code);
    if (r.status === 403) return t('err.forbidden');
    if (r.status === 404 || r.status === 405 || r.status === 501) return t('err.unavailable');
    if (r.status === 429) return t('err.throttled');
    return t('err.generic');
  }
  function rel(iso) {
    if (!iso) return '';
    const d = new Date(iso); if (isNaN(d)) return '';
    const s = (d.getTime() - Date.now()) / 1000, a = Math.abs(s);
    let rtf; try { rtf = new Intl.RelativeTimeFormat(S.lang, { numeric: 'auto' }); } catch (e) { return ''; }
    if (a < 3600) return rtf.format(Math.round(s / 60), 'minute');
    if (a < 86400) return rtf.format(Math.round(s / 3600), 'hour');
    return rtf.format(Math.round(s / 86400), 'day');
  }
  const sectionData = (p) => (S.data && S.data[p]) || {};
  const clearSecrets = () => { $$('#st-ai .aiu-secret').forEach((e) => { e.value = ''; }); };

  /* ───────── skeleton: provider blocks ───────── */
  function keyGroup(p, keyLabel) {
    // SA JSON của Vertex cũng là input type=password: dán JSON nhiều dòng sẽ bị bỏ xuống dòng, vẫn là JSON hợp lệ (private_key dùng \n dạng escape)
    const field = `<input id="aiu-${p}-key" class="aiu-mono aiu-secret aiu-admin" type="password" autocomplete="new-password" autocapitalize="off" spellcheck="false" data-lpignore="true" data-1p-ignore data-testid="aiu-${p}-key" style="flex:1;min-width:0">`;
    return `<div class="aiu-f" id="aiu-${p}-keywrap"><label for="aiu-${p}-key" data-i18n="${keyLabel || 'key'}"></label>
      <div class="aiu-row">${field}
      <button type="button" class="btn btn-ghost btn-sm aiu-admin" data-act="key-replace" data-p="${p}" data-i18n="replace"></button>
      <button type="button" class="btn btn-ghost btn-sm aiu-admin aiu-danger" data-act="key-remove" data-p="${p}" id="aiu-${p}-remove" data-i18n="remove"></button></div>
      <div class="aiu-hint" id="aiu-${p}-keyhint"></div><div class="aiu-err" id="aiu-${p}-keyerr" role="alert"></div></div>`;
  }
  function modelGroup(p, ph) {
    return `<div class="aiu-f"><label for="aiu-${p}-model"><span data-i18n="model"></span> <a href="#" class="aiu-admin-link" data-act="models" data-p="${p}" title="refresh" style="font-weight:400">⟳</a></label>
      <input id="aiu-${p}-model" class="aiu-admin aiu-mono" list="aiu-${p}-dl" autocomplete="off" placeholder="${ph}"><datalist id="aiu-${p}-dl"></datalist>
      <div class="aiu-hint" id="aiu-${p}-modelnote"></div></div>`;
  }
  function renderBlocks() {
    const H = {
      anthropic: `<div class="aiu-grid">
        <div class="aiu-f"><label for="aiu-anthropic-auth" data-i18n="auth"></label><select id="aiu-anthropic-auth" class="aiu-admin"><option value="api_key" data-i18n="authKey"></option><option value="wif" data-i18n="authWif"></option><option value="environment" data-i18n="authEnv"></option></select></div>
        ${modelGroup('anthropic', 'claude-opus-5-5')}
        ${keyGroup('anthropic')}
        <div class="aiu-f" id="aiu-anthropic-envnote"><div class="aiu-note" data-i18n="envNote"></div></div></div>
        <details class="aiu-details" id="aiu-anthropic-wif"><summary data-i18n="wifTitle"></summary><div class="aiu-grid" style="margin-top:10px">
          <div class="aiu-f"><label for="aiu-wif-rule">Federation rule ID</label><input id="aiu-wif-rule" class="aiu-admin aiu-mono" autocomplete="off"></div>
          <div class="aiu-f"><label for="aiu-wif-org">Organization ID</label><input id="aiu-wif-org" class="aiu-admin aiu-mono" autocomplete="off"></div>
          <div class="aiu-f"><label for="aiu-wif-token" data-i18n="wifToken"></label><input id="aiu-wif-token" class="aiu-admin aiu-mono" autocomplete="off"></div>
          <div class="aiu-f"><label for="aiu-wif-ws">Workspace ID</label><input id="aiu-wif-ws" class="aiu-admin aiu-mono" autocomplete="off"></div>
          <div class="aiu-f"><label for="aiu-wif-sa">Service account ID</label><input id="aiu-wif-sa" class="aiu-admin aiu-mono" autocomplete="off"></div></div></details>`,
      bedrock: `<div class="aiu-grid">
        <div class="aiu-f"><label for="aiu-bedrock-auth" data-i18n="auth"></label><select id="aiu-bedrock-auth" class="aiu-admin"><option value="aws_chain" data-i18n="brChain"></option><option value="profile" data-i18n="brProfile"></option><option value="bedrock_api_key" data-i18n="brKey"></option></select></div>
        <div class="aiu-f"><label for="aiu-bedrock-region">Region</label><input id="aiu-bedrock-region" class="aiu-admin aiu-mono" placeholder="us-east-1" autocomplete="off"></div>
        ${modelGroup('bedrock', 'anthropic.claude-opus-5-5')}
        <div class="aiu-f" id="aiu-bedrock-profwrap"><label for="aiu-bedrock-profile">AWS profile</label><input id="aiu-bedrock-profile" class="aiu-admin aiu-mono" placeholder="default" autocomplete="off"><div class="aiu-hint" data-i18n="brProfileHint"></div></div>
        ${keyGroup('bedrock')}</div>`,
      openai: `<div class="aiu-grid">
        ${modelGroup('openai', 'gpt-4o')}
        <div class="aiu-f"><label for="aiu-openai-base" data-i18n="baseUrl"></label><input id="aiu-openai-base" class="aiu-admin aiu-mono" placeholder="https://api.openai.com/v1" autocomplete="off"><div class="aiu-err" id="aiu-openai-baseerr" role="alert"></div></div>
        ${keyGroup('openai')}</div>`,
      openrouter: `<div class="aiu-grid">
        ${modelGroup('openrouter', 'anthropic/claude-3.5-sonnet')}
        ${keyGroup('openrouter')}</div>`,
      azure_openai: `<div class="aiu-grid">
        <div class="aiu-f"><label for="aiu-azure_openai-auth" data-i18n="auth"></label><select id="aiu-azure_openai-auth" class="aiu-admin"><option value="api_key" data-i18n="authKey"></option><option value="entra" data-i18n="azEntra"></option></select></div>
        <div class="aiu-f"><label for="aiu-azure_openai-endpoint" data-i18n="azEndpoint"></label><input id="aiu-azure_openai-endpoint" class="aiu-admin aiu-mono" placeholder="https://myres.openai.azure.com" autocomplete="off"><div class="aiu-hint" data-i18n="azEndpointHint"></div><div class="aiu-err" id="aiu-azure_openai-endpointerr" role="alert"></div></div>
        <div class="aiu-f"><label for="aiu-azure_openai-deployment" data-i18n="azDeployment"></label><input id="aiu-azure_openai-deployment" class="aiu-admin aiu-mono" placeholder="prod-chat" autocomplete="off"><div class="aiu-hint" data-i18n="azDeploymentHint"></div></div>
        <div class="aiu-f"><label for="aiu-azure_openai-version" data-i18n="azVersion"></label><input id="aiu-azure_openai-version" class="aiu-admin aiu-mono" placeholder="2024-10-21" autocomplete="off"></div>
        <div class="aiu-f" id="aiu-azure_openai-tenantwrap"><label for="aiu-azure_openai-tenant">Tenant ID</label><input id="aiu-azure_openai-tenant" class="aiu-admin aiu-mono" autocomplete="off"></div>
        <div class="aiu-f" id="aiu-azure_openai-clientwrap"><label for="aiu-azure_openai-client">Client ID</label><input id="aiu-azure_openai-client" class="aiu-admin aiu-mono" autocomplete="off"></div>
        ${keyGroup('azure_openai')}</div>`,
      gemini: `<div class="aiu-grid">
        ${modelGroup('gemini', 'gemini-2.5-flash')}
        ${keyGroup('gemini')}</div>`,
      vertex: `<div class="aiu-grid">
        <div class="aiu-f"><label for="aiu-vertex-project">GCP project</label><input id="aiu-vertex-project" class="aiu-admin aiu-mono" autocomplete="off"></div>
        <div class="aiu-f"><label for="aiu-vertex-location">Location</label><input id="aiu-vertex-location" class="aiu-admin aiu-mono" placeholder="us-central1" autocomplete="off"></div>
        ${modelGroup('vertex', 'google/gemini-2.5-flash')}
        ${keyGroup('vertex', 'vxKey')}</div>`,
      openai_compatible: `<div class="aiu-grid">
        <div class="aiu-f"><label for="aiu-openai_compatible-base" data-i18n="baseUrl"></label><input id="aiu-openai_compatible-base" class="aiu-admin aiu-mono" placeholder="https://llm.example.com/v1" autocomplete="off"><div class="aiu-err" id="aiu-openai_compatible-baseerr" role="alert"></div></div>
        ${modelGroup('openai_compatible', 'model-id')}
        ${keyGroup('openai_compatible')}</div>`,
    };
    $('aiu-prov-blocks').innerHTML = ORG_PROVIDERS.map((p) => `<div class="aiu-prov-block" data-p="${p}">${H[p]}</div>`).join('');
    $('aiu-add-prov').innerHTML = USER_PROVIDERS.map((p) => `<option value="${p}">${esc(PROV_NAME[p])}</option>`).join('');
  }

  /* ───────── data ───────── */
  // /api/ai/settings trả cấu hình + ollama{url,custom,default_url,model,vision_model}; danh sách model đã cài / reachable
  // lấy từ /api/ollama/* (GET mở cho mọi role). Tool-calling chỉ biết sau POST /api/ai/ollama/check (ADMIN).
  async function fetchSettings() {
    const [r, models] = await Promise.all([aiApi('/api/ai/settings'), aiApi('/api/ollama/models')]);
    if (!r.ok || !r.data || typeof r.data !== 'object' || !r.data.mode) { const e = new Error('settings'); e.status = r.status; throw e; }
    const d = r.data; d.ollama = d.ollama || {};
    const chk = S.olCheck && S.olCheck.model === d.ollama.model ? S.olCheck : null;
    d.ollama.installed = ((models.data && models.data.models) || []).map((m) => ({ name: m.name, size_gb: m.size_gb, tools: chk && chk.ok && chk.model === m.name ? chk.tools === true : null }));
    d.ollama.reachable = !!models.ok;
    d.status = d.status || {};
    d.status.ollama = { reachable: d.ollama.reachable, latency_ms: chk && chk.latency_ms != null ? chk.latency_ms : null, model: d.ollama.model, tools: chk && chk.ok ? chk.tools === true : null };
    return d;
  }

  /* ───────── fill ───────── */
  function fillOllamaSelects(keepModel, keepVision) {
    const o = (S.data && S.data.ollama) || {};
    const inst = o.installed || [];
    const label = (m) => `${m.name}${m.size_gb != null ? ' — ' + m.size_gb + ' GB' : ''}${m.tools === true ? ' · tools ✓' : m.tools === false ? ' · tools ✗' : ''}`;
    const build = (selId, cur, allowNone, missId) => {
      const sel = $(selId); const names = inst.map((m) => m.name);
      let h = '';
      if (allowNone) h += `<option value="">${esc(t('none'))}</option>`;
      else if (!cur) h += `<option value="">${esc(t('olPick'))}</option>`;
      if (cur && !names.includes(cur)) h += `<option value="${esc(cur)}">${esc(cur)} — ⚠ ${esc(t('notInstalled'))}</option>`;
      h += inst.map((m) => `<option value="${esc(m.name)}">${esc(label(m))}</option>`).join('');
      sel.innerHTML = h; sel.value = cur || '';
      const miss = $(missId);
      const missing = !!cur && !names.includes(cur) && o.reachable !== false;
      miss.classList.toggle('aiu-hide', !missing);
      miss.textContent = missing ? t('missingModel', { m: cur }) : '';
    };
    build('aiu-ol-model', keepModel !== undefined ? keepModel : (o.model || ''), false, 'aiu-ol-model-missing');
    build('aiu-ol-vision', keepVision !== undefined ? keepVision : (o.vision_model || ''), true, 'aiu-ol-vision-missing');
  }
  function fill() {
    const d = S.data;
    S.sel = d.mode || 'local_only'; S.prov = d.provider || 'anthropic';
    const o = d.ollama || {};
    setVal('aiu-ol-url', o.custom === false ? '' : (o.url || ''));
    $('aiu-ol-url').placeholder = o.default_url || o.url || 'http://localhost:11434';
    $('aiu-ol-url-hint').textContent = t('olUrlHint', { def: o.default_url || o.url || 'http://localhost:11434' });
    fillOllamaSelects();
    const h = d.hybrid || {};
    setVal('aiu-h-sev', h.escalate_min_severity || 'MEDIUM'); setVal('aiu-h-lo', h.fp_band_low); setVal('aiu-h-hi', h.fp_band_high);
    const a = sectionData('anthropic'), b = sectionData('bedrock'), oa = sectionData('openai'), orr = sectionData('openrouter');
    const az = sectionData('azure_openai'), ge = sectionData('gemini'), vx = sectionData('vertex'), oc = sectionData('openai_compatible');
    setVal('aiu-anthropic-auth', a.auth_mode || 'api_key'); setVal('aiu-anthropic-model', a.model);
    const w = a.wif || {};
    setVal('aiu-wif-rule', w.federation_rule_id); setVal('aiu-wif-org', w.organization_id); setVal('aiu-wif-token', w.identity_token_file); setVal('aiu-wif-ws', w.workspace_id); setVal('aiu-wif-sa', w.service_account_id);
    setVal('aiu-bedrock-auth', b.auth_mode || 'aws_chain'); setVal('aiu-bedrock-region', b.region); setVal('aiu-bedrock-profile', b.aws_profile); setVal('aiu-bedrock-model', b.model);
    setVal('aiu-openai-model', oa.model); setVal('aiu-openai-base', oa.base_url);
    setVal('aiu-openrouter-model', orr.model);
    setVal('aiu-azure_openai-auth', az.auth_mode || 'api_key'); setVal('aiu-azure_openai-endpoint', az.endpoint); setVal('aiu-azure_openai-deployment', az.deployment);
    setVal('aiu-azure_openai-version', az.api_version); setVal('aiu-azure_openai-tenant', az.tenant_id); setVal('aiu-azure_openai-client', az.client_id);
    setVal('aiu-gemini-model', ge.model);
    setVal('aiu-vertex-project', vx.project); setVal('aiu-vertex-location', vx.location); setVal('aiu-vertex-model', vx.model);
    setVal('aiu-openai_compatible-base', oc.base_url); setVal('aiu-openai_compatible-model', oc.model);
    clearSecrets();
    const pv = d.privacy || {};
    $('aiu-pv-send').checked = !!pv.send_code_context; setVal('aiu-pv-lines', pv.context_lines);
    const pm = (d.advanced && d.advanced.pentest_models) || {};      // chỉ đọc: PUT bỏ qua `advanced`, giá trị do env PENTEST_LLM_*_MODEL
    setVal('aiu-pt-planner', pm.planner); setVal('aiu-pt-executor', pm.executor); setVal('aiu-pt-summarizer', pm.summarizer);
    const p = d.policy || {};
    setVal('aiu-p-byok', p.byok || 'allowed'); setVal('aiu-p-fallback', p.fallback_to_org === false ? '0' : '1');
    setVal('aiu-p-allowed', (p.allowed || []).join(', '));
    const q = p.org_quota || {};
    setVal('aiu-p-usd', q.usd_per_user_month == null ? '' : q.usd_per_user_month); setVal('aiu-p-rpm', q.rpm_per_user == null ? '' : q.rpm_per_user);
    setVal('aiu-p-sched', p.scheduled_jobs_credential || 'org'); setVal('aiu-p-baseurl', p.custom_base_url || 'admin_only');
    setVal('aiu-route-cw', (h.tasks && h.tasks.coworker) || 'local');
    S.azMap = Object.entries(p.azure_deployment_models || {}).map(([k, m]) => { const i = k.indexOf('/'); return { res: k.slice(0, i), dep: k.slice(i + 1), model: m }; });
    renderAzMap();
    renderAll();
    S.base = formState();
    updateDirty();
  }

  /* ───────── form state / dirty ───────── */
  function formState() {
    const f = {};
    f.mode = S.sel;
    f['ollama.url'] = val('aiu-ol-url').trim(); f['ollama.model'] = val('aiu-ol-model'); f['ollama.vision_model'] = val('aiu-ol-vision');
    f['hybrid.route_cw'] = val('aiu-route-cw'); f['hybrid.sev'] = val('aiu-h-sev'); f['hybrid.lo'] = val('aiu-h-lo'); f['hybrid.hi'] = val('aiu-h-hi');
    f['cloud.provider'] = S.prov;
    ['anthropic-auth', 'anthropic-model', 'bedrock-auth', 'bedrock-region', 'bedrock-profile', 'bedrock-model', 'openai-model', 'openai-base', 'openrouter-model',
      'azure_openai-auth', 'azure_openai-endpoint', 'azure_openai-deployment', 'azure_openai-version', 'azure_openai-tenant', 'azure_openai-client',
      'gemini-model', 'vertex-project', 'vertex-location', 'vertex-model', 'openai_compatible-base', 'openai_compatible-model',
      'wif-rule', 'wif-org', 'wif-token', 'wif-ws', 'wif-sa', 'pv-lines'].forEach((k) => { f['cloud.' + k] = val('aiu-' + k); });
    f['cloud.pv-send'] = $('aiu-pv-send').checked;
    ORG_PROVIDERS.forEach((p) => { f['cloud.key.' + p] = val('aiu-' + p + '-key') ? 'typed' : ''; });   // KHÔNG lưu giá trị key
    if (isAdmin()) {
      ['byok', 'fallback', 'allowed', 'usd', 'rpm', 'sched', 'baseurl'].forEach((k) => { f['policy.' + k] = val('aiu-p-' + k); });
      f['policy.azmap'] = JSON.stringify(azMapObject());
    }
    return f;
  }
  function changes() {
    if (!S.base) return [];
    const cur = formState();
    return Object.keys(cur).filter((k) => cur[k] !== S.base[k]);
  }
  function updateDirty() {
    const ch = changes(); const secs = Array.from(new Set(ch.map(SECTION_OF)));
    const order = ['1', '2', '2b', '3', '5'];
    secs.sort((a, b) => order.indexOf(a) - order.indexOf(b));
    const el = $('aiu-unsaved');
    el.textContent = ch.length ? t('unsaved', { n: ch.length, s: secs.join(', ') }) : t('noChanges');
    $('aiu-save').disabled = !ch.length || S.saving;
    $('aiu-discard').disabled = !ch.length || S.saving;
    $('aiu-save').dataset.dirty = ch.length ? '1' : '0';
    renderBand();
    renderStatus();
  }

  /* ───────── render ───────── */
  function renderAll() {
    renderStatus(); renderModes(); renderVisibility(); renderProviders(); renderKeyHints(); renderChecks(); renderInstalled();
    renderBand(); renderMine(); renderPolicyBits(); renderBanners(); applyRole(); updatePrivacyWarn();
  }
  function modeLabel(m) { return m === 'local_only' ? 'Local' : m === 'cloud_only' ? 'Cloud' : 'Hybrid'; }
  function renderStatus() {
    const d = S.data; const box = $('aiu-status');
    if (!d) { box.innerHTML = ''; return; }
    const st = d.status || {}; const ol = st.ollama || {}; const cl = st.cloud || {}; const me = st.mine;
    const pills = [];
    pills.push({ c: 'ok', b: t('stMode', { m: modeLabel(S.sel) }), s: t('stModeSub' + (S.sel === 'local_only' ? 'L' : S.sel === 'cloud_only' ? 'C' : 'H')) });
    if (S.sel === 'cloud_only') pills.push({ c: 'off', b: 'Ollama', s: t('stOllamaOff') });
    else {
      const parts = [];
      if (ol.model) parts.push(ol.model);
      if (ol.latency_ms != null) parts.push(ol.latency_ms + ' ms');
      if (ol.tools === true) parts.push(t('toolsOk')); else if (ol.tools === false) parts.push(t('toolsNo'));
      pills.push({ c: ol.reachable === false ? 'err' : (ol.tools === false ? 'warn' : 'ok'), b: 'Ollama', s: ol.reachable === false ? t('stOllamaDown') : (parts.join(' · ') || t('stOllamaNoModel')) });
    }
    if (S.sel === 'local_only') pills.push({ c: 'off', b: t('stCloudOff'), s: t('stCloudOffSub') });
    else {
      const nm = PROV_NAME[S.prov] || S.prov;
      const lt = S.lastTest && S.lastTest.prov === S.prov ? S.lastTest : null;
      const at = lt ? lt.at : cl.last_test_at, okk = lt ? lt.ok : cl.last_test_ok;
      const tested = at ? t('stCloudTested', { w: rel(at) }) : t('stCloudNever');
      pills.push({ c: cl.configured === false ? 'err' : (okk === false ? 'err' : (at ? 'ok' : 'warn')), b: t('stCloud', { p: nm }), s: cl.configured === false ? t('stCloudNone') : tested });
    }
    if (!isViewer()) {
      if (!me) pills.push({ c: 'off', b: t('stMine', { p: '—' }), s: t('stMineNA') });
      else if (me.source === 'own') pills.push({ c: 'ok', b: t('stMine', { p: (PROV_NAME[me.provider] || me.provider || '') + (me.hint ? ' ' + me.hint : '') }), s: t('stMineOwn') });
      else if (me.source === 'org') pills.push({ c: 'warn', b: t('stMineOrgB'), s: t('stMineOrg') });
      else pills.push({ c: 'err', b: t('stMineNoneB'), s: t('stMineNone') });
    }
    box.innerHTML = pills.map((p) => `<div class="aiu-pill"><i class="aiu-dot ${p.c}"></i><div><b>${esc(p.b)}</b><span>${esc(p.s)}</span></div></div>`).join('');
  }
  function renderModes() {
    $$('#aiu-modes .aiu-mode').forEach((b) => b.setAttribute('aria-checked', String(b.dataset.mode === S.sel)));
  }
  function renderVisibility() {
    $('aiu-sec-ollama').classList.toggle('aiu-hide', S.sel === 'cloud_only');
    $('aiu-sec-hybrid').classList.toggle('aiu-hide', S.sel !== 'hybrid');
    $('aiu-sec-cloud').classList.toggle('aiu-hide', S.sel === 'local_only');
  }
  function availableProviders() {
    const av = S.data && S.data.providers_available;
    return Array.isArray(av) ? av : ORG_PROVIDERS;
  }
  const needsKey = (p) => (p === 'anthropic' ? val('aiu-anthropic-auth') === 'api_key' : p === 'bedrock' ? val('aiu-bedrock-auth') === 'bedrock_api_key'
    : p === 'azure_openai' ? true : p === 'openai_compatible' ? false : true);
  function renderProviders() {
    const av = availableProviders();
    $('aiu-prov').innerHTML = PROVIDERS.filter((p) => av.includes(p.id)).map((p) =>
      `<button type="button" role="radio" class="aiu-admin" data-prov="${p.id}" aria-checked="${p.id === S.prov}">${esc(p.name)}<small>${esc(p.sub)}</small></button>`).join('');
    $$('#aiu-prov-blocks .aiu-prov-block').forEach((b) => b.classList.toggle('aiu-hide', b.dataset.p !== S.prov));
    const a = val('aiu-anthropic-auth'), br = val('aiu-bedrock-auth'), az = val('aiu-azure_openai-auth');
    $('aiu-anthropic-keywrap').classList.toggle('aiu-hide', a !== 'api_key');
    $('aiu-anthropic-wif').classList.toggle('aiu-hide', a !== 'wif');
    $('aiu-anthropic-envnote').classList.toggle('aiu-hide', a !== 'environment');
    $('aiu-bedrock-profwrap').classList.toggle('aiu-hide', br !== 'profile');
    $('aiu-bedrock-keywrap').classList.toggle('aiu-hide', br !== 'bedrock_api_key');
    $('aiu-azure_openai-tenantwrap').classList.toggle('aiu-hide', az !== 'entra');
    $('aiu-azure_openai-clientwrap').classList.toggle('aiu-hide', az !== 'entra');
    $$('#aiu-prov button').forEach((b) => { b.disabled = !isAdmin(); });
  }
  function renderKeyHints() {
    ORG_PROVIDERS.forEach((p) => {
      const sec = sectionData(p); const inp = $('aiu-' + p + '-key'); if (!inp) return;
      const set = !!sec.api_key_set;
      inp.placeholder = set ? (p === 'vertex' ? '•••• (service account)' : '•••• ' + String(sec.api_key_hint || '').replace(/^…/, '')) : KEY_PLACEHOLDER[p];
      $('aiu-' + p + '-keyhint').textContent = set ? (p === 'vertex' ? t('keySavedNoHint') : t('keySaved', { h: sec.api_key_hint || '••••' })) : t(p === 'openai_compatible' ? 'keyOptional' : 'keyNone');
      $('aiu-' + p + '-remove').classList.toggle('aiu-hide', !set);
    });
  }
  function checkItem(c, text) { return `<li class="${c}">${esc(text)}</li>`; }
  function renderChecks() {
    const ul = $('aiu-ol-checks'); const c = S.olCheck;
    if (!c) { ul.innerHTML = checkItem('q', t('ckNone')); return; }
    const li = [];
    if (c.ok === false && !c.version && c.model_installed !== false) li.push(checkItem('x', t('ckConn') + ': ' + errText({ data: c })));
    else li.push(checkItem('ok', t('ck1', { ms: c.latency_ms == null ? '—' : c.latency_ms, v: c.version || '—' })));
    if (c.model_installed === true) li.push(checkItem('ok', t('ck2')));
    else if (c.model_installed === false) li.push(checkItem('x', t('ck2no')));
    if (c.ok) {
      li.push(c.tools === true ? checkItem('ok', t('ck3')) : checkItem('x', t(S.sel === 'local_only' ? 'ck3noL' : 'ck3noH')));
      li.push(c.json === true ? checkItem('ok', t('ck4ok')) : checkItem('q', t('ck4bad')));
    }
    ul.innerHTML = li.join('');
  }
  function renderInstalled() {
    const o = (S.data && S.data.ollama) || {}; const inst = o.installed || []; const admin = isAdmin();
    const rows = inst.map((m) => {
      const inUse = m.name === o.model;
      const tools = m.tools === true ? '<span class="aiu-tag ok">✓</span>' : m.tools === false ? '<span class="aiu-tag err">✗</span>' : '<span class="aiu-tag">?</span>';
      return `<tr><td class="aiu-mono">${esc(m.name)}</td><td>${m.size_gb != null ? esc(m.size_gb) + ' GB' : '—'}</td><td>${tools}</td><td>${inUse ? `<span class="aiu-tag b">${esc(t('inUse'))}</span>` : `<button type="button" class="btn btn-ghost btn-sm aiu-admin aiu-danger" data-act="ol-del" data-name="${esc(m.name)}" ${admin ? '' : 'disabled'}>${esc(t('del'))}</button>`}</td></tr>`;
    }).join('');
    $('aiu-ol-table').innerHTML = `<tr><th>${esc(t('thModel'))}</th><th>${esc(t('thSize'))}</th><th>Tools</th><th></th></tr>` + (rows || `<tr><td colspan="4">${esc(t('noModels'))}</td></tr>`);
  }
  function renderBand() {
    let lo = parseInt(val('aiu-h-lo'), 10), hi = parseInt(val('aiu-h-hi'), 10);
    if (isNaN(lo)) lo = 0; if (isNaN(hi)) hi = 0;
    lo = Math.max(0, Math.min(100, lo)); hi = Math.max(0, Math.min(100, hi));
    const b = $('aiu-h-band'); const a = Math.min(lo, hi), z = Math.max(lo, hi);
    b.style.left = a + '%'; b.style.width = (z - a) + '%';
  }
  function updatePrivacyWarn() {
    $('aiu-pv-warn').classList.toggle('aiu-hide', !($('aiu-pv-send').checked && S.sel !== 'local_only'));
    $('aiu-pv-warn').textContent = t('pvWarn', { p: PROV_NAME[S.prov] || S.prov });
  }
  function renderBanners() {
    const ro = $('aiu-ro');
    if (isAdmin()) ro.classList.add('aiu-hide'); else { ro.classList.remove('aiu-hide'); ro.textContent = t(isViewer() ? 'roViewer' : 'ro'); }
  }
  function applyRole() {
    const admin = isAdmin();
    $$('#st-ai .aiu-admin').forEach((e) => { e.disabled = !admin; });
    $$('#aiu-modes .aiu-mode').forEach((b) => { b.disabled = !admin; b.setAttribute('aria-disabled', String(!admin)); });
    $('aiu-pv-redact').disabled = true;
    $('aiu-sec-mine').classList.toggle('aiu-hide', isViewer());
    $('aiu-sec-policy').classList.toggle('aiu-hide', !admin);
    $('aiu-savebar').classList.toggle('aiu-hide', !admin);
    $('aiu-ol-manage').querySelectorAll('button[data-act="ol-del"]').forEach((b) => { b.disabled = !admin; });
    $$('#aiu-azmap input, #aiu-azmap button').forEach((e) => { e.disabled = !admin; });
    $$('#aiu-prov-blocks .aiu-admin-link').forEach((a) => a.classList.toggle('aiu-hide', !admin));
    const mineOK = S.credsState === 'ok' && !isViewer();
    $('aiu-add-btn').disabled = !mineOK || byokOff();
  }
  function byokOff() { const p = S.data && (S.data.policy_public || S.data.policy); return !!p && p.byok === 'off'; }

  /* ── section 4: my keys ── */
  function allowedUserProviders() {
    const pp = (S.data && S.data.policy_public) || (S.data && S.data.policy) || {};
    const globs = pp.allowed || [];
    if (!globs.length) return USER_PROVIDERS.slice();
    const set = new Set();
    globs.forEach((g) => { const p = String(g).split(':')[0]; if (p === '*') USER_PROVIDERS.forEach((x) => set.add(x)); else if (USER_PROVIDERS.includes(p)) set.add(p); });
    return USER_PROVIDERS.filter((p) => set.has(p));
  }
  function statusTag(c) {
    const when = rel(c.last_validated_at);
    const bad = c.status !== 'valid' && c.last_error_code && S.dict.vi['code.' + c.last_error_code] !== undefined ? ' · ' + t('code.' + c.last_error_code) : '';
    const m = { valid: ['ok', 'stValid'], invalid: ['err', 'stInvalid'], forbidden: ['err', 'stForbidden'], rate_limited: ['warn', 'stRate'], revoked: ['err', 'stRevoked'], disabled: ['warn', 'stDisabled'], unknown: ['', 'stUnknown'] }[c.status] || ['', 'stUnknown'];
    return `<span class="aiu-tag ${m[0]}">${esc(t(m[1]))}${when ? ' · ' + esc(when) : ''}${esc(bad)}</span>`;
  }
  function renderMine() {
    const note = $('aiu-policy-note'); const pp = (S.data && (S.data.policy_public || S.data.policy)) || null;
    if (pp) {
      const prov = allowedUserProviders().map((p) => PROV_NAME[p]).join(', ') || '—';
      const q = (pp.org_quota && pp.org_quota.usd_per_user_month) || pp.usd_per_user_month;
      const fb = pp.fallback_to_org === false ? t('polFbNo') : (q ? t('polFbQuota', { usd: q }) : t('polFbYes'));
      note.textContent = t('policyNote', { byok: t('polByok.' + (pp.byok || 'allowed')), prov, fb });
    } else note.textContent = t('policyNoteNA');
    $('aiu-mine-unavail').classList.toggle('aiu-hide', S.credsState === 'ok');
    $('aiu-mine-unavail').textContent = t(S.credsState === 'error' ? 'mineError' : 'mineUnavail');
    const tb = $('aiu-mine-table');
    if (S.credsState !== 'ok') { tb.innerHTML = ''; $('aiu-add-btn').disabled = true; return; }
    const list = S.creds || [];
    const head = `<tr><th>${esc(t('thProv'))}</th><th>${esc(t('thCred'))}</th><th>${esc(t('model'))}</th><th>${esc(t('thStatus'))}</th><th></th></tr>`;
    const rows = list.map((c) => {
      const rot = S.rotating === c.id;
      return `<tr data-id="${esc(c.id)}"><td>${esc(PROV_NAME[c.provider] || c.provider)}${c.label ? ' <small>' + esc(c.label) + '</small>' : ''} ${c.is_default ? `<span class="aiu-tag b">${esc(t('default'))}</span>` : ''}</td>
        <td class="aiu-mono">${esc(c.key_hint || '••••')}</td><td class="aiu-mono">${esc(c.provider === 'azure_openai' ? (c.deployment || c.model || '—') : (c.model || '—'))}${c.region ? ' <small>' + esc(c.region) + '</small>' : ''}</td><td>${statusTag(c)}</td>
        <td><div class="aiu-actions"><button type="button" class="btn btn-ghost btn-sm" data-act="c-test" data-id="${esc(c.id)}">${esc(t('test'))}</button>
        <button type="button" class="btn btn-ghost btn-sm" data-act="c-rot" data-id="${esc(c.id)}">${esc(t('rotate'))}</button>
        ${!c.is_default && list.length > 1 ? `<button type="button" class="btn btn-ghost btn-sm" data-act="c-def" data-id="${esc(c.id)}">${esc(t('makeDefault'))}</button>` : ''}
        <button type="button" class="btn btn-ghost btn-sm aiu-danger" data-act="c-del" data-id="${esc(c.id)}">${esc(t('remove'))}</button></div></td></tr>` +
        (rot ? `<tr class="aiu-rot"><td colspan="5"><div class="aiu-row"><input id="aiu-rot-key" class="aiu-mono aiu-secret" type="password" autocomplete="new-password" autocapitalize="off" spellcheck="false" data-lpignore="true" data-1p-ignore placeholder="${esc(KEY_PLACEHOLDER[c.provider] || '')}" aria-label="${esc(t('key'))}" style="flex:1;min-width:0"><button type="button" class="btn btn-primary btn-sm" data-act="c-rot-go" data-id="${esc(c.id)}">${esc(t('rotateGo'))}</button><button type="button" class="btn btn-ghost btn-sm" data-act="c-rot-x">${esc(t('cancel'))}</button></div><div class="aiu-err" id="aiu-rot-err" role="alert"></div></td></tr>` : '');
    }).join('');
    tb.innerHTML = head + (rows || `<tr><td colspan="5">${esc(t('noKeys'))}</td></tr>`);
  }
  function setMineMsg(msg, bad) { const m = $('aiu-mine-msg'); m.textContent = msg || ''; m.style.color = bad ? 'var(--critical)' : ''; }
  async function loadCreds() {
    if (isViewer()) { S.credsState = 'forbidden'; renderMine(); return; }
    try {
      const r = await aiApi('/api/me/ai-credentials');
      if (r.ok && r.data) { S.creds = Array.isArray(r.data) ? r.data : (r.data.credentials || []); S.credsState = 'ok'; }
      else if (r.status === 403) S.credsState = 'forbidden';
      else S.credsState = 'error';
    } catch (e) { S.credsState = 'error'; }
    renderMine(); applyRole();
  }
  async function loadAdminTables() {
    if (!isAdmin()) return;
    try {
      const [k, u] = await Promise.all([aiApi('/api/ai/credentials'), aiApi('/api/ai/usage?scope=all&days=30')]);
      S.ukeys = k.ok && k.data ? (Array.isArray(k.data) ? k.data : (k.data.credentials || [])) : null;
      S.usage = u.ok && u.data ? (Array.isArray(u.data) ? u.data : (u.data.rows || [])) : null;
    } catch (e) { S.ukeys = null; S.usage = null; }
    renderAdminTables();
  }
  function renderAdminTables() {
    const uk = $('aiu-ukeys'), us = $('aiu-usage');
    const hk = `<tr><th>${esc(t('thUser'))}</th><th>${esc(t('thProv'))}</th><th>${esc(t('thCred'))}</th><th>${esc(t('thStatus'))}</th><th>${esc(t('lastUsed'))}</th><th>${esc(t('thCalls30'))}</th><th></th></tr>`;
    uk.innerHTML = S.ukeys == null ? `<tr><td>${esc(t('err.unavailable'))}</td></tr>` : hk + (S.ukeys.map((c) => `<tr><td>${esc((c.owner && (c.owner.email || c.owner.id)) || c.owner_user_id || '—')}</td><td>${esc(PROV_NAME[c.provider] || c.provider)}</td><td class="aiu-mono">${esc(c.key_hint || '••••')}</td><td>${statusTag(c)}</td><td>${esc(rel(c.last_used_at) || '—')}</td><td>${esc(c.calls_30d == null ? '—' : c.calls_30d)}</td><td>${c.status === 'revoked' || c.status === 'disabled' ? '' : `<button type="button" class="btn btn-ghost btn-sm aiu-danger" data-act="uk-revoke" data-id="${esc(c.id)}">${esc(t('revoke'))}</button>`}</td></tr>`).join('') || `<tr><td colspan="7">${esc(t('noKeys'))}</td></tr>`);
    const hu = `<tr><th>${esc(t('thUser'))}</th><th>${esc(t('thCred'))}</th><th>${esc(t('thCalls'))}</th><th>${esc(t('thCost'))}</th></tr>`;
    us.innerHTML = S.usage == null ? `<tr><td>${esc(t('err.unavailable'))}</td></tr>` : hu + (S.usage.map((u) => {
      const own = u.credential_scope === 'user' || u.scope === 'own';
      const who = u.user_email || u.user || (u.credential_scope === 'system' || u.scope === 'system' ? t('sched') : '—');
      const cost = u.est_cost_usd == null ? '—' : Number(u.est_cost_usd).toLocaleString(S.lang === 'vi' ? 'vi-VN' : 'en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 }) + ' USD';
      return `<tr><td>${esc(who)}</td><td><span class="aiu-tag ${own ? 'b' : ''}">${esc(own ? t('own') : t('org'))}</span> ${esc(PROV_NAME[u.provider] || u.provider || '')} ${esc(u.key_hint || '')}</td><td>${esc(u.calls == null ? '—' : u.calls)}</td><td>${esc(cost)}${u.quota_pct != null ? ` <span class="aiu-tag warn">${esc(u.quota_pct)}%</span>` : ''}</td></tr>`;
    }).join('') || `<tr><td colspan="4">—</td></tr>`);
  }
  function renderPolicyBits() { if (isAdmin() && (S.ukeys || S.usage)) renderAdminTables(); }

  /* ── Azure OpenAI: ánh xạ deployment → model thật (policy.azure_deployment_models, ADMIN) ── */
  const AZ_KEY = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
  function azMapObject() {
    const o = {};
    S.azMap.forEach((r) => { const a = String(r.res || '').trim().toLowerCase(), d = String(r.dep || '').trim().toLowerCase(), m = String(r.model || '').trim(); if (a && d && m) o[a + '/' + d] = m; });
    return o;
  }
  function renderAzMap() {
    const box = $('aiu-azmap'); if (!box) return;
    box.innerHTML = S.azMap.length ? S.azMap.map((r, i) => `<div class="aiu-row aiu-azrow" data-i="${i}" style="margin-bottom:6px">
      <input class="aiu-mono aiu-admin" data-az="res" value="${esc(r.res)}" placeholder="resource" aria-label="${esc(t('azResource'))}" style="width:30%">
      <input class="aiu-mono aiu-admin" data-az="dep" value="${esc(r.dep)}" placeholder="deployment" aria-label="${esc(t('azDeployment'))}" style="width:30%">
      <span>→</span><input class="aiu-mono aiu-admin" data-az="model" value="${esc(r.model)}" placeholder="gpt-4o" aria-label="${esc(t('model'))}" style="flex:1;min-width:0">
      <button type="button" class="btn btn-ghost btn-sm aiu-admin aiu-danger" data-act="az-del" data-i="${i}">${esc(t('remove'))}</button></div>`).join('')
      : `<div class="aiu-hint">${esc(t('azMapNone'))}</div>`;
    $$('#aiu-azmap input, #aiu-azmap button').forEach((e) => { e.disabled = !isAdmin(); });
  }

  /* ───────── validation ───────── */
  const URL_RE = /^https?:\/\/[^\s/@?#]+(:\d+)?(\/.*)?$/i;
  function validate() {
    let ok = true;
    const err = (id, msg) => { const e = $(id); if (e) e.textContent = msg || ''; if (msg) ok = false; };
    ['aiu-ol-url-err', 'aiu-h-err', 'aiu-openai-baseerr', 'aiu-openai_compatible-baseerr', 'aiu-azure_openai-endpointerr'].forEach((i) => err(i, ''));
    ORG_PROVIDERS.forEach((p) => err('aiu-' + p + '-keyerr', ''));
    const u = val('aiu-ol-url').trim();
    if (u && !URL_RE.test(u)) err('aiu-ol-url-err', t('errUrl'));
    const ob = val('aiu-openai-base').trim();
    if (ob && !URL_RE.test(ob)) err('aiu-openai-baseerr', t('errUrl'));
    const oc = val('aiu-openai_compatible-base').trim();
    if (oc && !URL_RE.test(oc)) err('aiu-openai_compatible-baseerr', t('errUrl'));
    const ae = val('aiu-azure_openai-endpoint').trim();
    if (ae && !/^https:\/\/[a-z0-9-]+\.(openai\.azure\.com|cognitiveservices\.azure\.com)\/?$/i.test(ae)) err('aiu-azure_openai-endpointerr', t('errAzEndpoint'));
    if (S.sel === 'hybrid') {
      const lo = parseInt(val('aiu-h-lo'), 10), hi = parseInt(val('aiu-h-hi'), 10);
      if (isNaN(lo) || isNaN(hi) || lo < 0 || hi > 100 || lo > hi) err('aiu-h-err', t('errBand'));
    }
    if (S.sel !== 'local_only') {
      const p = S.prov; const sec = sectionData(p); const typed = !!val('aiu-' + p + '-key');
      if (needsKey(p) && !typed && !sec.api_key_set) err('aiu-' + p + '-keyerr', t('errKeyNeeded'));
    }
    const bad = S.azMap.some((r) => (r.res || r.dep || r.model) && !(AZ_KEY.test(String(r.res).trim().toLowerCase()) && /^[a-z0-9][a-z0-9._-]{0,63}$/.test(String(r.dep).trim().toLowerCase()) && String(r.model).trim()));
    if (bad) { ok = false; toast(t('errAzMap'), 'warn'); }
    return ok;
  }

  /* ───────── payload ───────── */
  const trimmed = (id) => val(id).trim();
  const orUndef = (id) => trimmed(id) || undefined;
  // giá trị của MỘT provider (dùng cho PUT và POST /api/ai/test); key chỉ đưa vào khi có gõ
  function providerSection(p) {
    const o = {
      anthropic: () => ({ auth_mode: val('aiu-anthropic-auth'), model: orUndef('aiu-anthropic-model'),
        wif: { federation_rule_id: trimmed('aiu-wif-rule'), organization_id: trimmed('aiu-wif-org'), identity_token_file: trimmed('aiu-wif-token'), workspace_id: trimmed('aiu-wif-ws'), service_account_id: trimmed('aiu-wif-sa') } }),
      bedrock: () => ({ auth_mode: val('aiu-bedrock-auth'), region: trimmed('aiu-bedrock-region'), aws_profile: trimmed('aiu-bedrock-profile'), model: orUndef('aiu-bedrock-model') }),
      openai: () => ({ model: orUndef('aiu-openai-model'), base_url: trimmed('aiu-openai-base') }),
      openrouter: () => ({ model: orUndef('aiu-openrouter-model') }),
      azure_openai: () => ({ auth_mode: val('aiu-azure_openai-auth'), endpoint: trimmed('aiu-azure_openai-endpoint'), deployment: trimmed('aiu-azure_openai-deployment'),
        api_version: orUndef('aiu-azure_openai-version'), tenant_id: trimmed('aiu-azure_openai-tenant'), client_id: trimmed('aiu-azure_openai-client') }),
      gemini: () => ({ model: orUndef('aiu-gemini-model') }),
      vertex: () => ({ project: trimmed('aiu-vertex-project'), location: orUndef('aiu-vertex-location'), model: orUndef('aiu-vertex-model') }),
      openai_compatible: () => ({ base_url: trimmed('aiu-openai_compatible-base'), model: trimmed('aiu-openai_compatible-model') }),
    }[p]();
    return o;
  }
  function secretOf(p) { const k = val('aiu-' + p + '-key'); return p === 'vertex' ? k.trim() : k.trim(); }
  function buildPayload() {
    const lo = parseInt(val('aiu-h-lo'), 10), hi = parseInt(val('aiu-h-hi'), 10);
    const pl = {
      mode: S.sel, provider: S.prov,
      hybrid: { escalate_min_severity: val('aiu-h-sev'), fp_band_low: isNaN(lo) ? 0 : lo, fp_band_high: isNaN(hi) ? 100 : hi, tasks: { coworker: val('aiu-route-cw') } },   // plan §4.11 A1
      privacy: { send_code_context: $('aiu-pv-send').checked, context_lines: Math.max(0, parseInt(val('aiu-pv-lines'), 10) || 0), redact_secrets: true },
      ollama: { url: trimmed('aiu-ol-url'), model: val('aiu-ol-model'), vision_model: val('aiu-ol-vision') },
    };
    ORG_PROVIDERS.forEach((p) => { pl[p] = providerSection(p); const k = secretOf(p); if (k) pl[p].api_key = k; });   // write-only: chỉ gửi khi gõ key mới
    if (isAdmin()) {
      const usd = trimmed('aiu-p-usd'), rpm = trimmed('aiu-p-rpm');
      pl.policy = {
        byok: val('aiu-p-byok'), fallback_to_org: val('aiu-p-fallback') === '1',
        allowed: val('aiu-p-allowed').split(',').map((x) => x.trim()).filter(Boolean),
        org_quota: { usd_per_user_month: usd === '' ? null : Number(usd), rpm_per_user: rpm === '' ? null : Number(rpm) },
        scheduled_jobs_credential: val('aiu-p-sched'), custom_base_url: val('aiu-p-baseurl'),
        azure_deployment_models: azMapObject(),          // REPLACE (xoá mục = bỏ khỏi object)
      };
    }
    return pl;
  }
  // Body của POST /api/ai/test: giá trị CHƯA LƯU của provider đang chọn (trường lạ bị server coi là "đổi nơi gửi khoá")
  function buildTestBody() {
    const p = S.prov; const b = { provider: p };
    const sec = providerSection(p);
    ['model', 'base_url', 'auth_mode', 'region', 'aws_profile', 'endpoint', 'deployment', 'api_version', 'tenant_id', 'client_id', 'project', 'location'].forEach((k) => {
      if (typeof sec[k] === 'string' && sec[k] !== '') b[k] = sec[k];
    });
    const k = secretOf(p); if (k) b.api_key = k;
    return b;
  }

  /* ───────── actions ───────── */
  async function load(force) {
    if (S.loading) return S.loading;
    if (S.inited && !force && S.data) { applyRole(); return; }
    S.loading = (async () => {
      const errBox = $('aiu-loaderr'); errBox.classList.add('aiu-hide'); $('st-ai').dataset.busy = '1';
      try {
        if (!S.dict.vi || !Object.keys(S.dict.vi).length) await loadDict('vi');
        if (S.lang === 'en') await loadDict('en');
        applyLang();
        S.data = await fetchSettings();
        S.inited = true;
        fill();
        loadCreds(); loadAdminTables();
      } catch (e) {
        errBox.classList.remove('aiu-hide'); errBox.textContent = t('loadErr');
      } finally { S.loading = null; delete $('st-ai').dataset.busy; }
    })();
    return S.loading;
  }
  async function save() {
    if (S.saving || !isAdmin()) return;
    if (!validate()) { toast(t('errFix'), 'warn'); return; }
    S.saving = true; $('aiu-save').disabled = true;
    let res;
    try {
      const pr = aiApi('/api/ai/settings', { method: 'PUT', body: buildPayload() }).then((r) => (r.ok ? { ok: true } : { ok: false, msg: errText(r) }));
      clearSecrets();     // key đã nằm trong body request → xoá khỏi DOM ngay, trước khi chờ phản hồi
      res = await pr;
    } catch (e) { res = { ok: false, msg: t('err.network') }; }
    S.saving = false;
    if (res.ok) { toast(t('saved'), 'success'); S.lastTest = null; await load(true); }
    else { toast(t('saveFail', { m: res.msg }), 'error'); updateDirty(); }
  }
  function discard() { if (S.data) { fill(); $('aiu-cloud-res').classList.add('aiu-hide'); } }

  function showRes(el, kind, text) { el.className = 'aiu-res ' + kind; el.textContent = text; }
  async function testCloud() {
    const el = $('aiu-cloud-res'); const btn = $('aiu-cloud-test');
    btn.disabled = true; showRes(el, 'warn', t('testing'));
    const prov = S.prov;
    try {
      const r = await aiApi('/api/ai/test', { method: 'POST', body: buildTestBody() });     // giá trị CHƯA LƯU; key chỉ đi trong body (ô nhập giữ nguyên để còn Lưu)
      const d = r.data || {};
      if (r.ok && d.ok) {
        const bits = [(PROV_NAME[d.provider] || d.provider || ''), d.model, d.latency_ms != null ? d.latency_ms + ' ms' : null, d.json === true ? 'JSON ✓' : d.json === false ? 'JSON ✗' : null, d.tools === true ? 'tools ✓' : d.tools === false ? 'tools ✗' : null].filter(Boolean);
        showRes(el, d.tools === false ? 'warn' : 'ok', '✓ ' + bits.join(' · '));
        S.lastTest = { prov, at: new Date().toISOString(), ok: true };
      } else {
        showRes(el, 'err', '✗ ' + errText({ status: r.status, data: d }));
        S.lastTest = { prov, at: new Date().toISOString(), ok: false };
      }
    } catch (e) { showRes(el, 'err', '✗ ' + t('err.network')); }
    btn.disabled = !isAdmin(); renderStatus();
  }
  async function testOllama() {
    const btn = $('aiu-ol-test'); const url = val('aiu-ol-url').trim();
    $('aiu-ol-url-err').textContent = '';
    if (url && !URL_RE.test(url)) { $('aiu-ol-url-err').textContent = t('errUrl'); return; }
    btn.disabled = true; $('aiu-ol-checks').innerHTML = checkItem('q', t('testing'));
    try {
      const r = await aiApi('/api/ai/ollama/check', { method: 'POST', body: { url: url || undefined, model: val('aiu-ol-model') || undefined, force: true } });
      S.olCheck = r.ok && r.data ? r.data : { ok: false, code: (r.data && (r.data.code || (r.data.detail && r.data.detail.code))) || (r.status === 429 ? 'RATE_LIMITED' : 'NETWORK') };
    } catch (e) { S.olCheck = { ok: false, code: 'NETWORK' }; }
    if (S.data && S.olCheck && S.olCheck.ok) {      // tag tools ✓/✗ cho model vừa kiểm
      const st = S.data.status.ollama;
      if (S.olCheck.model === st.model) { st.tools = S.olCheck.tools === true; if (S.olCheck.latency_ms != null) st.latency_ms = S.olCheck.latency_ms; }
      (S.data.ollama.installed || []).forEach((m) => { if (m.name === S.olCheck.model) m.tools = S.olCheck.tools === true; });
      fillOllamaSelects(val('aiu-ol-model'), val('aiu-ol-vision')); renderInstalled(); renderStatus();
    }
    renderChecks(); btn.disabled = !isAdmin();
  }
  async function loadModels(p) {
    const note = $('aiu-' + p + '-modelnote'); note.textContent = t('loadingModels');
    try {
      const r = await aiApi('/api/ai/models?provider=' + encodeURIComponent(p));
      if (!r.ok) { note.textContent = errText(r); return; }
      const list = (r.data && r.data.models) || [];
      $('aiu-' + p + '-dl').innerHTML = list.map((m) => `<option value="${esc(typeof m === 'string' ? m : (m && m.id) || '')}"></option>`).join('');
      note.textContent = t(r.data && r.data.source === 'api' ? 'modelsApi' : 'modelsStatic', { n: list.length });
      $('aiu-' + p + '-model').focus();
    } catch (e) { note.textContent = t('err.network'); }
  }
  async function pull() {
    const name = val('aiu-pull-name').trim(); if (!name || !isAdmin()) return;
    const prog = $('aiu-pull-prog'), txt = $('aiu-pull-text'), fill_ = $('aiu-pull-fill');
    prog.classList.remove('aiu-hide'); fill_.style.width = '5%'; txt.textContent = t('pulling', { m: name });
    S.pullAbort = new AbortController();
    try {
      const resp = await fetch('/api/ollama/pull', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ model: name }), signal: S.pullAbort.signal });
      if (typeof check401 === 'function') check401(resp);
      if (!resp.ok) { txt.textContent = errText({ status: resp.status }); return; }
      const reader = resp.body.getReader(); const dec = new TextDecoder(); let failed = false;
      for (;;) {
        const { done, value } = await reader.read(); if (done) break;
        for (const line of dec.decode(value).split('\n').filter((l) => l.trim())) {
          let d; try { d = JSON.parse(line); } catch (e) { continue; }
          if (d.error) { failed = true; txt.textContent = t('pullFail'); fill_.style.width = '0%'; }
          else if (d.total) { const pct = Math.round(100 * (d.completed || 0) / d.total); fill_.style.width = pct + '%'; txt.textContent = (d.status || '') + ' — ' + pct + '%'; }
          else txt.textContent = d.status || '';
        }
      }
      if (!failed) { txt.textContent = t('pullOk', { m: name }); fill_.style.width = '100%'; }
    } catch (e) { if (e.name !== 'AbortError') txt.textContent = t('err.network'); }
    S.pullAbort = null; await refreshOllama();
  }
  async function refreshOllama() {
    try { const d = await fetchSettings(); S.data.ollama = d.ollama; S.data.status = d.status; fillOllamaSelects(); renderInstalled(); renderStatus(); S.base = Object.assign(S.base || {}, { 'ollama.model': val('aiu-ol-model'), 'ollama.vision_model': val('aiu-ol-vision') }); updateDirty(); } catch (e) { /* giữ nguyên */ }
  }
  async function deleteModel(name) {
    if (!isAdmin() || !confirm(t('delConfirm', { m: name }))) return;
    const r = await aiApi('/api/ollama/models/' + encodeURIComponent(name), { method: 'DELETE' });
    if (!r.ok) toast(errText(r), 'error'); await refreshOllama();
  }
  async function removeOrgKey(p) {
    if (!isAdmin() || !confirm(t('keyDelConfirm', { p: PROV_NAME[p] }))) return;
    const r = await aiApi('/api/ai/settings', { method: 'PUT', body: { [p]: { clear_api_key: true } } });
    if (r.ok) { toast(t('keyRemoved'), 'success'); await load(true); } else toast(errText(r), 'error');
  }

  /* ── my keys actions ── */
  function openAdd(show) {
    const f = $('aiu-add'); f.classList.toggle('aiu-hide', !show);
    if (show) {
      const allowed = allowedUserProviders();
      $('aiu-add-prov').innerHTML = allowed.map((p) => `<option value="${p}">${esc(PROV_NAME[p])}</option>`).join('');
      onAddProv(); $('aiu-add-err').textContent = ''; $('aiu-add-key').focus();
    } else { clearSecrets(); $('aiu-add-err').textContent = ''; }
  }
  function onAddProv() {
    const p = val('aiu-add-prov');
    $('aiu-add-key').placeholder = KEY_PLACEHOLDER[p] || '';
    const az = p === 'azure_openai';
    $('aiu-add-region-wrap').classList.toggle('aiu-hide', p !== 'bedrock');
    ['aiu-add-az-wrap', 'aiu-add-dep-wrap', 'aiu-add-ver-wrap'].forEach((id) => $(id).classList.toggle('aiu-hide', !az));
    $('aiu-add-model-wrap').classList.toggle('aiu-hide', az);       // Azure: tên deployment thay cho model
    $('aiu-add-models').innerHTML = (MODEL_SUGGEST[p] || []).map((m) => `<option value="${esc(m)}"></option>`).join('');
    $('aiu-add-model').value = (MODEL_SUGGEST[p] || [''])[0] || '';
  }
  async function addKey() {
    const err = $('aiu-add-err'); err.textContent = '';
    const p = val('aiu-add-prov'); const k = val('aiu-add-key').trim();
    if (!k) { err.textContent = t('errKeyNeeded'); return; }
    if (/^sk-ant-oat/i.test(k)) { err.textContent = t('errOauth'); $('aiu-add-key').value = ''; return; }   // token subscription OAuth: không nhận
    const body = { provider: p, model: val('aiu-add-model').trim() || undefined, label: val('aiu-add-label').trim() || undefined, secret: k, is_default: !(S.creds || []).length };
    if (p === 'bedrock') body.region = val('aiu-add-region').trim();
    if (p === 'azure_openai') {
      body.model = undefined; body.resource = val('aiu-add-resource').trim().toLowerCase(); body.deployment = val('aiu-add-deployment').trim(); body.api_version = val('aiu-add-version').trim() || undefined;
      if (!body.resource || !body.deployment) { err.textContent = t('errAzNeeded'); return; }
    }
    const btn = $('aiu-add-go'); btn.disabled = true;
    let r;
    try { const pr = aiApi('/api/me/ai-credentials', { method: 'POST', body }); clearSecrets(); r = await pr; }
    catch (e) { r = { ok: false, status: 0 }; }
    btn.disabled = false;
    if (r.ok) { openAdd(false); $('aiu-add-label').value = ''; setMineMsg(t('keyAdded')); await loadCreds(); await refreshMe(); }
    else err.textContent = (r.status === 0 ? t('err.network') : errText(r)) + ' ' + t('reenter');
  }
  async function credAct(act, id) {
    if (act === 'c-rot') { S.rotating = S.rotating === id ? null : id; renderMine(); const k = $('aiu-rot-key'); if (k) k.focus(); return; }
    if (act === 'c-rot-x') { S.rotating = null; clearSecrets(); renderMine(); return; }
    if (act === 'c-rot-go') {
      const inp = $('aiu-rot-key'); const k = inp ? inp.value.trim() : ''; const e = $('aiu-rot-err');
      if (!k) { e.textContent = t('errKeyNeeded'); return; }
      if (/^sk-ant-oat/i.test(k)) { e.textContent = t('errOauth'); inp.value = ''; return; }
      let r; try { const pr = aiApi('/api/me/ai-credentials/' + encodeURIComponent(id) + '/secret', { method: 'PUT', body: { secret: k } }); clearSecrets(); r = await pr; } catch (x) { r = { ok: false, status: 0 }; }
      if (r.ok) { S.rotating = null; setMineMsg(t('keyRotated')); await loadCreds(); await refreshMe(); }
      else { const e2 = $('aiu-rot-err'); if (e2) e2.textContent = (r.status === 0 ? t('err.network') : errText(r)) + ' ' + t('reenter'); }
      return;
    }
    if (act === 'c-test') {
      setMineMsg(t('testing'));
      try { const r = await aiApi('/api/me/ai-credentials/' + encodeURIComponent(id) + '/test', { method: 'POST' }); const d = r.data || {};
        if (r.ok && d.ok) setMineMsg('✓ ' + [d.model, d.latency_ms != null ? d.latency_ms + ' ms' : null, d.tools === true ? 'tools ✓' : null].filter(Boolean).join(' · '));
        else setMineMsg('✗ ' + errText({ status: r.status, data: d }), true);
      } catch (e) { setMineMsg('✗ ' + t('err.network'), true); }
      await loadCreds(); await refreshMe(); return;
    }
    if (act === 'c-def') { const r = await aiApi('/api/me/ai-credentials/' + encodeURIComponent(id), { method: 'PATCH', body: { is_default: true } }); if (!r.ok) setMineMsg(errText(r), true); await loadCreds(); await refreshMe(); return; }
    if (act === 'c-del') {
      if (!confirm(t('keyDelOwnConfirm'))) return;
      const r = await aiApi('/api/me/ai-credentials/' + encodeURIComponent(id), { method: 'DELETE' });
      if (!r.ok) setMineMsg(errText(r), true); else setMineMsg(t('keyRemoved'));
      await loadCreds(); await refreshMe();
    }
  }
  async function refreshMe() {   // cập nhật pill "Khoá của bạn" sau khi đổi khoá
    try { const r = await aiApi('/api/ai/settings'); if (r.ok && r.data && r.data.status) { S.data.status = Object.assign({}, S.data.status, { mine: r.data.status.mine, cloud: r.data.status.cloud }); renderStatus(); } } catch (e) { /* giữ */ }
  }
  async function revokeUserKey(id) {
    if (!isAdmin() || !confirm(t('revokeConfirm'))) return;
    const r = await aiApi('/api/ai/credentials/' + encodeURIComponent(id) + '/revoke', { method: 'POST' });
    if (!r.ok) toast(errText(r), 'error'); else toast(t('revoked'), 'success');
    loadAdminTables();
  }

  /* ───────── events ───────── */
  function bind() {
    const root = $('st-ai');
    $('aiu-lang').addEventListener('click', (e) => { const b = e.target.closest('button'); if (b) setLang(b.dataset.v); });
    $('aiu-modes').addEventListener('click', (e) => { const b = e.target.closest('.aiu-mode'); if (!b || b.disabled) return; S.sel = b.dataset.mode; renderModes(); renderVisibility(); renderStatus(); updatePrivacyWarn(); updateDirty(); });
    $('aiu-prov').addEventListener('click', (e) => { const b = e.target.closest('button[data-prov]'); if (!b || b.disabled) return; S.prov = b.dataset.prov; $('aiu-cloud-res').classList.add('aiu-hide'); renderProviders(); updatePrivacyWarn(); updateDirty(); });
    root.addEventListener('input', (e) => {
      if (e.target.closest('#aiu-add,#aiu-mine-table')) return;
      if (e.target.id === 'aiu-anthropic-auth' || e.target.id === 'aiu-bedrock-auth' || e.target.id === 'aiu-azure_openai-auth') renderProviders();
      if (e.target.id === 'aiu-pv-send') updatePrivacyWarn();
      updateDirty();
    });
    root.addEventListener('change', (e) => { if (e.target.id === 'aiu-anthropic-auth' || e.target.id === 'aiu-bedrock-auth' || e.target.id === 'aiu-azure_openai-auth') renderProviders(); if (e.target.id === 'aiu-add-prov') onAddProv(); updateDirty(); });
    root.addEventListener('click', (e) => {
      const a = e.target.closest('[data-act]'); if (!a) return;
      const act = a.dataset.act;
      if (act === 'models') { e.preventDefault(); loadModels(a.dataset.p); }
      else if (act === 'key-replace') { const k = $('aiu-' + a.dataset.p + '-key'); k.disabled = false; k.focus(); }
      else if (act === 'key-remove') removeOrgKey(a.dataset.p);
      else if (act === 'ol-del') deleteModel(a.dataset.name);
      else if (act === 'uk-revoke') revokeUserKey(a.dataset.id);
      else if (act.startsWith('c-')) credAct(act, a.dataset.id);
    });
    $('aiu-azmap-add').addEventListener('click', () => { S.azMap.push({ res: '', dep: '', model: '' }); renderAzMap(); updateDirty(); const rows = $$('#aiu-azmap .aiu-azrow'); const l = rows[rows.length - 1]; if (l) l.querySelector('input').focus(); });
    $('aiu-azmap').addEventListener('input', (e) => { const row = e.target.closest('.aiu-azrow'); if (!row || !e.target.dataset.az) return; S.azMap[+row.dataset.i][e.target.dataset.az] = e.target.value; updateDirty(); });
    $('aiu-azmap').addEventListener('click', (e) => { const b = e.target.closest('[data-act="az-del"]'); if (!b) return; S.azMap.splice(+b.dataset.i, 1); renderAzMap(); updateDirty(); });
    $('aiu-cloud-test').addEventListener('click', testCloud);
    $('aiu-ol-test').addEventListener('click', testOllama);
    $('aiu-pull-btn').addEventListener('click', pull);
    $('aiu-save').addEventListener('click', save);
    $('aiu-discard').addEventListener('click', discard);
    $('aiu-add-btn').addEventListener('click', () => openAdd($('aiu-add').classList.contains('aiu-hide')));
    $('aiu-add-cancel').addEventListener('click', () => openAdd(false));
    $('aiu-add-go').addEventListener('click', addKey);
    window.addEventListener('hashchange', handleHash);
  }

  /* ───────── deep links (#st-ollama → #ollama, #st-ai → #mode …) ───────── */
  function handleHash() {
    const hit = HASH_MAP[location.hash]; if (!hit) return;
    try { if (!$('page-settings').classList.contains('active')) navigate('settings'); } catch (e) { return; }
    const tab = $('st-tab-ai'); if (tab && typeof switchTab === 'function') switchTab(tab, 'st-ai');
    if (location.hash !== hit[1]) history.replaceState(null, '', hit[1]);
    load(false).then(() => { const el = $(hit[0]); if (el) el.scrollIntoView({ block: 'start' }); });
  }

  /* ───────── entry ───────── */
  function init() {
    if (!$('st-ai')) return;
    S.lang = pickLang();
    renderBlocks(); bind();
    loadDict('vi').then(() => (S.lang === 'en' ? loadDict('en') : null)).then(() => { applyLang(); handleHash(); });
  }
  window.aiSettingsLoad = function () { return load(false).then(() => { if (S.data) { applyRole(); renderBanners(); } }); };
  window.aiSettingsRoleChanged = function () { if (S.data) { renderAll(); loadCreds(); loadAdminTables(); } };
  init();
})();
