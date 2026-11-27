/* Settings › AI — trang hợp nhất (PR-5, refs #109).
 *
 * Nói chuyện với API theo hợp đồng §6 của AI-Settings-Plan (docs/ai-settings-web-contract.md).
 * Backend khoá-theo-người (PR-1..PR-4) chưa merge, nên có 2 chế độ, tự dò bằng GET /api/ai/settings:
 *   • "contract" — backend có /api/ai/settings → dùng đầy đủ §6 (các tab cũ ẩn).
 *   • "bridge"   — 404 → ghép mục 1–3 từ endpoint HIỆN CÓ (/api/ai/config, /api/ollama/*); mục 4/5, kiểm tra
 *                  giá trị chưa lưu, tool-calling check… hiển thị "chưa khả dụng" (KHÔNG giả thành công) và 2 tab
 *                  cũ vẫn truy cập được (cờ body.ai-legacy-on). Khi PR-3 land, trang tự chuyển sang "contract".
 * Bí mật: ô key là type=password, đọc vào body request tại thời điểm gửi, xoá ô ngay sau khi gửi; không giữ trong
 * biến/State, không localStorage, không in ra toast/lỗi (lỗi đi qua maskSecrets + mã chuẩn hoá).
 */
(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
  const val = (id) => { const e = $(id); return e ? e.value : ''; };
  const setVal = (id, v) => { const e = $(id); if (e) e.value = (v === null || v === undefined) ? '' : v; };
  const esc = (s) => (typeof escHtml === 'function' ? escHtml(String(s)) : String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])));

  const PROVIDERS = [
    { id: 'anthropic', name: 'Anthropic', sub: 'API key · WIF', legacy: true },
    { id: 'bedrock', name: 'Amazon Bedrock', sub: 'IAM role · SSO profile · API key', legacy: true },
    { id: 'openai', name: 'OpenAI', sub: 'API key', legacy: true },
    { id: 'azure_openai', name: 'Azure OpenAI', sub: 'Key · Entra ID', legacy: false },
    { id: 'gemini', name: 'Google Gemini / Vertex', sub: 'API key · SA', legacy: false },
    { id: 'openrouter', name: 'OpenRouter', sub: 'API key', legacy: true },
  ];
  const PROV_NAME = { anthropic: 'Anthropic', bedrock: 'Amazon Bedrock', openai: 'OpenAI', azure_openai: 'Azure OpenAI', gemini: 'Gemini', vertex: 'Vertex AI', openrouter: 'OpenRouter', openai_compatible: 'OpenAI-compatible' };
  const USER_PROVIDERS = ['anthropic', 'bedrock', 'openai', 'openrouter'];   // D4: user không đặt base_url → chỉ provider host cố định
  const KEY_PLACEHOLDER = { anthropic: 'sk-ant-…', bedrock: 'ABSK…', openai: 'sk-…', openrouter: 'sk-or-…' };
  const MODEL_SUGGEST = {
    anthropic: ['claude-opus-5-5', 'claude-sonnet-5-5', 'claude-haiku-5-5'],
    bedrock: ['us.anthropic.claude-sonnet-5-5', 'anthropic.claude-opus-5-5'],
    openai: ['gpt-4o'],
    openrouter: ['anthropic/claude-3.5-sonnet'],
  };
  const SEV_RANK = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
  const SECTION_OF = (k) => (k === 'mode' ? '1' : k.startsWith('ollama.') ? '2' : k.startsWith('hybrid.') ? '2b' : k.startsWith('policy.') ? '5' : '3');
  const HASH_MAP = {
    '#st-ollama': ['aiu-sec-ollama', '#ollama'], '#ollama': ['aiu-sec-ollama', '#ollama'],
    '#st-ai': ['aiu-sec-mode', '#mode'], '#mode': ['aiu-sec-mode', '#mode'],
    '#hybrid': ['aiu-sec-hybrid', '#hybrid'], '#cloud': ['aiu-sec-cloud', '#cloud'],
    '#my-keys': ['aiu-sec-mine', '#my-keys'], '#policy': ['aiu-sec-policy', '#policy'],
  };

  const S = {
    lang: 'vi', dict: { vi: {}, en: {} },
    mode: 'unknown',        // unknown | contract | bridge
    data: null, base: null,
    sel: 'local_only', prov: 'anthropic',
    olCheck: null,
    creds: null, credsState: 'idle',   // idle | ok | unavailable | forbidden | error
    ukeys: null, usage: null,
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
    await loadDict(l); applyLang();
    if (S.data) { fillOllamaSelects(val('aiu-ol-model'), val('aiu-ol-vision')); renderAll(); updateDirty(); }
  }

  /* ───────── helpers ───────── */
  const role = () => (typeof currentUser !== 'undefined' && currentUser && currentUser.role) || 'ADMIN';   // auth tắt → như canAdmin()
  const isAdmin = () => role() === 'ADMIN';
  const isViewer = () => role() === 'VIEWER';
  const SECRET_RE = /(sk-[A-Za-z0-9_-]{6,}|ABSK[A-Za-z0-9+/=_-]{6,}|ksk_[\w-]{6,}|AIza[\w-]{10,}|gh[pous]_\w{10,}|github_pat_\w+|Bearer\s+\S+|api[-_ ]?key[=: ]+\S+)/gi;
  const maskSecrets = (s) => String(s == null ? '' : s).replace(SECRET_RE, '••••').slice(0, 240);

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
  function errText(r) {
    if (!r) return t('err.generic');
    const code = r.data && (r.data.code || (r.data.detail && r.data.detail.code));
    if (code && S.dict.vi['code.' + code] !== undefined) return t('code.' + code);
    if (r.status === 403) return t('err.forbidden');
    if (r.status === 404 || r.status === 405 || r.status === 501) return t('err.unavailable');
    if (r.status === 429) return t('err.throttled');
    if (r.status === 422 && r.data && typeof r.data.detail === 'string') return maskSecrets(r.data.detail);
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
  function keyGroup(p) {
    return `<div class="aiu-f" id="aiu-${p}-keywrap"><label for="aiu-${p}-key" data-i18n="key"></label>
      <div class="aiu-row"><input id="aiu-${p}-key" class="aiu-mono aiu-secret aiu-admin" type="password" autocomplete="new-password" autocapitalize="off" spellcheck="false" data-lpignore="true" data-1p-ignore data-testid="aiu-${p}-key" style="flex:1;min-width:0">
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
    };
    $('aiu-prov-blocks').innerHTML = USER_PROVIDERS.map((p) => `<div class="aiu-prov-block" data-p="${p}">${H[p]}</div>`).join('');
    $('aiu-add-prov').innerHTML = USER_PROVIDERS.map((p) => `<option value="${p}">${esc(PROV_NAME[p])}</option>`).join('');
  }

  /* ───────── data ───────── */
  async function fetchBridge() {
    const [cfg, ep, models, vis, health] = await Promise.all([
      aiApi('/api/ai/config'), aiApi('/api/ollama/endpoint'), aiApi('/api/ollama/models'),
      aiApi('/api/ollama/vision-model'), aiApi('/api/ollama/health'),
    ]);
    if (!cfg.ok || !cfg.data) throw new Error('config');
    const d = JSON.parse(JSON.stringify(cfg.data));
    const installed = ((models.data && models.data.models) || []).map((m) => ({ name: m.name, size_gb: m.size_gb, tools: null }));
    d.ollama = {
      url: (ep.data && ep.data.url) || '', custom: !!(ep.data && ep.data.custom), default_url: (ep.data && ep.data.default) || '',
      model: (models.data && models.data.active_model) || (health.data && health.data.active_model) || '',
      vision_model: (vis.data && vis.data.vision_model) || '', installed, reachable: !!models.ok, latency_ms: null, version: null, check: null,
    };
    const sec = d[d.provider] || {};
    const keyless = (d.provider === 'anthropic' && sec.auth_mode !== 'api_key') || (d.provider === 'bedrock' && sec.auth_mode !== 'bedrock_api_key');
    d.status = {
      ollama: { reachable: d.ollama.reachable, latency_ms: null, model: d.ollama.model, tools: null },
      cloud: { provider: d.provider, configured: !!(sec.api_key_set || keyless), last_test_at: null, last_test_ok: null },
      mine: null,
    };
    return d;
  }
  async function fetchSettings() {
    const r = await aiApi('/api/ai/settings');
    if (r.ok && r.data && typeof r.data === 'object' && r.data.mode) { S.mode = 'contract'; return r.data; }
    if (r.status === 404 || r.status === 405 || r.status === 501 || (r.ok && !(r.data && r.data.mode))) { S.mode = 'bridge'; return fetchBridge(); }
    const e = new Error('settings'); e.status = r.status; throw e;
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
    setVal('aiu-anthropic-auth', a.auth_mode || 'api_key'); setVal('aiu-anthropic-model', a.model);
    const w = a.wif || {};
    setVal('aiu-wif-rule', w.federation_rule_id); setVal('aiu-wif-org', w.organization_id); setVal('aiu-wif-token', w.identity_token_file); setVal('aiu-wif-ws', w.workspace_id); setVal('aiu-wif-sa', w.service_account_id);
    setVal('aiu-bedrock-auth', b.auth_mode || 'aws_chain'); setVal('aiu-bedrock-region', b.region); setVal('aiu-bedrock-profile', b.aws_profile); setVal('aiu-bedrock-model', b.model);
    setVal('aiu-openai-model', oa.model); setVal('aiu-openai-base', oa.base_url);
    setVal('aiu-openrouter-model', orr.model);
    clearSecrets();
    const pv = d.privacy || {};
    $('aiu-pv-send').checked = !!pv.send_code_context; setVal('aiu-pv-lines', pv.context_lines);
    const pm = (d.advanced && d.advanced.pentest_models) || {};
    setVal('aiu-pt-planner', pm.planner); setVal('aiu-pt-executor', pm.executor); setVal('aiu-pt-summarizer', pm.summarizer);
    const p = d.policy || {};
    setVal('aiu-p-byok', p.byok || 'allowed'); setVal('aiu-p-fallback', p.fallback_to_org === false ? '0' : '1');
    setVal('aiu-p-allowed', (p.allowed || []).join(', '));
    const q = p.org_quota || {};
    setVal('aiu-p-usd', q.usd_per_user_month == null ? '' : q.usd_per_user_month); setVal('aiu-p-rpm', q.rpm_per_user == null ? '' : q.rpm_per_user);
    setVal('aiu-p-sched', p.scheduled_jobs_credential || 'org'); setVal('aiu-p-baseurl', p.custom_base_url || 'admin_only');
    S.olCheck = o.check || null;
    renderAll();
    S.base = formState();
    updateDirty();
  }

  /* ───────── form state / dirty ───────── */
  function formState() {
    const f = {};
    f.mode = S.sel;
    f['ollama.url'] = val('aiu-ol-url').trim(); f['ollama.model'] = val('aiu-ol-model'); f['ollama.vision_model'] = val('aiu-ol-vision');
    f['hybrid.sev'] = val('aiu-h-sev'); f['hybrid.lo'] = val('aiu-h-lo'); f['hybrid.hi'] = val('aiu-h-hi');
    f['cloud.provider'] = S.prov;
    ['anthropic-auth', 'anthropic-model', 'bedrock-auth', 'bedrock-region', 'bedrock-profile', 'bedrock-model', 'openai-model', 'openai-base', 'openrouter-model',
      'wif-rule', 'wif-org', 'wif-token', 'wif-ws', 'wif-sa', 'pt-planner', 'pt-executor', 'pt-summarizer', 'pv-lines'].forEach((k) => { f['cloud.' + k] = val('aiu-' + k); });
    f['cloud.pv-send'] = $('aiu-pv-send').checked;
    USER_PROVIDERS.forEach((p) => { f['cloud.key.' + p] = val('aiu-' + p + '-key') ? 'typed' : ''; });   // KHÔNG lưu giá trị key
    if (isAdmin() && S.mode === 'contract') ['byok', 'fallback', 'allowed', 'usd', 'rpm', 'sched', 'baseurl'].forEach((k) => { f['policy.' + k] = val('aiu-p-' + k); });
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
    renderPreview(); renderBand();
    renderStatus();
  }

  /* ───────── render ───────── */
  function renderAll() {
    renderStatus(); renderModes(); renderVisibility(); renderProviders(); renderKeyHints(); renderChecks(); renderInstalled();
    renderPreview(); renderBand(); renderMine(); renderPolicyBits(); renderBanners(); applyRole(); updatePrivacyWarn();
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
      const tested = cl.last_test_at ? t('stCloudTested', { w: rel(cl.last_test_at) }) : t('stCloudNever');
      pills.push({ c: cl.configured === false ? 'err' : (cl.last_test_ok === false ? 'err' : (cl.last_test_at ? 'ok' : 'warn')), b: t('stCloud', { p: nm }), s: cl.configured === false ? t('stCloudNone') : tested });
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
    return Array.isArray(av) ? av : USER_PROVIDERS;
  }
  function renderProviders() {
    const av = availableProviders();
    $('aiu-prov').innerHTML = PROVIDERS.map((p) => {
      const ok = av.includes(p.id);
      return `<button type="button" role="radio" class="aiu-admin" data-prov="${p.id}" aria-checked="${p.id === S.prov}" ${ok ? '' : 'data-soon="1" disabled'}>${esc(p.name)}<small>${ok ? esc(p.sub) : esc(t('soon'))}</small></button>`;
    }).join('');
    $$('#aiu-prov-blocks .aiu-prov-block').forEach((b) => b.classList.toggle('aiu-hide', b.dataset.p !== S.prov));
    const a = val('aiu-anthropic-auth'), br = val('aiu-bedrock-auth');
    $('aiu-anthropic-keywrap').classList.toggle('aiu-hide', a !== 'api_key');
    $('aiu-anthropic-wif').classList.toggle('aiu-hide', a !== 'wif');
    $('aiu-anthropic-envnote').classList.toggle('aiu-hide', a !== 'environment');
    $('aiu-bedrock-profwrap').classList.toggle('aiu-hide', br !== 'profile');
    $('aiu-bedrock-keywrap').classList.toggle('aiu-hide', br !== 'bedrock_api_key');
    $$('#aiu-prov button').forEach((b) => { if (!b.dataset.soon) b.disabled = !isAdmin(); });
  }
  function renderKeyHints() {
    USER_PROVIDERS.forEach((p) => {
      const sec = sectionData(p); const inp = $('aiu-' + p + '-key'); if (!inp) return;
      const set = !!sec.api_key_set;
      inp.placeholder = set ? '•••• ' + String(sec.api_key_hint || '').replace(/^…/, '') : KEY_PLACEHOLDER[p];
      const meta = [];
      if (set && sec.api_key_saved_at) meta.push(t('keySavedAt', { w: rel(sec.api_key_saved_at) }));
      if (set && sec.api_key_saved_by) meta.push(t('keySavedBy', { u: sec.api_key_saved_by }));
      $('aiu-' + p + '-keyhint').textContent = set ? (t('keySaved', { h: sec.api_key_hint || '••••' }) + (meta.length ? ' · ' + meta.join(' · ') : '')) : t('keyNone');
      $('aiu-' + p + '-remove').classList.toggle('aiu-hide', !set);
    });
  }
  function checkItem(c, text) { return `<li class="${c}">${esc(text)}</li>`; }
  function renderChecks() {
    const ul = $('aiu-ol-checks'); const o = (S.data && S.data.ollama) || {}; const c = S.olCheck;
    if (!c) {
      ul.innerHTML = checkItem('q', t('ckNone')) + (S.mode === 'bridge' ? checkItem('q', t('ckBridge')) : '');
      return;
    }
    const li = [];
    if (c.ok === false && c.code) li.push(checkItem('x', t('ckConn') + ': ' + errText({ data: { code: c.code } })));
    else li.push(checkItem('ok', t('ck1', { ms: c.latency_ms == null ? '—' : c.latency_ms, v: c.version || '—' })));
    if (c.model_loaded === true) li.push(checkItem('ok', t('ck2')));
    else if (c.model_loaded === false) li.push(checkItem('x', t('ck2no')));
    if (c.tools === true) li.push(checkItem('ok', t('ck3')));
    else if (c.tools === false) li.push(checkItem('x', t(S.sel === 'local_only' ? 'ck3noL' : 'ck3noH')));
    else li.push(checkItem('q', S.mode === 'bridge' ? t('ckBridge') : t('ck3unk')));
    if (c.json_total) li.push(checkItem(c.json_ok === c.json_total ? 'ok' : 'q', c.json_ok === c.json_total ? t('ck4ok') : t('ck4', { bad: c.json_total - c.json_ok, n: c.json_total })));
    ul.innerHTML = li.join('');
    void o;
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
  function renderPreview() {
    const el = $('aiu-h-preview'); const pv = S.data && S.data.preview;
    el.className = 'aiu-res warn';
    if (!pv || !Array.isArray(pv.items) || !pv.items.length) { el.textContent = t('hPreviewNone'); return; }
    const min = SEV_RANK[val('aiu-h-sev')] || 2; const lo = parseInt(val('aiu-h-lo'), 10), hi = parseInt(val('aiu-h-hi'), 10);
    const n = pv.items.filter((it) => (SEV_RANK[it[0]] || 0) >= min || (it[1] != null && !isNaN(lo) && !isNaN(hi) && it[1] >= Math.min(lo, hi) && it[1] <= Math.max(lo, hi))).length;
    el.textContent = t('hPreviewTxt', { n, total: pv.items.length, pct: Math.round(100 * n / pv.items.length) });
    el.parentElement.querySelector('label').textContent = t('hPreviewL', { total: pv.items.length });
  }
  function updatePrivacyWarn() {
    $('aiu-pv-warn').classList.toggle('aiu-hide', !($('aiu-pv-send').checked && S.sel !== 'local_only'));
    $('aiu-pv-warn').textContent = t('pvWarn', { p: PROV_NAME[S.prov] || S.prov });
  }
  function renderBanners() {
    const br = $('aiu-bridge');
    if (S.mode === 'bridge' && isAdmin()) { br.classList.remove('aiu-hide'); br.textContent = t('bridge'); } else br.classList.add('aiu-hide');
    const ro = $('aiu-ro');
    if (isAdmin()) ro.classList.add('aiu-hide'); else { ro.classList.remove('aiu-hide'); ro.textContent = t(isViewer() ? 'roViewer' : 'ro'); }
  }
  function applyRole() {
    const admin = isAdmin(); const contract = S.mode === 'contract';
    $$('#st-ai .aiu-admin').forEach((e) => {
      if (e.dataset.soon) return;
      e.disabled = !admin || (e.classList.contains('aiu-contract') && !contract);
    });
    $$('#aiu-modes .aiu-mode').forEach((b) => { b.disabled = !admin; b.setAttribute('aria-disabled', String(!admin)); });
    $('aiu-pv-redact').disabled = true;
    $('aiu-sec-mine').classList.toggle('aiu-hide', isViewer());
    $('aiu-sec-policy').classList.toggle('aiu-hide', !admin);
    $('aiu-savebar').classList.toggle('aiu-hide', !admin);
    $('aiu-ol-manage').querySelectorAll('button[data-act="ol-del"]').forEach((b) => { b.disabled = !admin; });
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
    const m = { valid: ['ok', 'stValid'], invalid: ['err', 'stInvalid'], forbidden: ['err', 'stForbidden'], rate_limited: ['warn', 'stRate'], revoked: ['err', 'stRevoked'], disabled: ['warn', 'stDisabled'], unknown: ['', 'stUnknown'] }[c.status] || ['', 'stUnknown'];
    return `<span class="aiu-tag ${m[0]}">${esc(t(m[1]))}${when ? ' · ' + esc(when) : ''}</span>`;
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
        <td class="aiu-mono">${esc(c.key_hint || '••••')}</td><td class="aiu-mono">${esc(c.model || '—')}</td><td>${statusTag(c)}</td>
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
      else if (r.status === 404 || r.status === 405 || r.status === 501) S.credsState = 'unavailable';
      else if (r.status === 403) S.credsState = 'forbidden';
      else S.credsState = 'error';
    } catch (e) { S.credsState = 'error'; }
    renderMine(); applyRole();
  }
  async function loadAdminTables() {
    if (!isAdmin()) return;
    const ok = S.mode === 'contract';
    const uk = $('aiu-ukeys'), us = $('aiu-usage');
    if (!ok) { uk.innerHTML = ''; us.innerHTML = ''; return; }
    try {
      const [k, u] = await Promise.all([aiApi('/api/ai/credentials'), aiApi('/api/ai/usage?scope=all&days=30')]);
      S.ukeys = k.ok && k.data ? (Array.isArray(k.data) ? k.data : (k.data.credentials || [])) : null;
      S.usage = u.ok && u.data ? (Array.isArray(u.data) ? u.data : (u.data.rows || [])) : null;
    } catch (e) { S.ukeys = null; S.usage = null; }
    renderAdminTables();
  }
  function renderAdminTables() {
    const uk = $('aiu-ukeys'), us = $('aiu-usage');
    const hk = `<tr><th>${esc(t('thUser'))}</th><th>${esc(t('thProv'))}</th><th>${esc(t('thCred'))}</th><th>${esc(t('thStatus'))}</th><th>${esc(t('lastUsed'))}</th><th></th></tr>`;
    uk.innerHTML = S.ukeys == null ? `<tr><td>${esc(t('err.unavailable'))}</td></tr>` : hk + (S.ukeys.map((c) => `<tr><td>${esc((c.owner && (c.owner.email || c.owner.id)) || c.owner_user_id || '—')}</td><td>${esc(PROV_NAME[c.provider] || c.provider)}</td><td class="aiu-mono">${esc(c.key_hint || '••••')}</td><td>${statusTag(c)}</td><td>${esc(rel(c.last_used_at) || '—')}</td><td>${c.status === 'revoked' ? '' : `<button type="button" class="btn btn-ghost btn-sm aiu-danger" data-act="uk-revoke" data-id="${esc(c.id)}">${esc(t('revoke'))}</button>`}</td></tr>`).join('') || `<tr><td colspan="6">${esc(t('noKeys'))}</td></tr>`);
    const hu = `<tr><th>${esc(t('thUser'))}</th><th>${esc(t('thCred'))}</th><th>${esc(t('thCalls'))}</th><th>${esc(t('thCost'))}</th></tr>`;
    us.innerHTML = S.usage == null ? `<tr><td>${esc(t('err.unavailable'))}</td></tr>` : hu + (S.usage.map((u) => {
      const own = u.credential_scope === 'user' || u.scope === 'own';
      const who = u.user_email || u.user || (u.credential_scope === 'system' || u.scope === 'system' ? t('sched') : '—');
      const cost = u.est_cost_usd == null ? '—' : Number(u.est_cost_usd).toLocaleString(S.lang === 'vi' ? 'vi-VN' : 'en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 }) + ' USD';
      return `<tr><td>${esc(who)}</td><td><span class="aiu-tag ${own ? 'b' : ''}">${esc(own ? t('own') : t('org'))}</span> ${esc(PROV_NAME[u.provider] || u.provider || '')} ${esc(u.key_hint || '')}</td><td>${esc(u.calls == null ? '—' : u.calls)}</td><td>${esc(cost)}${u.quota_pct != null ? ` <span class="aiu-tag warn">${esc(u.quota_pct)}%</span>` : ''}</td></tr>`;
    }).join('') || `<tr><td colspan="4">—</td></tr>`);
  }
  function renderPolicyBits() {
    $('aiu-policy-unavail').classList.toggle('aiu-hide', S.mode === 'contract');
    const hasData = S.mode === 'contract';
    if (!hasData) { $('aiu-ukeys').innerHTML = ''; $('aiu-usage').innerHTML = ''; } else renderAdminTables();
  }

  /* ───────── validation ───────── */
  function validate() {
    let ok = true;
    const err = (id, msg) => { const e = $(id); if (e) e.textContent = msg || ''; if (msg) ok = false; };
    ['aiu-ol-url-err', 'aiu-h-err', 'aiu-openai-baseerr'].forEach((i) => err(i, ''));
    USER_PROVIDERS.forEach((p) => err('aiu-' + p + '-keyerr', ''));
    const u = val('aiu-ol-url').trim();
    if (u && !/^https?:\/\/[^\s/@?#]+(:\d+)?(\/.*)?$/i.test(u)) err('aiu-ol-url-err', t('errUrl'));
    const ob = val('aiu-openai-base').trim();
    if (ob && !/^https?:\/\/[^\s/@?#]+/i.test(ob)) err('aiu-openai-baseerr', t('errUrl'));
    if (S.sel === 'hybrid') {
      const lo = parseInt(val('aiu-h-lo'), 10), hi = parseInt(val('aiu-h-hi'), 10);
      if (isNaN(lo) || isNaN(hi) || lo < 0 || hi > 100 || lo > hi) err('aiu-h-err', t('errBand'));
    }
    if (S.sel !== 'local_only') {
      const p = S.prov; const sec = sectionData(p); const typed = !!val('aiu-' + p + '-key');
      const needs = (p === 'anthropic' && val('aiu-anthropic-auth') === 'api_key') || (p === 'bedrock' && val('aiu-bedrock-auth') === 'bedrock_api_key') || p === 'openai' || p === 'openrouter';
      if (needs && !typed && !sec.api_key_set) err('aiu-' + p + '-keyerr', t('errKeyNeeded'));
    }
    return ok;
  }

  /* ───────── payload ───────── */
  function buildPayload() {
    const lo = parseInt(val('aiu-h-lo'), 10), hi = parseInt(val('aiu-h-hi'), 10);
    const pl = {
      mode: S.sel, provider: S.prov,
      anthropic: { auth_mode: val('aiu-anthropic-auth'), model: val('aiu-anthropic-model').trim() || undefined,
        wif: { federation_rule_id: val('aiu-wif-rule').trim(), organization_id: val('aiu-wif-org').trim(), identity_token_file: val('aiu-wif-token').trim(), workspace_id: val('aiu-wif-ws').trim(), service_account_id: val('aiu-wif-sa').trim() } },
      bedrock: { auth_mode: val('aiu-bedrock-auth'), region: val('aiu-bedrock-region').trim(), aws_profile: val('aiu-bedrock-profile').trim(), model: val('aiu-bedrock-model').trim() || undefined },
      openai: { model: val('aiu-openai-model').trim() || undefined, base_url: val('aiu-openai-base').trim() },
      openrouter: { model: val('aiu-openrouter-model').trim() || undefined },
      hybrid: { escalate_min_severity: val('aiu-h-sev'), fp_band_low: isNaN(lo) ? 0 : lo, fp_band_high: isNaN(hi) ? 100 : hi },
      privacy: { send_code_context: $('aiu-pv-send').checked, context_lines: Math.max(0, parseInt(val('aiu-pv-lines'), 10) || 0), redact_secrets: true },
    };
    USER_PROVIDERS.forEach((p) => { const k = val('aiu-' + p + '-key').trim(); if (k) pl[p].api_key = k; });   // write-only: chỉ gửi khi gõ key mới
    return pl;
  }
  function buildContractPayload() {
    const pl = buildPayload();
    pl.ollama = { url: val('aiu-ol-url').trim(), model: val('aiu-ol-model'), vision_model: val('aiu-ol-vision') };
    pl.advanced = { pentest_models: { planner: val('aiu-pt-planner').trim(), executor: val('aiu-pt-executor').trim(), summarizer: val('aiu-pt-summarizer').trim() } };
    if (isAdmin()) {
      const usd = val('aiu-p-usd').trim(), rpm = val('aiu-p-rpm').trim();
      pl.policy = {
        byok: val('aiu-p-byok'), fallback_to_org: val('aiu-p-fallback') === '1',
        allowed: val('aiu-p-allowed').split(',').map((s) => s.trim()).filter(Boolean),
        org_quota: { usd_per_user_month: usd === '' ? null : Number(usd), rpm_per_user: rpm === '' ? null : Number(rpm) },
        scheduled_jobs_credential: val('aiu-p-sched'), custom_base_url: val('aiu-p-baseurl'),
      };
    }
    return pl;
  }

  /* ───────── actions ───────── */
  async function load(force) {
    if (S.loading) return S.loading;
    if (S.inited && !force && S.data) { applyRole(); return; }
    S.loading = (async () => {
      const errBox = $('aiu-loaderr'); errBox.classList.add('aiu-hide');
      try {
        if (!S.dict.vi || !Object.keys(S.dict.vi).length) await loadDict('vi');
        if (S.lang === 'en') await loadDict('en');
        applyLang();
        S.data = await fetchSettings();
        document.body.classList.toggle('ai-legacy-on', S.mode === 'bridge' || /[?&]ai_legacy=1/.test(location.search));
        S.inited = true;
        fill();
        loadCreds(); loadAdminTables();
      } catch (e) {
        errBox.classList.remove('aiu-hide'); errBox.textContent = t('loadErr');
      } finally { S.loading = null; }
    })();
    return S.loading;
  }
  async function saveBridge(pl, ch) {
    const out = { ok: true, msgs: [] };
    const cfg = await aiApi('/api/ai/config', { method: 'PUT', body: pl });
    if (!cfg.ok) return { ok: false, msg: errText(cfg) };
    if (ch.includes('ollama.url')) { const r = await aiApi('/api/ollama/endpoint', { method: 'PUT', body: { url: val('aiu-ol-url').trim() } }); if (!r.ok) return { ok: false, msg: t('errOllamaUrl') + ' ' + errText(r) }; }
    if (ch.includes('ollama.model') && val('aiu-ol-model')) { const r = await aiApi('/api/ollama/active-model', { method: 'PUT', body: { model: val('aiu-ol-model') } }); if (!r.ok) return { ok: false, msg: errText(r) }; }
    if (ch.includes('ollama.vision_model') && val('aiu-ol-vision')) { const r = await aiApi('/api/ollama/vision-model', { method: 'PUT', body: { model: val('aiu-ol-vision') } }); if (!r.ok) return { ok: false, msg: errText(r) }; }
    return out;
  }
  async function save() {
    if (S.saving || !isAdmin()) return;
    if (!validate()) { toast(t('errFix'), 'warn'); return; }
    const ch = changes();
    S.saving = true; $('aiu-save').disabled = true;
    let res;
    try {
      const pr = S.mode === 'contract'
        ? aiApi('/api/ai/settings', { method: 'PUT', body: buildContractPayload() }).then((r) => (r.ok ? { ok: true } : { ok: false, msg: errText(r) }))
        : saveBridge(buildPayload(), ch);
      clearSecrets();     // key đã nằm trong body request → xoá khỏi DOM ngay, trước khi chờ phản hồi
      res = await pr;
    } catch (e) { res = { ok: false, msg: t('err.network') }; }
    S.saving = false;
    if (res.ok) { toast(t('saved'), 'success'); await load(true); }
    else { toast(t('saveFail', { m: res.msg }), 'error'); updateDirty(); }
  }
  function discard() { if (S.data) { fill(); $('aiu-cloud-res').classList.add('aiu-hide'); } }

  function showRes(el, kind, text) { el.className = 'aiu-res ' + kind; el.textContent = text; }
  async function testCloud() {
    const el = $('aiu-cloud-res'); const btn = $('aiu-cloud-test');
    const cloudDirty = changes().some((k) => SECTION_OF(k) === '3');
    if (S.mode === 'bridge' && cloudDirty) { showRes(el, 'warn', t('testDirtyBridge')); return; }
    btn.disabled = true; showRes(el, 'warn', t('testing'));
    try {
      const body = S.mode === 'contract' ? buildPayload() : undefined;      // key chưa lưu đi trong body, không giữ lại ở đâu
      const r = await aiApi('/api/ai/test', { method: 'POST', body });
      const d = r.data || {};
      if (r.ok && d.ok) {
        const bits = [(PROV_NAME[d.provider] || d.provider || ''), d.model, d.latency_ms != null ? d.latency_ms + ' ms' : null, d.json === true ? 'JSON ✓' : d.json === false ? 'JSON ✗' : null, d.tools === true ? 'tools ✓' : d.tools === false ? 'tools ✗' : null].filter(Boolean);
        showRes(el, d.tools === false ? 'warn' : 'ok', '✓ ' + bits.join(' · '));
      } else if (r.ok && d.ok === false) {
        showRes(el, 'err', '✗ ' + (d.code ? errText({ data: { code: d.code } }) : maskSecrets(d.error || t('err.generic'))));
      } else showRes(el, 'err', '✗ ' + errText(r));
    } catch (e) { showRes(el, 'err', '✗ ' + t('err.network')); }
    btn.disabled = !isAdmin();
  }
  async function testOllama() {
    const btn = $('aiu-ol-test'); const url = val('aiu-ol-url').trim();
    $('aiu-ol-url-err').textContent = '';
    if (url && !/^https?:\/\/[^\s/@?#]+/i.test(url)) { $('aiu-ol-url-err').textContent = t('errUrl'); return; }
    btn.disabled = true; $('aiu-ol-checks').innerHTML = checkItem('q', t('testing'));
    try {
      if (S.mode === 'contract') {
        const r = await aiApi('/api/ai/ollama/check', { method: 'POST', body: { url: url || undefined, model: val('aiu-ol-model') || undefined } });
        S.olCheck = r.ok && r.data ? r.data : { ok: false, code: (r.data && r.data.code) || (r.status === 429 ? 'RATE_LIMITED' : 'NETWORK') };
      } else {
        if (changes().includes('ollama.url')) { S.olCheck = null; $('aiu-ol-checks').innerHTML = checkItem('q', t('testDirtyBridge')); btn.disabled = !isAdmin(); return; }
        const t0 = performance.now(); const [h, m] = await Promise.all([aiApi('/api/ollama/health'), aiApi('/api/ollama/models')]);
        const names = ((m.data && m.data.models) || []).map((x) => x.name); const cur = val('aiu-ol-model');
        S.olCheck = h.ok ? { ok: true, latency_ms: Math.round(performance.now() - t0), version: null, model_loaded: cur ? names.includes(cur) : null, tools: null } : { ok: false, code: 'NETWORK' };
      }
    } catch (e) { S.olCheck = { ok: false, code: 'NETWORK' }; }
    renderChecks(); btn.disabled = !isAdmin();
  }
  async function loadModels(p) {
    const note = $('aiu-' + p + '-modelnote'); note.textContent = t('loadingModels');
    try {
      const r = await aiApi('/api/ai/models?provider=' + encodeURIComponent(p));
      if (!r.ok) { note.textContent = errText(r); return; }
      $('aiu-' + p + '-dl').innerHTML = ((r.data && r.data.models) || []).map((m) => `<option value="${esc(m)}"></option>`).join('');
      note.textContent = t(r.data && r.data.source === 'api' ? 'modelsApi' : 'modelsStatic', { n: ((r.data && r.data.models) || []).length });
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
    const r = S.mode === 'contract'
      ? await aiApi('/api/ai/settings', { method: 'PUT', body: { [p]: { clear_api_key: true } } })
      : await aiApi('/api/ai/config', { method: 'PUT', body: { [p]: { clear_api_key: true } } });
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
    $('aiu-add-region-wrap').classList.toggle('aiu-hide', p !== 'bedrock');
    $('aiu-add-models').innerHTML = (MODEL_SUGGEST[p] || []).map((m) => `<option value="${esc(m)}"></option>`).join('');
    $('aiu-add-model').value = (MODEL_SUGGEST[p] || [''])[0];
  }
  async function addKey() {
    const err = $('aiu-add-err'); err.textContent = '';
    const p = val('aiu-add-prov'); const k = val('aiu-add-key').trim();
    if (!k) { err.textContent = t('errKeyNeeded'); return; }
    if (/^sk-ant-oat/i.test(k)) { err.textContent = t('errOauth'); $('aiu-add-key').value = ''; return; }   // token subscription OAuth: không nhận
    const body = { provider: p, model: val('aiu-add-model').trim() || undefined, label: val('aiu-add-label').trim() || undefined, secret: k, is_default: !(S.creds || []).length };
    if (p === 'bedrock') body.region = val('aiu-add-region').trim();
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
        else setMineMsg('✗ ' + (d.code ? errText({ data: { code: d.code } }) : errText(r)), true);
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
    if (S.mode !== 'contract') return;
    try { const r = await aiApi('/api/ai/settings'); if (r.ok && r.data && r.data.status) { S.data.status = r.data.status; renderStatus(); } } catch (e) { /* giữ */ }
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
      if (e.target.id === 'aiu-anthropic-auth' || e.target.id === 'aiu-bedrock-auth') renderProviders();
      if (e.target.id === 'aiu-pv-send') updatePrivacyWarn();
      updateDirty();
    });
    root.addEventListener('change', (e) => { if (e.target.id === 'aiu-anthropic-auth' || e.target.id === 'aiu-bedrock-auth') renderProviders(); if (e.target.id === 'aiu-add-prov') onAddProv(); updateDirty(); });
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
