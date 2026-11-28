/* VulnGuard — Co-work: dòng trạng thái ĐỌC-CHỈ "hội thoại chạy ở đâu" (AI PR-5b, kế hoạch §4.11.5).
 *
 * Dữ liệu: GET /api/coworker/agent/conversations/{id}/route (đã có hội thoại) hoặc GET /api/coworker/agent/route-preview
 * (chưa có). Cả hai chỉ đọc, không gọi LLM. KHÔNG có picker/toggle: dòng này không thay đổi route.
 * Chỉ render chuỗi i18n của UI + provider/model/hint (qua textContent) — không bao giờ render text do server/provider trả về.
 */
(function () {
  'use strict';
  var DICT = {
    vi: {
      local: '🏠 Chạy local · {model} — dữ liệu không rời máy này',
      cloud: '☁ Chạy trên cloud · {provider} {model} ({key}) — nội dung file, output lệnh và tin nhắn sẽ rời máy này; secret/PII được che tự động',
      keyUser: 'khoá của bạn {hint}',
      keyUserNoHint: 'khoá của bạn',
      keyOrg: 'khoá của tổ chức',
      changed: 'Cài đặt đã đổi: hội thoại mới sẽ chạy trên Cloud',
      link: 'Settings › AI',
      unknown: 'Chưa xác định được nơi chạy',
      loading: 'Đang kiểm tra nơi chạy…',
      AI_ROUTE_CHANGED: 'Cài đặt đã đổi sang Local — hãy bắt đầu hội thoại mới',
      AI_NO_CREDENTIAL: 'Chưa có khoá AI — thêm tại Settings › AI › Khoá AI của tôi',
      AI_CRED_REVOKED: 'Khoá AI của hội thoại đã bị thu hồi — hãy bắt đầu hội thoại mới',
      AI_CRED_FORBIDDEN: 'Khoá AI không dùng được cho hội thoại này — hãy bắt đầu hội thoại mới',
      AI_QUOTA: 'Đã hết hạn mức AI — hãy bắt đầu hội thoại mới hoặc liên hệ quản trị viên',
      AI_RATE_LIMIT: 'Vượt giới hạn số yêu cầu AI — thử lại sau ít phút',
      AI_NOT_ALLOWED: 'Chính sách AI không cho phép model này — xem Settings › AI',
      AI_CLOUD_NO_TOOLS: 'Model cloud chưa qua kiểm tra tool-calling — xem Settings › AI',
      pinnedCloud: 'Hội thoại này đã chạy trên cloud — nội dung đã gửi đã rời máy này',
      refused: 'Co-work không chạy được với cài đặt AI hiện tại — xem Settings › AI',
      riskTitle: 'Hành động rủi ro — tự duyệt đã bị tắt cho hành động này',
      riskSensitive: 'Gửi nội dung file nhạy cảm này lên cloud?',
      riskSensitiveExec: 'Lệnh này có thể đọc file nhạy cảm hoặc lịch sử git — kết quả sẽ được gửi lên cloud. Chạy?',
      riskSuspicious: 'Đề xuất sau khi đọc nội dung đáng ngờ',
      riskHosts: 'Host bên ngoài:',
      riskConfirm: 'Tôi đã xem và xác nhận',
      autoOff: 'Tự duyệt đã tắt cho hành động rủi ro',
      autoOffCloud: 'Tự duyệt bị tắt khi dùng cloud: mọi hành động cần bạn duyệt tay'
    },
    en: {
      local: '🏠 Runs locally · {model} — data stays on this machine',
      cloud: '☁ Runs in the cloud · {provider} {model} ({key}) — file contents, command output and messages leave this machine; secrets/PII are masked automatically',
      keyUser: 'your key {hint}',
      keyUserNoHint: 'your key',
      keyOrg: 'organisation key',
      changed: 'Settings changed: new conversations run on Cloud',
      link: 'Settings › AI',
      unknown: 'Cannot determine where this runs',
      loading: 'Checking where this runs…',
      AI_ROUTE_CHANGED: 'Settings changed to Local — start a new conversation',
      AI_NO_CREDENTIAL: 'No AI key — add one in Settings › AI › My AI keys',
      AI_CRED_REVOKED: "This conversation's AI key was revoked — start a new conversation",
      AI_CRED_FORBIDDEN: 'This AI key cannot be used for this conversation — start a new conversation',
      AI_QUOTA: 'AI quota exhausted — start a new conversation or contact an administrator',
      AI_RATE_LIMIT: 'AI request rate limit reached — try again in a few minutes',
      AI_NOT_ALLOWED: 'AI policy does not allow this model — see Settings › AI',
      AI_CLOUD_NO_TOOLS: 'The cloud model has not passed the tool-calling check — see Settings › AI',
      pinnedCloud: 'This conversation ran in the cloud — content already sent left this machine',
      refused: 'Co-work cannot run with the current AI settings — see Settings › AI',
      riskTitle: 'Risky action — auto-approve is disabled for this action',
      riskSensitive: 'Send the contents of this sensitive file to the cloud?',
      riskSensitiveExec: 'This command may read a sensitive file or git history — its output will be sent to the cloud. Run it?',
      riskSuspicious: 'Proposed after suspicious content',
      riskHosts: 'External hosts:',
      riskConfirm: 'I have reviewed this and confirm',
      autoOff: 'Auto-approve is disabled for risky actions',
      autoOffCloud: 'Auto-approve is disabled on the cloud route: every action needs your explicit approval'
    }
  };
  var PROVIDERS = { anthropic: 'Anthropic', bedrock: 'AWS Bedrock', openai: 'OpenAI', azure_openai: 'Azure OpenAI', ollama: 'Ollama' };

  function lang() {
    try { var v = localStorage.getItem('vg-ai-lang'); if (v === 'vi' || v === 'en') return v; } catch (e) { /* storage có thể bị chặn */ }
    return String(navigator.language || 'vi').toLowerCase().indexOf('en') === 0 ? 'en' : 'vi';
  }
  function t(key, vars, l) {
    var d = DICT[l || lang()] || DICT.vi;
    var s = d[key] !== undefined ? d[key] : (DICT.vi[key] !== undefined ? DICT.vi[key] : key);
    return vars ? s.replace(/\{(\w+)\}/g, function (m, k) { return vars[k] == null ? '' : String(vars[k]); }) : s;
  }

  // info = JSON của server → {text, tone: 'local'|'cloud'|'refused'|'unknown', note}
  function describe(info, l) {
    l = l || lang();
    if (!info || typeof info !== 'object') return { text: t('unknown', null, l), tone: 'unknown' };
    if (info.state === 'refused') {
      var known = ['AI_ROUTE_CHANGED', 'AI_NO_CREDENTIAL', 'AI_CRED_REVOKED', 'AI_CRED_FORBIDDEN', 'AI_QUOTA', 'AI_RATE_LIMIT', 'AI_NOT_ALLOWED', 'AI_CLOUD_NO_TOOLS'];
      var rt = t(known.indexOf(info.code) >= 0 ? info.code : 'refused', null, l);
      if (info.route_kind === 'cloud') rt += ' · ' + t('pinnedCloud', null, l);   // hội thoại đã ghim cloud: vẫn nói rõ dữ liệu đã rời máy
      return { text: rt, tone: 'refused', code: info.code || null };
    }
    if (info.state !== 'ok') return { text: t('unknown', null, l), tone: 'unknown' };
    if (info.route_kind === 'cloud') {
      var key = info.key_scope === 'user'
        ? (info.key_hint ? t('keyUser', { hint: info.key_hint }, l) : t('keyUserNoHint', null, l))
        : t('keyOrg', null, l);
      return { text: t('cloud', { provider: PROVIDERS[info.provider] || info.provider || '', model: info.model || '', key: key }, l), tone: 'cloud' };
    }
    var txt = t('local', { model: info.model || '' }, l);
    if (info.settings_changed) txt += ' · ' + t('changed', null, l);
    return { text: txt, tone: 'local' };
  }

  function mount(textEl, linkEl, info) {
    var d = describe(info);
    var host = textEl.parentElement;
    textEl.textContent = d.text;                       // textContent: không bao giờ HTML
    if (linkEl) linkEl.textContent = t('link');
    if (host) { host.dataset.tone = d.tone; host.dataset.route = (info && info.route_kind) || ''; host.dataset.state = (info && info.state) || ''; host.lang = lang(); }
    return d;
  }

  window.VGRoute = { describe: describe, mount: mount, t: t, lang: lang };
})();
