// 暗色跟随系统：Basecoat 的暗色认 <html class="dark">，不读 prefers-color-scheme。
// 在 <head> 里同步加载，避免页面先按亮色画一帧再闪成暗色。
(function () {
  var m = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)');
  function apply() { document.documentElement.classList.toggle('dark', !!(m && m.matches)); }
  apply();
  if (m && m.addEventListener) m.addEventListener('change', apply);
})();

// 页面交互全走 data 属性 + 事件委托，模板里不写任何内联 on*= / <script>（2026-09-29 安全整改）：
// 这样页面能在 CSP script-src 'self' 下工作，用户可控文本（DCR 的 client_name 等）只进 HTML 属性值，
// 由 getAttribute 取回当纯文本用，不会再被当 JS 执行。
// 本文件在 <head> 同步加载，挂在 document 上的委托不用等 DOMContentLoaded。
(function () {
  // antiforgery（2026-10-16，external-auth.md §二十三）：个人中心 / 管理后台的页面在 <meta name="csrf-token"> 里放请求令牌，
  // 服务端渲染的表单自带隐藏字段；脚本 fetch 同源写请求时这里自动补 X-CSRF-TOKEN 头。没有 meta 的页面（登录、授权确认）不动。
  if (window.fetch) {
    var origFetch = window.fetch;
    window.fetch = function (input, init) {
      var meta = document.querySelector('meta[name="csrf-token"]');
      var isReq = typeof Request !== 'undefined' && input instanceof Request;
      var method = ((init && init.method) || (isReq ? input.method : 'GET')).toUpperCase();
      var url = new URL(isReq ? input.url : String(input), window.location.href);
      if (!meta || method === 'GET' || method === 'HEAD' || url.origin !== window.location.origin)
        return origFetch.call(this, input, init);
      var headers = new Headers((init && init.headers) || (isReq ? input.headers : undefined));
      if (!headers.has('X-CSRF-TOKEN')) headers.set('X-CSRF-TOKEN', meta.getAttribute('content'));
      return origFetch.call(this, input, Object.assign({}, init, { headers: headers }));
    };
  }

  // <form data-confirm="提示文字">：提交前确认，取消则不提交
  document.addEventListener('submit', function (e) {
    var f = e.target;
    var msg = f && f.getAttribute ? f.getAttribute('data-confirm') : null;
    if (msg && !window.confirm(msg)) e.preventDefault();
  });

  // 提交中 loading + 防重复提交（2026-10-02）：「以 xx 身份授权」/ 登录后要等下游应用回调，网络慢时看起来像卡住，
  // 用户会再点一次。被点的按钮加 aria-busy（app.css 画转圈、禁点），同一表单第二次提交直接拦掉。
  // 挂在 data-confirm 那个监听之后：确认框点了取消（defaultPrevented）就不进 loading。
  document.addEventListener('submit', function (e) {
    if (e.defaultPrevented) return;
    var f = e.target;
    if (!f || !f.setAttribute || f.hasAttribute('data-no-busy')) return;
    if (f.getAttribute('data-busy') === '1') { e.preventDefault(); return; }
    f.setAttribute('data-busy', '1');
    var btn = e.submitter || f.querySelector('button[type=submit], button:not([type])');
    // 延后一拍再禁用：表单数据在 submit 事件之后才收集，同步禁用会把按钮自己的 name/value 丢掉
    setTimeout(function () {
      if (btn) { btn.setAttribute('aria-busy', 'true'); btn.disabled = true; }
    }, 0);
  });

  // 外部登录（通过 Google / 微软继续）是链接不是表单，同样要等 IdP 跳转：点一次后 loading，第二次点直接拦掉
  document.addEventListener('click', function (e) {
    var a = e.target && e.target.closest ? e.target.closest('a.btn[href*="/external/"]') : null;
    if (!a || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey) return;
    if (a.getAttribute('aria-busy') === 'true') { e.preventDefault(); return; }
    a.setAttribute('aria-busy', 'true');
  });

  // 浏览器后退回到这页（bfcache 原样恢复 DOM）：清掉 loading，否则按钮会一直转着点不了
  window.addEventListener('pageshow', function (e) {
    if (!e.persisted) return;
    document.querySelectorAll('form[data-busy]').forEach(function (f) { f.removeAttribute('data-busy'); });
    document.querySelectorAll('[aria-busy="true"]').forEach(function (b) { b.removeAttribute('aria-busy'); b.disabled = false; });
  });

  // 密码框的显示 / 隐藏按钮（2026-10-04）：每个 input[type=password] 右侧加一个眼睛按钮，按一下显示明文、再按一下隐藏。
  // 管理员替家人设密码时看不见自己打了什么，容易设错。
  // 包一层 .pw-wrap 放按钮；Basecoat 只给 .field 的直接子 input 上样式，包了之后靠 .input 类保住样式。
  var EYE = '<svg class="eye" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>' +
    '<svg class="eye-off" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10.7 5.1A10.4 10.4 0 0 1 12 5c6.5 0 10 7 10 7a17.6 17.6 0 0 1-3.2 4.1"/><path d="M6.6 6.6A17.3 17.3 0 0 0 2 12s3.5 7 10 7a10.3 10.3 0 0 0 5.4-1.6"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/><path d="M3 3l18 18"/></svg>';
  function pwLabel(shown) {
    var zh = /^zh/i.test(document.documentElement.lang || '');
    return shown ? (zh ? '隐藏密码' : 'Hide password') : (zh ? '显示密码' : 'Show password');
  }
  function setPwShown(btn, shown) {
    var inp = btn.parentNode.querySelector('input');
    if (!inp) return;
    inp.type = shown ? 'text' : 'password';
    btn.setAttribute('aria-pressed', shown ? 'true' : 'false');
    btn.setAttribute('aria-label', pwLabel(shown));
    btn.title = pwLabel(shown);
  }
  function addPwToggles() {
    document.querySelectorAll('input[type=password]').forEach(function (inp) {
      if (inp.parentNode.classList.contains('pw-wrap')) return;
      var wrap = document.createElement('div');
      wrap.className = 'pw-wrap';
      inp.parentNode.insertBefore(wrap, inp);
      wrap.appendChild(inp);
      inp.classList.add('input');
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'pw-toggle';
      btn.innerHTML = EYE;
      wrap.appendChild(btn);
      setPwShown(btn, false);
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', addPwToggles);
  else addPwToggles();

  document.addEventListener('click', function (e) {
    var btn = e.target && e.target.closest ? e.target.closest('.pw-toggle') : null;
    if (!btn) return;
    setPwShown(btn, btn.getAttribute('aria-pressed') !== 'true');
    var inp = btn.parentNode.querySelector('input');
    if (inp) inp.focus();
  });
  // 提交前一律变回密码框：明文状态提交的话，浏览器会把它当普通文本记进表单自动填充历史，密码管理器也不认
  document.addEventListener('submit', function () {
    document.querySelectorAll('.pw-toggle[aria-pressed="true"]').forEach(function (btn) { setPwShown(btn, false); });
  }, true);

  document.addEventListener('click', function (e) {
    var t = e.target && e.target.closest ? e.target.closest('[data-lang], [data-sidebar-toggle]') : null;
    if (!t) return;
    // <a data-lang="zh">：保留现有 query（consent 页参数不能丢），只改 / 加 lang
    var lang = t.getAttribute('data-lang');
    if (lang) {
      e.preventDefault();
      var u = new URL(window.location.href);
      u.searchParams.set('lang', lang);
      window.location.href = u.toString();
      return;
    }
    // <button data-sidebar-toggle>：窄屏顶栏的菜单按钮；toggle 由 Basecoat sidebar.min.js 挂上
    if (t.hasAttribute('data-sidebar-toggle')) {
      var s = document.querySelector('.sidebar');
      if (s && typeof s.toggle === 'function') s.toggle();
    }
  });
})();
(function () {
  'use strict';
  var zh = /^zh/i.test(document.documentElement.lang || '');
  function label(cn, en) { return zh ? cn : en; }
  function init() {
    document.querySelectorAll('[data-directory]').forEach(function (box) {
      var cfg = JSON.parse(box.getAttribute('data-directory'));
      var query = box.querySelector('[data-directory-query]');
      var status = box.querySelector('[data-directory-status]');
      var results = box.querySelector('[data-directory-results]');
      var form = box.querySelector('[data-directory-save]');
      var auto = cfg.self && new URL(location.href).searchParams.get('profile_refresh') === cfg.provider;
      var continuation = new URL(location.href).searchParams.get('return_url') || '';
      var frame, nonce, timer;
      function finishFailure(message) {
        status.textContent = message;
        if (frame) { frame.remove(); frame = null; }
        clearTimeout(timer);
        if (auto && continuation) {
          var dest = new URL(continuation, location.href);
          if (dest.origin === location.origin) location.assign(dest.href);
        }
      }
      function select(row) {
        form.elements.subject.value = row[cfg.subjectField];
        form.elements.profile_json.value = JSON.stringify(row);
        form.elements.return_url.value = continuation;
        box.querySelector('[data-directory-preview]').textContent = cfg.visible
          .filter(function (k) { return row[k]; }).map(function (k) { return cfg.fields[k] + ': ' + row[k]; }).join(' · ');
        form.hidden = false;
        if (auto) form.requestSubmit();
      }
      window.addEventListener('message', function (event) {
        if (!frame || event.source !== frame.contentWindow || event.origin !== new URL(cfg.bridge).origin) return;
        var message = event.data;
        if (!message || message.request !== nonce) return;
        if (message.type === 'directory-ready') {
          frame.contentWindow.postMessage({ type: 'directory-query', request: nonce, keyword: query.value.trim() }, event.origin);
          return;
        }
        if (message.type !== 'directory-result') return;
        clearTimeout(timer);
        if (message.status !== 'ok' || !Array.isArray(message.rows) || message.rows.length > 128)
          return finishFailure(label('公司目录暂不可用，请先登录身份提供方后重试。', 'Directory unavailable. Sign in to your identity provider and retry.'));
        var rows = message.rows.map(function (row) {
          var clean = {};
          Object.keys(cfg.fields).forEach(function (k) {
            if (typeof row[k] === 'string' && row[k].length <= 256 && !/[\x00-\x1f\x7f]/.test(row[k])) clean[k] = row[k];
          });
          return clean;
        }).filter(function (row) { return row[cfg.subjectField] && (!cfg.subject || row[cfg.subjectField] === cfg.subject); });
        results.replaceChildren();
        if (!rows.length || (cfg.subject && rows.length !== 1))
          return finishFailure(label('没有唯一匹配的用户 ID，请核对搜索条件。', 'No unique matching identity. Check your search.'));
        status.textContent = label('请选择人员并确认保存；权限单独配置。', 'Select a person and confirm. Permissions are configured separately.');
        if (cfg.subject) select(rows[0]);
        else rows.forEach(function (row) {
          var button = document.createElement('button'); button.type = 'button'; button.className = 'btn';
          button.textContent = cfg.visible.filter(function (k) { return row[k]; })
            .map(function (k) { return cfg.fields[k] + ': ' + row[k]; }).join(' · ');
          button.addEventListener('click', function () { select(row); }); results.append(button);
        });
        frame.remove(); frame = null;
      });
      function search() {
        if (query.value.trim().length < 2 || query.value.trim().length > 80) return;
        clearTimeout(timer); if (frame) frame.remove(); form.hidden = true; results.replaceChildren();
        nonce = crypto.randomUUID(); frame = document.createElement('iframe');
        frame.hidden = true; frame.setAttribute('sandbox', 'allow-scripts allow-same-origin');
        if (cfg.localNetwork) frame.setAttribute('allow', 'local-network; local-network-access');
        frame.src = cfg.bridge + '#parent=' + encodeURIComponent(location.origin) + '&request=' + encodeURIComponent(nonce);
        box.append(frame); status.textContent = label('正在查询公司目录…', 'Searching directory…');
        timer = setTimeout(function () { finishFailure(label('查询超时，请重试。', 'Directory query timed out.')); }, 8000);
      }
      box.querySelector('[data-directory-search]').addEventListener('click', search);
      query.addEventListener('keydown', function (event) { if (event.key === 'Enter') { event.preventDefault(); search(); } });
      if (auto) search();
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
