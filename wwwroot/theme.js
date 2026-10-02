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
