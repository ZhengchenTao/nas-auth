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
