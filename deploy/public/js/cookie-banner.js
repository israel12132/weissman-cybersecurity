// Cookie-consent banner — show once, store consent for the session. Externalized from an
// inline <script> so the marketing-site CSP can drop script-src 'unsafe-inline'.
(function () {
  var key = 'weissman_cookie_consent_v1';
  try {
    if (!localStorage.getItem(key)) {
      var banner = document.getElementById('cookie-banner');
      if (banner) {
        banner.classList.remove('hidden');
      }
    }
    var ok = document.getElementById('cookie-ok');
    if (ok) {
      ok.addEventListener('click', function () {
        localStorage.setItem(key, '' + Date.now());
        var banner = document.getElementById('cookie-banner');
        if (banner) {
          banner.classList.add('hidden');
        }
      });
    }
  } catch (_) {}
})();
