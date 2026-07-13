// Footer year stamp. Externalized from inline <script> so the marketing-site CSP
// can drop script-src 'unsafe-inline'. Sets any #y / #year element to the current year.
(function () {
  var y = String(new Date().getFullYear());
  ['y', 'year'].forEach(function (id) {
    var el = document.getElementById(id);
    if (el) {
      el.textContent = y;
    }
  });
})();
