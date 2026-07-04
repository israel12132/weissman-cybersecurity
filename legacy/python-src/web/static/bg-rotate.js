(function () {
  const ROTATE_MS = 5 * 60 * 1000;
  const LAYERS = 5;

  function setActiveBg(index) {
    document.querySelectorAll('.bg-layer').forEach(function (el, i) {
      el.classList.toggle('active', i === index);
    });
  }

  function init() {
    var layers = document.querySelectorAll('.bg-layer');
    if (layers.length === 0) return;
    setActiveBg(0);
    setInterval(function () {
      var current = Array.from(layers).findIndex(function (el) { return el.classList.contains('active'); });
      if (current < 0) current = 0;
      setActiveBg((current + 1) % LAYERS);
    }, ROTATE_MS);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
