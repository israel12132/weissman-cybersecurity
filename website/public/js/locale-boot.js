/* eslint-env browser */
(function () {
  try {
    var path = window.location.pathname || '/'
    if (path !== '/' && path !== '/index.html') return
    var match = document.cookie.match(/(?:^|; )weissman_locale=([^;]*)/)
    var pref = match ? decodeURIComponent(match[1]) : ''
    if (!pref) {
      try {
        pref = window.localStorage.getItem('weissman_locale') || ''
      } catch {
        pref = ''
      }
    }
    if (pref === 'he') window.location.replace('/he/')
  } catch {
    /* ignore */
  }
})()
