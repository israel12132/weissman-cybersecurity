// Self-serve signup form handler. Externalized from an inline <script> so the marketing-site
// CSP can drop script-src 'unsafe-inline'.
(function () {
  var form = document.getElementById('signup-form');
  var status = document.getElementById('form-status');
  var btn = document.getElementById('submit-btn');
  if (!form) {
    return;
  }

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    status.textContent = '';
    status.style.color = '';
    if (!form.accept_terms.checked) {
      status.style.color = '#f87171';
      status.textContent = 'You must accept the Terms of Service and Privacy Policy.';
      return;
    }
    var payload = {
      workspace_name: form.workspace_name.value.trim(),
      email: form.email.value.trim(),
      password: form.password.value,
      accept_terms: true,
    };
    btn.disabled = true;
    btn.textContent = 'Creating…';
    try {
      var r = await fetch('/api/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      var d = await r.json().catch(function () { return {}; });
      if (r.status === 202 || r.ok) {
        status.style.color = '#22d3ee';
        status.textContent = d.detail || 'Check your inbox to confirm your workspace.';
        if (d.verify_url) {
          // Dev-mode shortcut: render the link
          status.innerHTML +=
            ' <a href="' + d.verify_url + '" style="color:#22d3ee;display:block;margin-top:.5rem;font-size:.7rem">Dev verify link →</a>';
        }
        form.reset();
      } else if (r.status === 503) {
        status.style.color = '#fbbf24';
        status.textContent = d.detail || 'Self-serve signup is not enabled on this deployment. Contact sales@weissman.io.';
      } else {
        status.style.color = '#f87171';
        status.textContent = d.detail || 'Something went wrong. Try again.';
      }
    } catch (err) {
      status.style.color = '#f87171';
      status.textContent = 'Network error — please try again.';
    } finally {
      btn.disabled = false;
      btn.textContent = 'Create workspace';
    }
  });
})();
