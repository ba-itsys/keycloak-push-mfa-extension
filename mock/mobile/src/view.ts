export function getView() {
  return `
<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Mock Enrollment</title>
  <style>
    :root { color-scheme: light dark; }
    body { font-family: system-ui, sans-serif; margin: 24px; max-width: 900px; }
    .row { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
    input[type="text"], textarea { width: 100%; font-family: ui-monospace, Menlo, Consolas, monospace; }
    textarea { height: 120px; }
    button { padding: 10px 16px; font-weight: 600; cursor: pointer; }
    .grid { display: grid; grid-template-columns: 1fr; gap: 16px; }
    .result { white-space: pre-wrap; font-family: ui-monospace, Menlo, Consolas, monospace; background: rgba(0,0,0,.05); padding: 12px; border-radius: 8px; }
    .pill { display:inline-block; padding:2px 8px; border-radius:999px; background:#eee; margin-left:8px; font-size:12px; }
    label b { display:block; margin-bottom:6px; }
    .field { margin-top: 12px; }
    .field input[type="text"] { border: 1px solid rgba(0,0,0,.15); }
    @media (prefers-color-scheme: dark) {
      .field input[type="text"] { border-color: rgba(255,255,255,.2); color: inherit; }
    }
  </style>
</head>
<body>
  <h1>SecureApp - Mock</h1>

  <div class="grid">
    <div>
      <label>
        <b>Keycloak Token (JWS):</b>
        <textarea id="token" placeholder="eyJhbGciOi..."></textarea>
      </label>

      <label class="field">
        <b>Enter context (only for Enroll)[optional]:</b>
        <input id="context" type="text" placeholder="e.g. deviceXY" />
      </label>

      <label class="field">
        <b>User verification (number/PIN) [optional]:</b>
        <input id="userVerification" type="text" placeholder="e.g. 42 or 0123" />
      </label>

      <label class="field">
        <b>Login action:</b>
        <select id="action">
          <option value="approve" selected>approve</option>
          <option value="deny">deny</option>
        </select>
      </label>

    <label class="field">
        <b>Actions:</b>
            <div class="row" style="justify-content: space-between;">
            <div>
          <button id="enrollBtn">Enroll</button>
          <button id="confirm-loginBtn">confirm-login</button>
        </div>
        <small>Optional: ?token=...&context=... in URL automatically fills the fields.</small>
      </div>
    </div>
    </label>
  
    <div>
      <label>
        <b>Answer:</b>
        <pre id="out" class="result">No interactions yet.</pre>
      </label>
    </div>

    <details open>
      <summary><b>Configuration</b></summary>
      <pre class="result" id="cfg"></pre>
    </details >
  </div>

  <script>
    const qs = new URLSearchParams(location.search);
    const tokenEl = document.getElementById('token');
    const contextEl = document.getElementById('context');
    const userVerificationEl = document.getElementById('userVerification');
    const actionEl = document.getElementById('action');
    const outEl = document.getElementById('out');
    const cfgEl = document.getElementById('cfg');

    fetch('/meta').then(r => r.json()).then(meta => {
      cfgEl.textContent = JSON.stringify(meta, null, 2);
    }).catch(()=>{});

    if (qs.get('token')) tokenEl.value = qs.get('token');
    if (qs.get('context')) contextEl.value = qs.get('context');
    if (qs.get('userVerification')) userVerificationEl.value = qs.get('userVerification');
    if (qs.get('action')) actionEl.value = qs.get('action');

    document.getElementById('enrollBtn').addEventListener('click', async () => {
      const token = tokenEl.value.trim();
      const context = contextEl.value.trim();
      if (!token) {
        outEl.textContent = 'Please enter token.';
        return;
      }
      outEl.textContent = 'Starting enrollment...';
      try {
        const res = await fetch('/enroll', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ token, context })
        });
        const data = await res.json();
        outEl.textContent = JSON.stringify(data, null, 2);
      } catch (e) {
        outEl.textContent = 'Error: ' + (e?.message || e);
      }
    });

    document.getElementById('confirm-loginBtn').addEventListener('click', async () => {
      const token = tokenEl.value.trim();
      const userVerification = userVerificationEl.value.trim();
      const action = actionEl.value.trim();
      if (!token) {
        outEl.textContent = 'Please enter token.';
        return;
      }
      outEl.textContent = 'Start confirm-login...';
      try {
        const res = await fetch('/confirm-login', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ token, userVerification, action })
        });
        const data = await res.json();
        outEl.textContent = JSON.stringify(data, null, 2);
      } catch (e) {
        outEl.textContent = 'Error: ' + (e?.message || e);
      }
    });
  </script>
</body>
</html>`;
}
