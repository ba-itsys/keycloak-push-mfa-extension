export function getView() {
    return `<!doctype html>
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
  </style>
</head>
<body>
  <h1>SecureApp - Mock</h1>

  <div class="grid">
    <div>
      <label>
        <b>Keycloak Token (JWS)</b>
        <textarea id="token" placeholder="eyJhbGciOi..."></textarea>
      </label>
      <div class="row" style="justify-content: space-between;">
        <div>
          <button id="enrollBtn">Enroll</button>
          <button id="confirm-loginBtn">confirm-login</button>
        </div>
        <small>Optional: ?token=... in der URL füllt das Feld automatisch.</small>
      </div>
    </div>

    <div>
      <label>
        <b>Antwort</b>
        <pre id="out" class="result">Noch nichts ausgeführt.</pre>
      </label>
    </div>

    <details>
      <summary><b>Konfiguration</b></summary>
      <pre class="result" id="cfg"></pre>
    </details>
  </div>

  <script>
    const qs = new URLSearchParams(location.search);
    const tokenEl = document.getElementById('token');
    const outEl = document.getElementById('out');
    const cfgEl = document.getElementById('cfg');

    // Hole Server-Defaults von GET /meta
    fetch('/meta').then(r => r.json()).then(meta => {
      cfgEl.textContent = JSON.stringify(meta, null, 2);
    }).catch(()=>{});

    if (qs.get('token')) tokenEl.value = qs.get('token');

    document.getElementById('enrollBtn').addEventListener('click', async () => {
      const token = tokenEl.value.trim();
      if (!token) {
        outEl.textContent = 'Bitte Enrollment-Token eintragen.';
        return;
      }
      outEl.textContent = 'Starte Enrollment...';
      try {
        const res = await fetch('/enroll', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ token })
        });
        const data = await res.json();
        outEl.textContent = JSON.stringify(data, null, 2);
      } catch (e) {
        outEl.textContent = 'Fehler: ' + (e?.message || e);
      }
    });
    
      document.getElementById('confirm-loginBtn').addEventListener('click', async () => {
      const token = tokenEl.value.trim();
      if (!token) {
        outEl.textContent = 'Bitte Token eintragen.';
        return;
      }
      outEl.textContent = 'Starte confirm-login...';
      try {
        const res = await fetch('/confirm-login', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ token })
        });
        const data = await res.json();
        outEl.textContent = JSON.stringify(data, null, 2);
      } catch (e) {
        outEl.textContent = 'Fehler: ' + (e?.message || e);
      }
    });
  </script>
</body>
</html>`;
}