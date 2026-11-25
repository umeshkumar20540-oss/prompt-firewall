const http = require('http');
const https = require('https');
const { URL } = require('url');
const { SecretVault } = require('./scanner');

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Prompt Firewall Dashboard</title>
<style>
  body{margin:0;font-family:system-ui,sans-serif;background:#0b0f19;color:#f1f5f9;padding:24px;}
  .wrap{max-width:960px;margin:0 auto;}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin:18px 0;}
  .card{background:#111827;border:1px solid #253047;border-radius:12px;padding:16px;}
  .val{font-size:2rem;font-weight:800;color:#38bdf8;}
  .lbl{font-size:0.8rem;color:#94a3b8;text-transform:uppercase;}
  table{width:100%;border-collapse:collapse;font-size:0.86rem;}
  th,td{text-align:left;padding:8px;border-bottom:1px solid #253047;}
  .badge{padding:2px 8px;border-radius:999px;background:rgba(239,68,68,.2);color:#f87171;font-weight:700;font-size:0.75rem;}
</style></head>
<body><div class="wrap">
  <h1>&#128737;&#65039; Prompt Firewall — Live Local Shield</h1>
  <p style="color:#94a3b8;">Intercepting outgoing LLM prompts, masking secrets reversibly, and restoring them in responses.</p>
  <div class="grid" id="stats"></div>
  <div class="card"><h3>Recent Blocked Secrets</h3><table><thead><tr><th>Time</th><th>Type</th><th>Source</th><th>Token</th></tr></thead><tbody id="rows"></tbody></table></div>
</div>
<script>
async function refresh(){
  const s = await (await fetch('/api/stats')).json();
  document.getElementById('stats').innerHTML =
    '<div class="card"><div class="val">'+s.totalRedactions+'</div><div class="lbl">Secrets Blocked</div></div>' +
    '<div class="card"><div class="val">'+s.uniqueSecretsMasked+'</div><div class="lbl">Unique Vault Tokens</div></div>';
  document.getElementById('rows').innerHTML = s.recentEvents.map(e =>
    '<tr><td>'+e.ts.slice(11,19)+'</td><td><span class="badge">'+e.type+'</span></td><td>'+e.source+'</td><td><code>'+e.token+'</code></td></tr>'
  ).join('') || '<tr><td colspan="4">No secrets intercepted yet.</td></tr>';
}
refresh(); setInterval(refresh, 2000);
</script></body></html>`;

function startProxy({ port = 4100, upstream = 'https://api.openai.com' } = {}) {
  const vault = new SecretVault();
  const targetBase = new URL(upstream);

  const server = http.createServer((req, res) => {
    if (req.url === '/ui' || req.url === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end(DASHBOARD_HTML);
    }
    if (req.url === '/api/stats') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(vault.stats()));
    }

    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      let bodyBuf = Buffer.concat(chunks);
      const ct = req.headers['content-type'] || '';
      if (ct.includes('application/json') && bodyBuf.length) {
        try {
          const parsed = JSON.parse(bodyBuf.toString('utf8'));
          const masked = vault.maskObject(parsed, req.url);
          bodyBuf = Buffer.from(JSON.stringify(masked.value), 'utf8');
        } catch {}
      }

      const headers = { ...req.headers, host: targetBase.host, 'content-length': bodyBuf.length };
      const client = targetBase.protocol === 'https:' ? https : http;
      const upReq = client.request({
        hostname: targetBase.hostname,
        port: targetBase.port || (targetBase.protocol === 'https:' ? 443 : 80),
        path: req.url,
        method: req.method,
        headers
      }, (upRes) => {
        const outHeaders = { ...upRes.headers };
        delete outHeaders['content-length'];
        res.writeHead(upRes.statusCode, outHeaders);
        upRes.on('data', chunk => {
          const text = chunk.toString('utf8');
          res.write(vault.unmaskText(text));
        });
        upRes.on('end', () => res.end());
      });

      upReq.on('error', err => {
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Upstream error: ' + err.message }));
      });
      upReq.end(bodyBuf);
    });
  });

  return { server, vault, listen: () => new Promise(r => server.listen(port, '127.0.0.1', r)) };
}

module.exports = { startProxy };
