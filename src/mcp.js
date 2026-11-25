const readline = require('readline');
const fs = require('fs');
const { SecretVault } = require('./scanner');

function startMcp() {
  const vault = new SecretVault();
  const rl = readline.createInterface({ input: process.stdin, terminal: false });

  const send = obj => process.stdout.write(JSON.stringify(obj) + '\n');

  rl.on('line', line => {
    if (!line.trim()) return;
    let req;
    try { req = JSON.parse(line); } catch { return; }

    if (req.method === 'initialize') {
      return send({
        jsonrpc: '2.0', id: req.id,
        result: { protocolVersion: '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'prompt-firewall', version: '1.0.0' } }
      });
    }
    if (req.method === 'tools/list') {
      return send({
        jsonrpc: '2.0', id: req.id,
        result: {
          tools: [
            {
              name: 'redact_secrets',
              description: 'Scan and reversibly mask API keys, JWTs, passwords, and PII before sending text to an LLM.',
              inputSchema: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'] }
            },
            {
              name: 'scan_file',
              description: 'Scan a local file for leaked secrets and return redacted safe content.',
              inputSchema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] }
            }
          ]
        }
      });
    }
    if (req.method === 'tools/call') {
      const { name, arguments: args = {} } = req.params || {};
      if (name === 'redact_secrets') {
        const res = vault.maskText(args.text || '', 'mcp');
        return send({ jsonrpc: '2.0', id: req.id, result: { content: [{ type: 'text', text: JSON.stringify({ hits: res.hits, redacted: res.text }, null, 2) }] } });
      }
      if (name === 'scan_file') {
        const raw = fs.readFileSync(args.path, 'utf8');
        const res = vault.maskText(raw, args.path);
        return send({ jsonrpc: '2.0', id: req.id, result: { content: [{ type: 'text', text: JSON.stringify({ hits: res.hits, redacted: res.text }, null, 2) }] } });
      }
    }
    if (req.id !== undefined) {
      send({ jsonrpc: '2.0', id: req.id, error: { code: -32601, message: 'Method not found' } });
    }
  });
}

module.exports = { startMcp };
