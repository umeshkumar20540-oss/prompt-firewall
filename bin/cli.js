#!/usr/bin/env node
const fs = require('fs');
const { SecretVault } = require('../src/scanner');
const { startProxy } = require('../src/proxy');
const { startMcp } = require('../src/mcp');

const [cmd, arg] = process.argv.slice(2);

if (cmd === 'start') {
  const port = parseInt(process.env.PORT || '4100', 10);
  const upstream = process.env.UPSTREAM_URL || 'https://api.openai.com';
  startProxy({ port, upstream }).listen().then(() => {
    console.log(`Prompt Firewall listening on http://127.0.0.1:${port}`);
    console.log(`Dashboard: http://127.0.0.1:${port}/ui -> Upstream: ${upstream}`);
  });
} else if (cmd === 'mcp') {
  startMcp();
} else if (cmd === 'scan' && arg) {
  const vault = new SecretVault();
  const res = vault.maskText(fs.readFileSync(arg, 'utf8'), arg);
  console.log(`Secrets detected: ${res.hits}`);
  console.log(res.text);
} else {
  console.log('Usage:\n  prompt-firewall start          # Start reversible LLM proxy + UI\n  prompt-firewall mcp            # Start MCP stdio server\n  prompt-firewall scan <file>    # Scan and redact a file');
}
