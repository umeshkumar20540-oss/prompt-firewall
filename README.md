# 🛡️ Prompt Firewall

**Stop leaking `.env` secrets, API keys, JWTs, and PII to cloud LLMs.**  
Zero-dependency local reversible firewall proxy, CLI scanner, and **MCP Server** for Claude Code, Cursor, Antigravity, Codex, and custom AI SDKs.

## Why Prompt Firewall?
```mermaid
flowchart LR
  A[AI Agent / Cursor / SDK] -->|Raw Prompt with sk_live_...| B[Prompt Firewall :4100]
  B -->|Masks to {{PF_STRIPE_KEY_1}}| C[OpenAI / Anthropic / Gemini]
  C -->|Response with {{PF_STRIPE_KEY_1}}| B
  B -->|Restores real key locally| A
```

- **Reversible Token Vault**: Replaces secrets before leaving your machine and restores them in responses so generated code still works.
- **Zero External Dependencies**: Pure Node.js—no Python/Docker bloat required.
- **Live Local Dashboard**: Inspect blocked secrets in real time at `http://127.0.0.1:4100/ui`.
- **MCP Server Included**: Works natively as an MCP tool inside AI IDEs.

## Quickstart
```bash
npx prompt-firewall start
# Point your OpenAI/LLM SDK baseURL to http://127.0.0.1:4100
```

## MCP Configuration
```json
{
  "mcpServers": {
    "prompt-firewall": {
      "command": "npx",
      "args": ["prompt-firewall", "mcp"]
    }
  }
}
```

## License
MIT — Built for the open-source developer community. More free privacy-first tools at [minimaxtools.com](https://minimaxtools.com).
