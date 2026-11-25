const RULES = [
  { name: 'OPENAI_KEY', rx: /\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}\b/g },
  { name: 'ANTHROPIC_KEY', rx: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  { name: 'GITHUB_TOKEN', rx: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g },
  { name: 'AWS_ACCESS_KEY', rx: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'STRIPE_KEY', rx: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  { name: 'JWT_TOKEN', rx: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  { name: 'PRIVATE_KEY', rx: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
  { name: 'DB_URI', rx: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s"'`]+/gi },
  { name: 'ENV_SECRET', rx: /\b([A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|API_KEY|ACCESS_TOKEN|PRIVATE_KEY)[A-Z0-9_]*)\s*=\s*["']?([^\s"'\r\n]{8,})["']?/g },
  { name: 'EMAIL', rx: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g }
];

function shannonEntropy(str) {
  const counts = {};
  for (const ch of str) counts[ch] = (counts[ch] || 0) + 1;
  let ent = 0;
  for (const c of Object.values(counts)) {
    const p = c / str.length;
    ent -= p * Math.log2(p);
  }
  return ent;
}

class SecretVault {
  constructor() {
    this.forward = new Map(); // original -> token
    this.reverse = new Map(); // token -> original
    this.counts = {};
    this.events = [];
  }

  maskText(text, source = 'prompt') {
    if (typeof text !== 'string' || !text) return { text, hits: 0 };
    let out = text;
    let hits = 0;

    const getToken = (type, original) => {
      if (this.forward.has(original)) return this.forward.get(original);
      this.counts[type] = (this.counts[type] || 0) + 1;
      const token = `{{PF_${type}_${this.counts[type]}}}`;
      this.forward.set(original, token);
      this.reverse.set(token, original);
      return token;
    };

    for (const rule of RULES) {
      out = out.replace(rule.rx, (...args) => {
        const match = args[0];
        if (rule.name === 'ENV_SECRET') {
          const key = args[1], val = args[2];
          const tok = getToken('ENV_SECRET', val);
          hits++;
          this.events.unshift({ ts: new Date().toISOString(), type: rule.name, source, token: tok });
          return `${key}=${tok}`;
        }
        const tok = getToken(rule.name, match);
        hits++;
        this.events.unshift({ ts: new Date().toISOString(), type: rule.name, source, token: tok });
        return tok;
      });
    }

    // High-entropy token catch-all (32+ chars alphanumeric/symbol strings)
    out = out.replace(/\b[A-Za-z0-9+/=_-]{32,}\b/g, (word) => {
      if (word.startsWith('{{PF_') || /^[a-z]+$/i.test(word)) return word;
      if (shannonEntropy(word) >= 4.2) {
        const tok = getToken('HIGH_ENTROPY', word);
        hits++;
        this.events.unshift({ ts: new Date().toISOString(), type: 'HIGH_ENTROPY', source, token: tok });
        return tok;
      }
      return word;
    });

    if (this.events.length > 200) this.events.length = 200;
    return { text: out, hits };
  }

  maskObject(val, source = 'proxy') {
    if (typeof val === 'string') return this.maskText(val, source);
    if (Array.isArray(val)) {
      let hits = 0;
      const arr = val.map(v => { const r = this.maskObject(v, source); hits += r.hits; return r.text !== undefined ? r.text : r.value; });
      return { value: arr, hits };
    }
    if (val && typeof val === 'object') {
      let hits = 0;
      const obj = {};
      for (const [k, v] of Object.entries(val)) {
        const r = this.maskObject(v, source);
        hits += r.hits;
        obj[k] = r.text !== undefined ? r.text : r.value;
      }
      return { value: obj, hits };
    }
    return { value: val, hits: 0 };
  }

  unmaskText(text) {
    if (typeof text !== 'string' || !text.includes('{{PF_')) return text;
    let out = text;
    for (const [tok, orig] of this.reverse.entries()) {
      out = out.split(tok).join(orig);
    }
    return out;
  }

  stats() {
    return {
      uniqueSecretsMasked: this.reverse.size,
      totalRedactions: Object.values(this.counts).reduce((a, b) => a + b, 0),
      byType: this.counts,
      recentEvents: this.events.slice(0, 30)
    };
  }
}

module.exports = { SecretVault, shannonEntropy };
