// PhishGuard analysis engine.
// Everything here runs entirely in the browser. Nothing is uploaded anywhere.

const SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
  "rebrand.ly", "cutt.ly", "shorte.st", "rb.gy", "tiny.cc", "s.id", "lnkd.in",
];

const FREE_MAIL_DOMAINS = [
  "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
  "icloud.com", "protonmail.com", "mail.com", "yandex.com", "zoho.com",
];

const URGENCY_PHRASES = [
  "act now", "immediately", "urgent action", "verify your account",
  "suspended", "click here", "confirm your password", "limited time",
  "final notice", "failure to comply", "your account will be closed",
  "unusual activity", "restricted access", "kindly verify",
];

// --- Levenshtein distance, used to catch lookalike / typosquat domains ---
function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost
      );
    }
  }
  return dp[m][n];
}

function similarityScore(a, b) {
  const dist = levenshtein(a.toLowerCase(), b.toLowerCase());
  const maxLen = Math.max(a.length, b.length) || 1;
  return 1 - dist / maxLen; // 1 = identical
}

// --- Header parsing (handles folded/multi-line headers per RFC 5322) ---
function splitSource(raw) {
  const normalized = raw.replace(/\r\n/g, "\n");
  const idx = normalized.indexOf("\n\n");
  if (idx === -1) return { headerBlock: normalized, body: "" };
  return {
    headerBlock: normalized.slice(0, idx),
    body: normalized.slice(idx + 2),
  };
}

function parseHeaders(headerBlock) {
  const lines = headerBlock.split("\n");
  const headers = [];
  for (const line of lines) {
    if (/^\s/.test(line) && headers.length > 0) {
      headers[headers.length - 1].value += " " + line.trim();
    } else {
      const m = line.match(/^([^:]+):\s*(.*)$/);
      if (m) headers.push({ name: m[1].trim().toLowerCase(), value: m[2].trim() });
    }
  }
  return headers;
}

function getHeader(headers, name) {
  const h = headers.find((h) => h.name === name.toLowerCase());
  return h ? h.value : null;
}

// --- From / Reply-To field parsing: "Display Name <user@domain.com>" ---
function parseAddressField(value) {
  if (!value) return null;
  const match = value.match(/<([^>]+)>/);
  const email = match ? match[1].trim() : value.trim();
  const displayName = match ? value.slice(0, match.index).trim().replace(/^"|"$/g, "") : "";
  const domainMatch = email.match(/@([^@]+)$/);
  const domain = domainMatch ? domainMatch[1].toLowerCase() : null;
  return { displayName, email, domain };
}

// --- SPF / DKIM / DMARC, read straight from Authentication-Results ---
function parseAuthResults(headers) {
  const raw = getHeader(headers, "authentication-results");
  const result = { spf: "not present", dkim: "not present", dmarc: "not present", raw };
  if (!raw) return result;
  const spf = raw.match(/spf=(\w+)/i);
  const dkim = raw.match(/dkim=(\w+)/i);
  const dmarc = raw.match(/dmarc=(\w+)/i);
  if (spf) result.spf = spf[1].toLowerCase();
  if (dkim) result.dkim = dkim[1].toLowerCase();
  if (dmarc) result.dmarc = dmarc[1].toLowerCase();
  return result;
}

// --- URL extraction & inspection ---
function extractUrls(body) {
  const regex = /\bhttps?:\/\/[^\s<>"')\]]+/gi;
  const found = body.match(regex) || [];
  return [...new Set(found)];
}

function inspectUrl(rawUrl, trustedDomains) {
  const flags = [];
  let host = null;
  try {
    const u = new URL(rawUrl);
    host = u.hostname.toLowerCase();

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      flags.push({ label: "Raw IP address instead of a domain name", severity: "high" });
    }
    if (rawUrl.includes("@")) {
      flags.push({ label: "Contains an \u201c@\u201d — text before it can hide the real destination", severity: "high" });
    }
    if (host.startsWith("xn--") || host.includes(".xn--")) {
      flags.push({ label: "Uses punycode — can visually impersonate another domain", severity: "high" });
    }
    if (SHORTENERS.some((s) => host === s || host.endsWith("." + s))) {
      flags.push({ label: "Link shortener — real destination is hidden", severity: "medium" });
    }
    if (u.protocol !== "https:") {
      flags.push({ label: "Not using HTTPS", severity: "low" });
    }

    // Typosquat / lookalike check against the organisation's trusted domains
    let bestMatch = null;
    for (const trusted of trustedDomains) {
      if (!trusted) continue;
      const t = trusted.toLowerCase().trim();
      if (!t) continue;
      if (host === t || host.endsWith("." + t)) {
        bestMatch = { domain: t, score: 1, exact: true };
        break;
      }
      const score = similarityScore(host, t);
      if (!bestMatch || score > bestMatch.score) bestMatch = { domain: t, score, exact: false };
    }
    if (bestMatch && !bestMatch.exact && bestMatch.score >= 0.75) {
      flags.push({
        label: `Looks like a lookalike of "${bestMatch.domain}" (${Math.round(bestMatch.score * 100)}% similar) but isn't an exact match`,
        severity: "high",
      });
    }
  } catch {
    flags.push({ label: "Malformed link", severity: "medium" });
  }
  return { url: rawUrl, host, flags };
}

// --- Main entry point ---
export function analyzeEmail(rawSource, trustedDomainsInput) {
  const trustedDomains = (trustedDomainsInput || "")
    .split(",")
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean);

  const { headerBlock, body } = splitSource(rawSource);
  const headers = parseHeaders(headerBlock);

  const from = parseAddressField(getHeader(headers, "from"));
  const replyTo = parseAddressField(getHeader(headers, "reply-to"));
  const returnPath = parseAddressField(getHeader(headers, "return-path"));
  const auth = parseAuthResults(headers);

  const findings = [];

  // Exhibit A — sender identity
  if (from) {
    const nameLooksOfficial = /minist|govern|energy|hr\b|it support|admin|payroll|finance/i.test(
      from.displayName || ""
    );
    if (nameLooksOfficial && FREE_MAIL_DOMAINS.includes(from.domain)) {
      findings.push({
        id: "sender-freemail",
        title: "Sender identity",
        detail: `The display name ("${from.displayName}") sounds official, but the email actually comes from a free provider (${from.domain}), not an organisational domain.`,
        severity: "high",
      });
    }
    if (trustedDomains.length && from.domain) {
      const exact = trustedDomains.some((t) => from.domain === t || from.domain.endsWith("." + t));
      if (!exact) {
        let best = null;
        for (const t of trustedDomains) {
          const score = similarityScore(from.domain, t);
          if (!best || score > best.score) best = { domain: t, score };
        }
        if (best && best.score >= 0.75) {
          findings.push({
            id: "sender-lookalike",
            title: "Sender domain",
            detail: `Sender domain "${from.domain}" closely resembles "${best.domain}" (${Math.round(best.score * 100)}% match) but is not an exact match — a common impersonation trick.`,
            severity: "high",
          });
        }
      }
    }
  } else {
    findings.push({
      id: "sender-missing",
      title: "Sender identity",
      detail: "No usable \u201cFrom\u201d header was found in the pasted content.",
      severity: "low",
    });
  }

  // Exhibit B — reply-to / return-path mismatch
  if (from && replyTo && replyTo.domain && from.domain && replyTo.domain !== from.domain) {
    findings.push({
      id: "reply-to-mismatch",
      title: "Reply-To mismatch",
      detail: `Replies are routed to "${replyTo.domain}", which is different from the sending domain "${from.domain}". Genuine replies usually go back to the same domain.`,
      severity: "medium",
    });
  }
  if (from && returnPath && returnPath.domain && from.domain && returnPath.domain !== from.domain) {
    findings.push({
      id: "return-path-mismatch",
      title: "Return-Path mismatch",
      detail: `The bounce address "${returnPath.domain}" doesn't match the sending domain "${from.domain}".`,
      severity: "low",
    });
  }

  // Exhibit C — authentication results
  const authSeverity = (v) => (v === "fail" ? "high" : v === "none" || v === "not present" ? "medium" : null);
  [
    ["spf", "SPF"],
    ["dkim", "DKIM"],
    ["dmarc", "DMARC"],
  ].forEach(([key, label]) => {
    const val = auth[key];
    const sev = authSeverity(val);
    if (sev) {
      findings.push({
        id: `auth-${key}`,
        title: `${label} authentication`,
        detail: `${label} result: ${val}. ${val === "fail" ? "This email failed authentication for the claimed sending domain." : "No authentication result was found — this can mean the check wasn't performed, which is common but worth noting."}`,
        severity: sev,
      });
    }
  });

  // Exhibit D — urgency language
  const bodyLower = body.toLowerCase();
  const matchedPhrases = URGENCY_PHRASES.filter((p) => bodyLower.includes(p));
  if (matchedPhrases.length >= 2) {
    findings.push({
      id: "urgency-language",
      title: "Pressure language",
      detail: `The message uses ${matchedPhrases.length} urgency phrases (e.g. "${matchedPhrases[0]}"), a common pressure tactic to stop people thinking it through.`,
      severity: "medium",
    });
  }

  // Exhibit E — links
  const urls = extractUrls(body).map((u) => inspectUrl(u, trustedDomains));
  const urlFlagCount = urls.reduce((sum, u) => sum + u.flags.length, 0);
  if (urlFlagCount > 0) {
    const highest = urls.reduce((max, u) => {
      const worst = u.flags.reduce((w, f) => (f.severity === "high" ? "high" : w === "high" ? "high" : f.severity), "low");
      return worst === "high" ? "high" : max;
    }, "medium");
    findings.push({
      id: "link-flags",
      title: "Link analysis",
      detail: `${urls.length} link(s) found, ${urlFlagCount} flag(s) raised across them. See the link breakdown below.`,
      severity: highest,
    });
  }

  // Score aggregation
  const weights = { high: 35, medium: 15, low: 5 };
  let score = findings.reduce((s, f) => s + (weights[f.severity] || 0), 0);
  score = Math.min(100, score);

  let verdict = "safe";
  if (score >= 60) verdict = "dangerous";
  else if (score >= 25) verdict = "suspicious";

  return { verdict, score, findings, urls, from, replyTo, auth, hadHeaders: headers.length > 0 };
}
