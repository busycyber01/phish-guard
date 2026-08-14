"use client";

import { useState } from "react";
import { analyzeEmail } from "../lib/analyzer";

const TIPS = [
  "Hover over a link before clicking — the real address shows at the bottom of most email apps.",
  "A genuine ministry email will never ask you to \u201cconfirm your password\u201d by replying or clicking a link.",
  "Check the sender's full email address, not just the display name — anyone can type \u201cIT Support.\u201d",
  "Urgency is a tactic. Real deadlines rarely require you to act in the next 10 minutes.",
  "When in doubt, contact the sender through a phone number or channel you already know — not one from the email.",
];

const VERDICT_COPY = {
  safe: { label: "Cleared", sub: "No significant red flags found" },
  suspicious: { label: "Review Required", sub: "Some red flags — proceed carefully" },
  dangerous: { label: "Flagged", sub: "Multiple strong red flags — do not click or reply" },
};

const EXHIBIT_LETTERS = "ABCDEFGH".split("");

export default function Page() {
  const [raw, setRaw] = useState("");
  const [domains, setDomains] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [caseCount, setCaseCount] = useState(0);

  const tip = TIPS[caseCount % TIPS.length];

  function handleCheck() {
    setError("");
    if (!raw.trim()) {
      setError("Paste an email's full source (or at least the body) before screening.");
      return;
    }
    const res = analyzeEmail(raw, domains);
    setResult(res);
    setCaseCount((c) => c + 1);
  }

  function handleClear() {
    setRaw("");
    setDomains("");
    setResult(null);
    setError("");
  }

  const verdict = result ? VERDICT_COPY[result.verdict] : null;

  return (
    <div className="wrap">
      <header className="masthead">
        <div className="wordmark">
          Phish<em>Guard</em>
        </div>
        <div className="masthead-meta">
          Internal Screening Tool
          <br />
          Ministry of Energy
        </div>
      </header>

      <p className="tagline">
        Paste a suspicious email and get a plain-language verdict — no cybersecurity
        background needed. Built for staff who just want to know: is this safe to click?
      </p>

      <span className="privacy-note">
        <span className="dot" /> Runs entirely in your browser — nothing is uploaded or stored
      </span>

      <div className="field">
        <label className="field-label" htmlFor="raw">
          Email content to screen
        </label>
        <textarea
          id="raw"
          value={raw}
          onChange={(e) => setRaw(e.target.value)}
          placeholder={`Paste the email here. For the best result, paste the full original source:\n\nGmail: Open the email \u2192 three dots (\u22ee) \u2192 "Show original" \u2192 copy all\nOutlook: Open the email \u2192 three dots \u2192 "View message source"\n\nA plain copy-paste of the visible email also works, just with fewer checks available.`}
        />
        <p className="field-hint">
          Full source unlocks sender authentication checks (SPF/DKIM/DMARC). A plain paste still
          runs link and language checks.
        </p>
      </div>

      <div className="field">
        <label className="field-label" htmlFor="domains">
          Your organisation's real domain(s), comma separated
        </label>
        <input
          id="domains"
          type="text"
          value={domains}
          onChange={(e) => setDomains(e.target.value)}
          placeholder="e.g. energy.gov.ng"
        />
        <p className="field-hint">
          Optional, but this is what catches lookalike domains like "energy-gov.ng" or
          "enegy.gov.ng".
        </p>
      </div>

      <div className="actions">
        <button className="btn-screen" onClick={handleCheck}>
          Screen this email
        </button>
        {(raw || result) && (
          <button className="btn-clear" onClick={handleClear}>
            Clear
          </button>
        )}
      </div>
      {error && <p className="error-note">{error}</p>}

      {result && (
        <section className="results">
          <div className="case-row">
            <div>
              <div className="case-id">
                CASE No. {String(caseCount).padStart(4, "0")} — SCREENED{" "}
                {new Date().toLocaleDateString()}
              </div>
              <div className={`stamp ${result.verdict}`}>{verdict.label}</div>
              <div className="stamp-sub">{verdict.sub}</div>
            </div>
            <div style={{ textAlign: "right" }}>
              <div className="score-num">{result.score}</div>
              <div className="score-label">Risk score / 100</div>
            </div>
          </div>

          <h2 className="section-title">The evidence</h2>
          {result.findings.length === 0 ? (
            <p className="no-findings">
              No red flags were detected by any check. Still, if something about this email
              feels off, trust that instinct and verify through a separate channel.
            </p>
          ) : (
            result.findings.map((f, i) => (
              <div className="exhibit" key={f.id}>
                <div className="exhibit-tag">Exhibit {EXHIBIT_LETTERS[i] || i + 1}</div>
                <div>
                  <p className="exhibit-title">{f.title}</p>
                  <p className="exhibit-detail">{f.detail}</p>
                </div>
                <span className={`severity-pill severity-${f.severity}`}>{f.severity}</span>
              </div>
            ))
          )}

          {result.urls.length > 0 && (
            <>
              <h2 className="section-title">Link breakdown</h2>
              <div className="url-table">
                {result.urls.map((u, i) => (
                  <div className="url-row" key={i}>
                    <div className="url-link">{u.url}</div>
                    {u.flags.length > 0 ? (
                      <ul className="url-flags">
                        {u.flags.map((f, j) => (
                          <li key={j}>
                            <span className={`severity-pill severity-${f.severity}`}>
                              {f.severity}
                            </span>
                            <span>{f.label}</span>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="field-hint" style={{ marginTop: 8 }}>
                        No flags on this link.
                      </p>
                    )}
                  </div>
                ))}
              </div>
            </>
          )}
        </section>
      )}

      <div className="sidebar-tip">
        <strong>Quick tip</strong>
        <p>{tip}</p>
      </div>

      <footer>
        PhishGuard — internal pilot tool. No account, no tracking, no cost to run or host.
      </footer>
    </div>
  );
}
