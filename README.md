# PhishGuard

A free, browser-only phishing email screening tool built for staff who aren't
cybersecurity-inclined. Paste an email, get a plain-language verdict — Cleared,
Review Required, or Flagged — with the reasons spelled out.

## What it actually checks (not an AI wrapper)

- **Sender identity** — flags an "official-sounding" display name sent from a
  free email provider (Gmail, Yahoo, etc.) instead of the real organisation domain
- **Lookalike domains** — string-similarity scoring (Levenshtein distance) against
  your organisation's real domain(s), catches things like `enegy-gov.ng`
- **Reply-To / Return-Path mismatches**
- **SPF / DKIM / DMARC** — read directly from the email's `Authentication-Results` header
- **Pressure language** — detects clusters of urgency phrases ("act now", "verify immediately")
- **Link inspection** — raw IPs, `@` tricks, punycode, URL shorteners, non-HTTPS,
  and lookalike-domain links

Everything runs client-side in JavaScript. No email content is ever sent to a
server, logged, or stored — nothing to pay for, nothing to secure on the backend.

## Run it locally

```bash
npm install
npm run dev
```

Then open http://localhost:3000

## Deploy for free on Vercel

1. Push this folder to a GitHub repository (public or private).
2. Go to https://vercel.com and sign in with your GitHub account (free).
3. Click **Add New → Project**, select this repository.
4. Vercel auto-detects Next.js — leave all settings as default.
5. Click **Deploy**. You'll get a free `*.vercel.app` URL in about a minute.

No environment variables, no database, and no paid plan are required. Vercel's
free (Hobby) tier comfortably covers a small internal tool like this.

## Customising for your organisation

Open `app/page.js` and update the default placeholder domain, or simply have
staff type their own domain(s) into the "Your organisation's real domain(s)"
field each time — comma-separated if there's more than one (e.g. a ministry
domain and an agency sub-domain).
