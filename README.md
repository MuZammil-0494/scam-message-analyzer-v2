# Scam Message Analyzer v2

A fully **client-side** PWA that pastes in a suspicious SMS, WhatsApp message or
email and instantly returns a **0–100 risk score**, the **named attack type**
(e.g. *fake bank KYC*, *UPI refund fraud*, *CEO whaling*, *sextortion*), and a
plain-language explanation of **every point added**. No data ever leaves the
device unless you opt in to the AI second opinion.

Live demo: https://muzammil-0494.github.io/scam-message-analyzer-v2/

---

## Features

- **Two analyzers** — one for SMS/WhatsApp messages, one for emails
  (sender check, reply-to check, SPF/DKIM/DMARC hints, attachment warnings).
- **Risk score 0–100** with levels: Safe (0–24), Low (25–49), Medium (50–74),
  High (75–89), Critical (90–100). Always shown as icon + text, never colour alone.
- **23 named attack types**, including India-specific ones:
  Digital arrest / police impersonation, KYC phishing, UPI collect-request fraud,
  electricity-disconnection scams, fake courier customs fees, OTP theft/vishing,
  and international patterns (sextortion, romance scam, BEC invoice fraud, CEO whaling…).
- **Explainable scoring** — the results dashboard breaks down exactly which
  phrases, links and sender traits added points, with the offending text
  highlighted in the message.
- **Link forensics** — every URL is inspected: http vs https, IP addresses,
  suspicious TLDs, look-alike domains, brand words smuggled into hosts,
  link shorteners, punycode/homograph tricks.
- **Batch mode** — analyse several messages at once, separated by `---`.
- **History & statistics** — last 60 results saved locally, with a simple
  dashboard and a "clear all data" button.
- **Privacy** — everything runs in your browser. Your text, history and API key
  stay in `localStorage`; nothing is uploaded.
- **Optional AI second opinion** — paste your own Gemini or Anthropic API key
  (stored only in your browser) to get a machine-read answer alongside the
  rule engine. Never required, never bundled with a key.
- **i18n** — English (default), Hindi and Telugu dictionaries with graceful
  fallback to English for untranslated strings.
- **Accessible & themeable** — dark/light themes, keyboard-focussable, WCAG-style
  contrast, works offline after first visit (installable PWA).

---

## How the scoring works (transparency)

Everything lives in `js/rules.js` and `js/scoring.js` — you can read or edit every
rule. There is no machine-learning black box.

1. **Signals** — ~18 pattern families score phrases like
   *"act immediately"*, *"pay a processing fee to release a refund"*,
   *"keep it between us"*, *"transfer to this safe account"*, or
   *"reply with this OTP"*. Each match adds its documented weight.
2. **Links** — each URL is inspected (see Features) and flagged points.
3. **Email checks** — sender/reply-to mismatch, look-alike or free-mail domains,
   SPF/DKIM/DMARC failures, dangerous attachments.
4. **Attack confidence** — the text is matched against ~23 attack profiles.
   Each profile has its own weighted patterns; when total confidence ≥ 45 the
   attack is **named** in the results and contributes up to 35 points.
5. **Reducers** — genuine-looking traits (e.g. *"do not share this OTP"*,
   *"ignore if this wasn't you"*) subtract a little and **auto-downgrade**
   credential-stealing labels, so a real OTP from your bank is not called a scam.

Final score = signals + link points + email points + attack points + reducers,
clamped to 0–100. The dashboard shows every step.

### Tuning the rules

Edit `js/rules.js`, then run the test harness:

```bash
node tests/run-tests.js
```

The corpus in `tests/samples.js` holds 31 real-looking messages (20 scams +
11 legitimate) with expected level bands and attack ids. `tests/index.html` runs
the same suite in a browser.

---

## Project structure

```
index.html              Single page: tabs, forms, samples, results, history,
                        stats, learn, settings/modals.
css/styles.css          Dark/light themes and all component styles.
js/
  i18n.js               English / Hindi / Telugu dictionaries + fallback.
  rules.js              *EDITABLE* — signals, brands, TLDs, attacks, advice, learn.
  links.js              URL extraction and inspection.
  email.js              Email-only checks (sender, reply-to, SPF/DKIM/DMARC, files).
  scoring.js            Scoring engine, reducers, highlights, levels.
  history.js            localStorage history (sma_history_v2, max 60).
  ai.js                 Optional Gemini/Anthropic second opinion.
  charts.js             SVG gauge + bar charts.
  ui.js                 Renders results, history, stats, learn, actions.
  app.js                Wiring: tabs, analyze flow, samples, theme, PWA.
tests/
  samples.js            31 test cases.
  run-tests.js          Node runner (node tests/run-tests.js).
  index.html            Browser runner.
manifest.json / service-worker.js / icons/   PWA files.
```

---

## Run locally / deploy

Any static file server works:

```bash
# local preview
python -m http.server 8080     # or: npx serve .
# open http://localhost:8080
```

Deploy to GitHub Pages:

1. Push this folder to a repo, go to **Settings → Pages**.
2. Source: **Deploy from a branch**, branch `main`, folder `/ (root)`.
3. Visit `https://<user>.github.io/<repo>/`.

The service worker caches all assets for offline use and is bumped to `v2` in this
release, so returning visitors get the new engine automatically.

---

## Privacy & API key notes

- The rule engine runs entirely offline in the browser.
- History, theme and language preferences live in `localStorage` only.
- The **AI second opinion is opt-in**: you paste your own key. It is kept in
  `localStorage` and is only sent to Google (Gemini) or Anthropic **together with
  the message text you are analysing**, and nothing else. Delete it anytime from
  Settings. If you do not want any text leaving your device, do not enable it.

---

## Disclaimer

This tool is a heuristic aid based on patterns — it is **not a guarantee**
that a message is or is not fraudulent. Real scammers constantly change their
wording. Always verify identity through official channels, never share OTPs,
and report scams to your bank / local cyber-crime authorities.