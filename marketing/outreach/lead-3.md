# Lead 3 — High-Intent Power User

**Session ID:** `8439f79b-253f-4500-bfa7-67c693573df6`

## Profile

| Metric | Value |
|---|---|
| Total events | 191 |
| Active days | July 13 – July 15, 2026 (3 days) |
| Platform | macOS arm64, Node v22 |
| Versions used | 1.31.0, 1.32.1 |
| Stage | `paid_intent` |
| Fingerprint | `6da64cf0365c5aff` |

## Usage Pattern

This session is intense and compressed — 191 events across just 3 days, using 14 distinct commands. The `paid_intent` stage flag suggests enterprise purchase intent.

**Top commands:**
- `run` — 36
- `setup-ci` — 35
- `diff` — 32
- `audit` — 22
- `test` — 20
- `attack-sim` — 14
- `score` — 8
- `risk-graph` — 6
- `receipt` — 4
- `ci-report` — 4
- `serve` — 3
- `cloud` — 3
- `telemetry` — 2
- `history` — 2

## Important Discovery

**The `git_email` field contains `william.weishuhn3@gmail.com` and the hostname is `Williams-Laptop.local`.** This is William Weishuhn's own session — the founder's laptop, not an external enterprise lead.

The `paid_intent` stage and machine fingerprint match internal usage, likely testing or dogfooding the enterprise flow.

## Email Draft

---

**SKIPPED** — This session belongs to `william.weishuhn3@gmail.com` (hostname: `Williams-Laptop.local`). It is not an external enterprise lead. No outreach needed.

---

**Note:** This session was flagged by the database query as a top-3 external lead because its `is_first_party` column is `0`. This may indicate a classification bug where the author's local sessions aren't consistently tagged as first-party. The `raw_json` payload reveals the true identity via `git_email` and `hostname`.
