# Outreach Guide — mcp-observatory Enterprise Leads

## Data Source

Lead profiles were generated from the live mcp-observatory telemetry database:

```
.mcp-observatory-metrics/observatory.sqlite
```

Query: top 3 sessions by event count, filtered to `is_first_party=0`, minimum 50 events.

## Privacy Status

**All leads are anonymous.** The telemetry database contains session IDs, command usage, platform info, and version history — but no email addresses, GitHub usernames, or contact information for any of these leads.

- Lead 1 (`20226c8c-...`): 12,512 events, heavy production user — no identity data
- Lead 2 (`unknown`): 390 events, CI pipeline iteration — no identity data
- Lead 3 (`8439f79b-...`): 191 events — **identified as internal (william.weishuhn3@gmail.com, Williams-Laptop.local)** via raw JSON payload; excluded from outreach

## How to Reach These Users

### Option A: `--identify` Opt-In (Not Yet Built)

The intended path is a `--identify` flag that lets users voluntarily share their email for enterprise conversations. This doesn't exist yet. Until it's built:

1. Add a `--identify <email>` CLI option
2. Store `optedInEmail` in the telemetry row
3. Re-query the database filtering for opted-in sessions
4. Use the email address from the opt-in record

### Option B: GitHub Discussions (Recommended Now)

Post in the mcp-observatory GitHub Discussions inviting enterprise users to reach out:

```
Title: Building the enterprise tier — would love to chat

Hey all, I'm working on a hosted enterprise tier for mcp-observatory
(private CI reporting, team dashboards, SSO). If you're using
mcp-observatory in production and would be open to a 15-minute
feedback call, drop a comment or email me at william@banksey.com.

No pitch — I genuinely want to understand your workflow.
```

This is public, opt-in, and respects user privacy.

### Option C: Direct Outreach (Not Recommended)

Do **not** attempt to identify users via IP logs, GitHub activity heuristics, or CI metadata. The telemetry is intentionally anonymous and reaching out without explicit opt-in would violate user trust and likely privacy regulations (GDPR, etc.).

## Lead 3 — Classification Bug

Lead 3 (`8439f79b-...`) has `is_first_party=0` in the database column, but the raw JSON payload confirms it's `william.weishuhn3@gmail.com` on `Williams-Laptop.local`. This suggests the first-party classification logic isn't catching all of the author's local sessions. Fix by ensuring the `is_first_party` column is set to `1` when:

- `git_email` matches known author emails, or
- `hostname` matches known author hostnames, or
- The session originates from a recognized machine fingerprint

## Files

| File | Description |
|---|---|
| `lead-1.md` | Heavy power user (12,512 events, 4-month history) |
| `lead-2.md` | CI pipeline iterating user (390 events, unknown session) |
| `lead-3.md` | Internal session — excluded from outreach |
| `README.md` | This guide |
