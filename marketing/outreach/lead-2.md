# Lead 2 — CI Pipeline Power User (Anonymous)

**Session ID:** `unknown` (multiple CI pipeline runs with no persisted session)

## Profile

| Metric | Value |
|---|---|
| Total events | 390 |
| Active days | ~15 (July 1 – July 15, 2026) |
| Source | 388 external_ci, 2 local |
| Versions used | 0.26.1 through 1.32.1 |
| CI provider | GitHub Actions |

## Usage Pattern

This lead is iterating heavily on CI pipeline setup. Nearly all events (388 of 390) are `setup-ci`, plus one `test` and one `curl_test`. They've upgraded across 8 versions in 15 days, suggesting active iteration on a CI integration. The `target_ids` field shows `example-server` — they may be prototyping before pointing at real servers.

The session ID is `unknown` across all events, meaning CI pipelines aren't persisting a session identifier. Events come from `external_ci` telemetry source (GitHub Actions).

**No identifying data:** No email, GitHub repository, actor, hostname, or fingerprint available.

## Email Draft

---

Subject: Quick question about your mcp-observatory CI setup

Hi,

I noticed you've been actively iterating on an mcp-observatory CI pipeline setup over the past couple weeks — you've run `setup-ci` nearly 400 times across 8 version upgrades in GitHub Actions. That kind of iteration signals a real production integration effort.

I'm the founder and I'd love a 15-minute chat about what's been going well (or not). No pitch — just trying to understand how teams are getting mcp-observatory into their CI pipelines so I can make it better.

If you hit any friction with the CI setup or want to talk about our hosted enterprise tier for private reporting, I'm all ears.

Thanks,
William
william@banksey.com

---

**Note:** Session ID is `unknown` — no identifying data. Cannot send until user opts in.
