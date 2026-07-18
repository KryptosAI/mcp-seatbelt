# --identify Pipeline: From Opt-in to Outreach

## Flow

1. User runs `mcp-observatory <command> --identify dev@company.com`
2. Email is stored in-memory for the session, validated against email regex
3. One-time thank-you message printed to stderr (once per session)
4. All subsequent telemetry events include `identifiedEmail` in the payload
5. Telemetry worker stores the `identified_email` column in D1
6. `scripts/telemetry-company-intelligence.ts` extracts the domain from `identified_email` / `opted_in_email` and includes it as `opted_in_email` evidence in company matching

## Enterprise outreach integration

The `telemetry-company-intelligence.ts` script already:
- Extracts company domains from git email, org, contact, git remote, and hostname
- Now also extracts domains from `identifiedEmail` (the `--identify` flag value)
- Ranks accounts by confidence, tier, and production signals

When a user opts in with `--identify`:
- Their email domain is attached to their telemetry events
- The intel script matches that domain to the same account as other signals
- The `evidence` field shows `opted_in_email` as a signal source
- This gives a direct contact path for enterprise outreach

## Privacy
- Email is never stored in plaintext in logs/CLI output
- Only the domain is extracted for company matching in reports
- Users can omit `--identify` to never participate
- No dark patterns: the flag is opt-in only, never prompted
