# Discord Community Setup Guide — MCP Security Platform

This guide walks through setting up a Discord server for the MCP security community (mcp-observatory, mcp-seatbelt, and related projects).

---

## Server Structure

### Channels

| Channel | Type | Purpose |
|---------|------|---------|
| `#welcome` | Announcement | Rules, getting started, links to repos and docs. Only mods can post; new members see this first. |
| `#announcements` | Announcement | New releases, security advisories, and blog posts. Only mods can post. |
| `#general` | Text | General MCP security discussion — trends, news, questions about AI agent security. |
| `#observatory` | Text | mcp-observatory support — scanner usage, results interpretation, CI integration. |
| `#seatbelt` | Text | mcp-seatbelt support — proxy setup, policy authoring, rule debugging. |
| `#showcase` | Text | What are you protecting? Share your setup, dashboards, policy configs. |
| `#contributing` | Text | PR discussion, issue triage, roadmap feedback, CLA questions. |

### Optional Channels

| Channel | Purpose |
|---------|---------|
| `#off-topic` | Casual conversation unrelated to MCP security |
| `#jobs` | MCP security and AI agent job postings |
| `#enterprise` | Enterprise/team discussions (can be role-gated) |

### Roles

| Role | Permissions |
|------|-------------|
| `@moderator` | Manage messages, kick/ban, manage channels |
| `@maintainer` | Post in announcement channels, manage threads |
| `@contributor` | Recognized open-source contributors |
| `@community` | Default role for all members |

---

## Suggested Rules

Post these in `#welcome`:

1. **Be respectful.** No harassment, hate speech, or personal attacks. Assume good intent.
2. **Stay on topic.** Keep discussions in the appropriate channels. MCP security and AI agent tooling are the focus.
3. **No spam or self-promotion.** Share your projects in `#showcase` — not via DMs or in unrelated threads.
4. **No unsolicited DMs.** Do not DM members without their consent. Report unwanted DMs to moderators.
5. **Search before asking.** Check pinned messages and use Discord search before posting support questions.
6. **No security vulnerability disclosure in public channels.** Use the project's `SECURITY.md` process or DM a maintainer.
7. **Follow Discord's [Terms of Service](https://discord.com/terms) and [Community Guidelines](https://discord.com/guidelines).**

---

## Server Settings

1. **Community Server** — Enable in Server Settings > Community. This unlocks welcome screen, server insights, and the Membership Screening feature.
2. **Welcome Screen** — Enable and display `#welcome`, `#general`, `#showcase` as starting channels.
3. **Membership Screening** — Enable with a simple checkbox: "I agree to follow the server rules."
4. **Verification Level** — Set to "Email verification" to reduce spam accounts.
5. **Explicit Media Content Filter** — Set to "Scan messages from all members."
6. **Auto-moderation** — Enable Discord's built-in auto-mod for suspicious content, spam, and harmful links.

---

## Adding Discord to README Badges

Add this badge to the top of each project's README alongside existing badges:

```markdown
[![Discord](https://img.shields.io/discord/YOUR_SERVER_ID?label=Discord&logo=discord&color=5865F2)](https://discord.gg/YOUR_INVITE_CODE)
```

Replace `YOUR_SERVER_ID` and `YOUR_INVITE_CODE` with your actual values after creating the server.

To find your Server ID:
1. Enable Developer Mode (User Settings > Advanced > Developer Mode)
2. Right-click your server icon > Copy ID

To create an invite link:
1. Right-click a channel > Invite People
2. Create a link that never expires

---

## Invite Link Placeholder

Once the server is created, the invite link will be:

```
https://discord.gg/<invite-code>
```

**Action needed:** Create the Discord server, then update this link in all project READMEs, the landing page, and social profiles.
