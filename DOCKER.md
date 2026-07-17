# Docker Usage

## Pull from GitHub Container Registry

```bash
docker pull ghcr.io/kryptosai/mcp-seatbelt:latest
```

## Run the Proxy

```bash
docker run -p 9420:9420 -p 9421:9421 \
  -v $(pwd)/.mcp-seatbelt:/app/.mcp-seatbelt \
  ghcr.io/kryptosai/mcp-seatbelt:latest proxy
```

## Build Locally

```bash
npm run build
docker build -t mcp-seatbelt:local .
docker run -p 9420:9420 -p 9421:9421 \
  -v $(pwd)/.mcp-seatbelt:/app/.mcp-seatbelt \
  mcp-seatbelt:local proxy
```

## Available Tags

- `latest` — latest release
- `v0.3.0` — version-pinned

## Image URL

```
ghcr.io/kryptosai/mcp-seatbelt
```
