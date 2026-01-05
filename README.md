# AntiProxy

Rust-based multi-protocol AI proxy with a web console.

## Features
- OpenAI-compatible endpoints (`/v1/chat/completions`, `/v1/completions`, `/v1/responses`)
- Anthropic-compatible endpoint (`/v1/messages`)
- Gemini-compatible endpoints (`/v1beta/models/...`)
- Web console for account management, mappings, and status
- Configurable API key auth

## Quick Start
1. Install Rust (stable toolchain).
2. Run the server:
   ```bash
   cargo run
   ```
3. Open the web console: `http://localhost:8045`

## Configuration
`web_config.json` is created automatically on first run if missing. You can adjust:
- `port`, `allow_lan_access`, `auth_mode`, `api_key`
- `anthropic_mapping`, `openai_mapping`, `custom_mapping`

Environment overrides:
- `ANTI_PROXY_BIND` (bind address)
- `ANTI_PROXY_ALLOW_LAN` (`1`/`true`/`yes`/`on` to allow LAN)
- `ANTI_PROXY_ENABLED` (`1`/`true`/`yes`/`on` to force enable)

## Notes
- If auth is enabled, send the API key via `Authorization: Bearer <key>` or `x-api-key`.
