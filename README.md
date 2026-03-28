# oai-x

This repository can now:

- register Codex/OpenAI accounts and persist token fields into PostgreSQL
- import existing `token_*.json` files into PostgreSQL
- expose a `/v1/responses` proxy that reads Codex credentials from PostgreSQL instead of a config file
- auto-cool down quota-exhausted Codex accounts and retry the next available account
- auto-start `oai-x.py` in the background when available Codex accounts fall below a threshold

## Environment

```bash
export DATABASE_URL='postgresql://postgres:postgres@127.0.0.1:5432/oai_x'
export SERVICE_API_KEYS='your-service-key'
export MIN_AVAILABLE_CODEX_TOKENS='50'
```

Optional:

```bash
export CODEX_BASE_URL='https://chatgpt.com/backend-api/codex'
export TOKEN_POOL_CHECK_INTERVAL_SECONDS='15'
export OAI_X_REPLENISH_ARGS='--proxy http://127.0.0.1:7890 --mail-provider tempmail'
```

If `CODEX_BASE_URL` is unset, the proxy defaults to:

```text
https://chatgpt.com/backend-api/codex/responses
```

## Save new registrations into PostgreSQL

```bash
python3 oai-x.py --storage-mode db --database-url "$DATABASE_URL"
```

You can still keep files as well:

```bash
python3 oai-x.py --storage-mode both --database-url "$DATABASE_URL"
```

## Import old token files

```bash
python3 import_tokens.py --database-url "$DATABASE_URL" 'token_*.json'
```

## Run the `/v1/responses` proxy

```bash
uvicorn api_server:app --host 0.0.0.0 --port 8000
```

## Docker Compose

```bash
export SERVICE_API_KEYS='your-service-key'
export OAI_X_REPLENISH_ARGS='--proxy http://host.docker.internal:7890 --mail-provider tempmail'
docker compose up -d --build
```

Default services:

- `gateway`: FastAPI `/v1/responses` proxy on port `8000`
- `postgres`: PostgreSQL 16 with a named data volume

Useful overrides:

```bash
export GATEWAY_PORT='8000'
export POSTGRES_DB='oai_x'
export POSTGRES_USER='oai_x'
export POSTGRES_PASSWORD='strong-password'
export MIN_AVAILABLE_CODEX_TOKENS='50'
export TOKEN_POOL_CHECK_INTERVAL_SECONDS='15'
```

## Gateway automation

- The gateway only selects available accounts: `is_active=true` and `cooldown_until` not in the future.
- If Codex returns `429` with `error.type=usage_limit_reached`, the account is cooled down for `resets_in_seconds` and the gateway retries the next available account automatically.
- If Codex returns `402 {"detail":{"code":"deactivated_workspace"}}` or `401` with `error.code=account_deactivated`, the account is permanently disabled in PostgreSQL and will never be used again.
- If available accounts are below `MIN_AVAILABLE_CODEX_TOKENS` (default `50`), the gateway asynchronously starts:

```bash
python oai-x.py --storage-mode db --once --database-url "$DATABASE_URL"
```

- The auto-fill process is backgrounded and does not block user requests.
- You can fully override the fill command with `OAI_X_REPLENISH_CMD`, or append extra registration args with `OAI_X_REPLENISH_ARGS`.

## Health check

```bash
curl http://127.0.0.1:8000/healthz
```
