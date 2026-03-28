import asyncio
import json
import logging
import os
import shlex
import sys
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, ConfigDict

from database import close_database, init_db
from token_store import (
    claim_next_active_token,
    get_token_counts,
    mark_token_error,
    mark_token_success,
    update_token_refresh_state,
)


logger = logging.getLogger("oai_x.api")

CODEX_OAUTH_TOKEN_URL = "https://auth.openai.com/oauth/token"
CODEX_OAUTH_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
CODEX_ACCESS_TOKEN_REFRESH_SKEW_SECONDS = 30

_oauth_cache: dict[int, dict[str, Any]] = {}
_oauth_locks: dict[int, asyncio.Lock] = {}


class ResponsesRequest(BaseModel):
    model: str
    input: Any
    stream: bool | None = None

    model_config = ConfigDict(extra="allow")


def _int_env(name: str, default: int, *, minimum: int = 0) -> int:
    raw = str(os.getenv(name, "") or "").strip()
    try:
        value = int(raw) if raw else int(default)
    except ValueError:
        value = int(default)
    return max(minimum, value)


def _min_available_codex_tokens() -> int:
    return _int_env("MIN_AVAILABLE_CODEX_TOKENS", 50, minimum=0)


def _token_pool_check_interval_seconds() -> int:
    return _int_env("TOKEN_POOL_CHECK_INTERVAL_SECONDS", 15, minimum=1)


def _max_request_account_retries() -> int:
    return _int_env("MAX_REQUEST_ACCOUNT_RETRIES", 100, minimum=1)


def _default_usage_limit_cooldown_seconds() -> int:
    return _int_env("DEFAULT_USAGE_LIMIT_COOLDOWN_SECONDS", 300, minimum=1)


def _get_service_api_keys() -> set[str]:
    raw = os.getenv("SERVICE_API_KEYS") or os.getenv("API_KEY") or ""
    return {item.strip() for item in raw.split(",") if item.strip()}


async def verify_service_api_key(http_request: Request) -> None:
    valid_keys = _get_service_api_keys()
    if not valid_keys:
        return

    header = (http_request.headers.get("Authorization") or "").strip()
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or token.strip() not in valid_keys:
        raise HTTPException(status_code=401, detail="Invalid or missing bearer token")


def _codex_responses_url() -> str:
    base = (os.getenv("CODEX_BASE_URL") or "").strip()
    if not base:
        return "https://chatgpt.com/backend-api/codex/responses"

    base = base.rstrip("/")
    if base.endswith("/v1/responses") or base.endswith("/responses"):
        return base
    return f"{base}/responses"


def _oauth_lock(token_id: int) -> asyncio.Lock:
    lock = _oauth_locks.get(token_id)
    if lock is None:
        lock = asyncio.Lock()
        _oauth_locks[token_id] = lock
    return lock


def _access_token_is_valid(access_token: str | None, expires_at: datetime | None) -> bool:
    if not access_token:
        return False
    if expires_at is None:
        return True
    now = datetime.now(timezone.utc)
    return now < (expires_at - timedelta(seconds=CODEX_ACCESS_TOKEN_REFRESH_SKEW_SECONDS))


def _decode_error_body(raw: bytes) -> str:
    try:
        return raw.decode("utf-8", errors="replace").strip()
    except Exception:
        return repr(raw)


def _extract_usage_limit_cooldown_seconds(status_code: int, error_text: str) -> int | None:
    if status_code != 429:
        return None

    try:
        payload = json.loads(error_text)
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None

    error = payload.get("error")
    if not isinstance(error, dict):
        return None

    error_type = str(error.get("type") or "").strip()
    error_message = str(error.get("message") or "").strip().lower()
    if error_type != "usage_limit_reached" and "usage limit" not in error_message:
        return None

    resets_in_seconds = error.get("resets_in_seconds")
    if resets_in_seconds is not None:
        try:
            return max(0, int(float(resets_in_seconds)))
        except Exception:
            pass

    resets_at = error.get("resets_at")
    if resets_at is not None:
        try:
            reset_at_epoch = int(float(resets_at))
            now_epoch = int(datetime.now(timezone.utc).timestamp())
            return max(0, reset_at_epoch - now_epoch)
        except Exception:
            pass

    return _default_usage_limit_cooldown_seconds()


def _is_permanent_account_disable_error(status_code: int, error_text: str) -> bool:
    if status_code not in (401, 402):
        return False

    try:
        payload = json.loads(error_text)
    except Exception:
        return False
    if not isinstance(payload, dict):
        return False

    if status_code == 402:
        detail = payload.get("detail")
        if isinstance(detail, dict):
            detail_code = str(detail.get("code") or "").strip()
            if detail_code == "deactivated_workspace":
                return True

    if status_code == 401:
        error = payload.get("error")
        if isinstance(error, dict):
            error_code = str(error.get("code") or "").strip()
            if error_code == "account_deactivated":
                return True

    return False


async def _refresh_codex_access_token(client: httpx.AsyncClient, refresh_token: str) -> dict[str, Any]:
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    data = {
        "client_id": CODEX_OAUTH_CLIENT_ID,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "scope": "openid profile email",
    }
    response = await client.post(CODEX_OAUTH_TOKEN_URL, data=data, headers=headers, timeout=30.0)
    if response.status_code != 200:
        raise HTTPException(
            status_code=401,
            detail=f"Codex token refresh failed: status {response.status_code}: {response.text}",
        )

    payload = response.json()
    access_token = str(payload.get("access_token") or "").strip()
    if not access_token:
        raise HTTPException(status_code=401, detail="Codex token refresh returned empty access_token")

    refresh_token_out = str(payload.get("refresh_token") or "").strip() or None
    expires_at = None
    expires_in = payload.get("expires_in")
    try:
        expires_in_int = int(expires_in)
        if expires_in_int > 0:
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in_int)
    except Exception:
        expires_at = None

    return {
        "access_token": access_token,
        "refresh_token": refresh_token_out,
        "expires_at": expires_at,
    }


async def _get_codex_access_token(token_row, client: httpx.AsyncClient) -> str:
    lock = _oauth_lock(token_row.id)
    async with lock:
        cache_entry = _oauth_cache.get(token_row.id) or {}
        if _access_token_is_valid(cache_entry.get("access_token"), cache_entry.get("expires_at")):
            return str(cache_entry["access_token"])

        if _access_token_is_valid(token_row.access_token, token_row.expires_at):
            _oauth_cache[token_row.id] = {
                "access_token": token_row.access_token,
                "refresh_token": token_row.refresh_token,
                "expires_at": token_row.expires_at,
            }
            return str(token_row.access_token)

        refreshed = await _refresh_codex_access_token(client, token_row.refresh_token)
        next_refresh_token = refreshed.get("refresh_token") or token_row.refresh_token
        await update_token_refresh_state(
            token_row.id,
            access_token=refreshed["access_token"],
            refresh_token=next_refresh_token,
            expires_at=refreshed.get("expires_at"),
        )
        _oauth_cache[token_row.id] = {
            "access_token": refreshed["access_token"],
            "refresh_token": next_refresh_token,
            "expires_at": refreshed.get("expires_at"),
        }
        token_row.access_token = refreshed["access_token"]
        token_row.refresh_token = next_refresh_token
        token_row.expires_at = refreshed.get("expires_at")
        return refreshed["access_token"]


def _build_upstream_headers(http_request: Request, access_token: str, account_id: str | None, stream: bool) -> dict[str, str]:
    session_id = (http_request.headers.get("Session_id") or "").strip() or str(uuid.uuid4())
    conversation_id = (http_request.headers.get("Conversation_id") or "").strip() or session_id

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
        "Openai-Beta": (http_request.headers.get("Openai-Beta") or "responses=experimental").strip(),
        "Originator": (http_request.headers.get("Originator") or "codex_cli_rs").strip(),
        "Version": (http_request.headers.get("Version") or "0.21.0").strip(),
        "Session_id": session_id,
        "Conversation_id": conversation_id,
        "User-Agent": (http_request.headers.get("User-Agent") or "codex_cli_rs/0.50.0").strip(),
        "Connection": "Keep-Alive",
        "Accept": "text/event-stream" if stream else "application/json",
    }
    if account_id:
        headers["Chatgpt-Account-Id"] = account_id
    return headers


def _sanitize_codex_payload(payload: dict[str, Any]) -> dict[str, Any]:
    payload.pop("max_output_tokens", None)
    payload.pop("previous_response_id", None)
    payload.pop("prompt_cache_retention", None)
    payload.pop("safety_identifier", None)
    payload.setdefault("instructions", "")
    return payload


def _track_background_task(app: FastAPI, coro, *, label: str) -> None:
    task = asyncio.create_task(coro, name=label)
    app.state.background_tasks.add(task)

    def _done(done_task: asyncio.Task) -> None:
        app.state.background_tasks.discard(done_task)
        try:
            done_task.result()
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("Background task failed: %s", label)

    task.add_done_callback(_done)


def _track_singleton_background_task(app: FastAPI, coro, *, label: str, state_key: str) -> None:
    existing_task = getattr(app.state, state_key, None)
    if existing_task is not None and not existing_task.done():
        return

    task = asyncio.create_task(coro, name=label)
    setattr(app.state, state_key, task)
    app.state.background_tasks.add(task)

    def _done(done_task: asyncio.Task) -> None:
        app.state.background_tasks.discard(done_task)
        if getattr(app.state, state_key, None) is done_task:
            setattr(app.state, state_key, None)
        try:
            done_task.result()
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("Background task failed: %s", label)

    task.add_done_callback(_done)


async def _drain_process_output(stream, *, label: str) -> None:
    if stream is None:
        return
    while True:
        line = await stream.readline()
        if not line:
            return
        logger.info("[%s] %s", label, line.decode("utf-8", errors="replace").rstrip())


def _replenisher_is_running(app: FastAPI) -> bool:
    process = getattr(app.state, "replenish_process", None)
    return process is not None and process.returncode is None


def _build_replenish_command() -> list[str]:
    custom_cmd = (os.getenv("OAI_X_REPLENISH_CMD") or "").strip()
    if custom_cmd:
        return shlex.split(custom_cmd)

    script_path = Path(__file__).resolve().with_name("oai-x.py")
    command = [sys.executable, str(script_path), "--storage-mode", "db", "--once"]

    database_url = (os.getenv("DATABASE_URL") or "").strip()
    if database_url:
        command.extend(["--database-url", database_url])

    extra_args = (os.getenv("OAI_X_REPLENISH_ARGS") or "").strip()
    if extra_args:
        command.extend(shlex.split(extra_args))
    return command


async def _watch_replenisher(app: FastAPI, process: asyncio.subprocess.Process, *, reason: str) -> None:
    try:
        return_code = await process.wait()
        logger.info("Replenisher exited: pid=%s returncode=%s reason=%s", process.pid, return_code, reason)
    finally:
        if getattr(app.state, "replenish_process", None) is process:
            app.state.replenish_process = None


async def ensure_token_pool(app: FastAPI, *, reason: str) -> None:
    min_available = _min_available_codex_tokens()
    if min_available <= 0:
        return

    counts = await get_token_counts()
    if counts.available >= min_available:
        return

    async with app.state.replenish_lock:
        counts = await get_token_counts()
        if counts.available >= min_available:
            return
        if _replenisher_is_running(app):
            return

        command = _build_replenish_command()
        cwd = str(Path(__file__).resolve().parent)
        env = os.environ.copy()
        env.setdefault("PYTHONUNBUFFERED", "1")

        process = await asyncio.create_subprocess_exec(
            *command,
            cwd=cwd,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        app.state.replenish_process = process
        logger.info(
            "Started replenisher: pid=%s reason=%s available=%s min=%s cmd=%s",
            process.pid,
            reason,
            counts.available,
            min_available,
            command,
        )
        _track_background_task(app, _drain_process_output(process.stdout, label="replenisher:stdout"), label="replenisher-stdout")
        _track_background_task(app, _drain_process_output(process.stderr, label="replenisher:stderr"), label="replenisher-stderr")
        _track_background_task(app, _watch_replenisher(app, process, reason=reason), label="replenisher-watch")


async def _token_pool_monitor(app: FastAPI) -> None:
    interval = _token_pool_check_interval_seconds()
    while True:
        try:
            await ensure_token_pool(app, reason="background-monitor")
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Token pool monitor failed")
        await asyncio.sleep(interval)


async def _stop_replenisher(app: FastAPI) -> None:
    process = getattr(app.state, "replenish_process", None)
    if process is None or process.returncode is not None:
        return

    logger.info("Stopping replenisher: pid=%s", process.pid)
    process.terminate()
    try:
        await asyncio.wait_for(process.wait(), timeout=10)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
    finally:
        if getattr(app.state, "replenish_process", None) is process:
            app.state.replenish_process = None


def _kick_token_pool_maintenance(app: FastAPI, *, reason: str) -> None:
    _track_singleton_background_task(
        app,
        ensure_token_pool(app, reason=reason),
        label=f"ensure-token-pool:{reason}",
        state_key="ensure_token_pool_task",
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
    await init_db()
    app.state.http_client = httpx.AsyncClient(
        follow_redirects=True,
        http2=False,
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
    )
    app.state.background_tasks = set()
    app.state.ensure_token_pool_task = None
    app.state.replenish_lock = asyncio.Lock()
    app.state.replenish_process = None
    app.state.token_pool_monitor_task = asyncio.create_task(_token_pool_monitor(app), name="token-pool-monitor")
    try:
        _kick_token_pool_maintenance(app, reason="startup")
        yield
    finally:
        app.state.token_pool_monitor_task.cancel()
        with suppress(asyncio.CancelledError):
            await app.state.token_pool_monitor_task

        tasks = list(app.state.background_tasks)
        for task in tasks:
            task.cancel()
        for task in tasks:
            with suppress(asyncio.CancelledError):
                await task

        await _stop_replenisher(app)
        await app.state.http_client.aclose()
        await close_database()


app = FastAPI(title="oai-x Codex Proxy", version="0.2.0", lifespan=lifespan)


@app.get("/healthz")
async def healthz(request: Request):
    counts = await get_token_counts()
    return {
        "ok": True,
        "upstream": _codex_responses_url(),
        "total_tokens": counts.total,
        "active_tokens": counts.active,
        "available_tokens": counts.available,
        "cooling_tokens": counts.cooling,
        "min_available_tokens": _min_available_codex_tokens(),
        "replenisher_running": _replenisher_is_running(request.app),
    }


async def _stream_upstream_response(
    stream_cm,
    upstream_response: httpx.Response,
) -> AsyncGenerator[bytes, None]:
    try:
        async for chunk in upstream_response.aiter_raw():
            yield chunk
    finally:
        await stream_cm.__aexit__(None, None, None)


async def _proxy_request_with_token(
    client: httpx.AsyncClient,
    http_request: Request,
    request_data: ResponsesRequest,
    *,
    access_token: str,
    account_id: str | None,
) -> Response:
    payload = _sanitize_codex_payload(request_data.model_dump(exclude_unset=True))
    headers = _build_upstream_headers(
        http_request,
        access_token=access_token,
        account_id=account_id,
        stream=bool(request_data.stream),
    )
    upstream_url = _codex_responses_url()
    json_payload = json.dumps(payload, ensure_ascii=False)

    if request_data.stream:
        stream_cm = client.stream(
            "POST",
            upstream_url,
            headers=headers,
            content=json_payload,
            timeout=httpx.Timeout(connect=30.0, read=None, write=30.0, pool=30.0),
        )
        upstream_response = await stream_cm.__aenter__()
        if upstream_response.status_code < 200 or upstream_response.status_code >= 300:
            raw = await upstream_response.aread()
            await stream_cm.__aexit__(None, None, None)
            raise HTTPException(
                status_code=upstream_response.status_code,
                detail=_decode_error_body(raw),
            )

        return StreamingResponse(
            _stream_upstream_response(stream_cm, upstream_response),
            media_type="text/event-stream",
        )

    upstream_response = await client.post(
        upstream_url,
        headers=headers,
        content=json_payload,
        timeout=httpx.Timeout(connect=30.0, read=300.0, write=30.0, pool=30.0),
    )
    if upstream_response.status_code < 200 or upstream_response.status_code >= 300:
        raw = await upstream_response.aread()
        raise HTTPException(
            status_code=upstream_response.status_code,
            detail=_decode_error_body(raw),
        )

    try:
        data = upstream_response.json()
    except json.JSONDecodeError:
        return Response(
            content=upstream_response.content,
            status_code=upstream_response.status_code,
            media_type=upstream_response.headers.get("content-type", "application/octet-stream"),
        )
    return JSONResponse(status_code=upstream_response.status_code, content=data)


@app.post("/v1/responses")
async def responses_route(
    http_request: Request,
    request_data: ResponsesRequest,
    _: None = Depends(verify_service_api_key),
):
    _kick_token_pool_maintenance(http_request.app, reason="request-start")

    counts = await get_token_counts()
    if counts.available <= 0:
        raise HTTPException(status_code=503, detail="No available Codex token in database")

    max_attempts = max(1, min(counts.available, _max_request_account_retries()))
    client: httpx.AsyncClient = http_request.app.state.http_client
    last_error: HTTPException | None = None

    for attempt in range(1, max_attempts + 1):
        token_row = await claim_next_active_token()
        if token_row is None:
            break

        try:
            access_token = await _get_codex_access_token(token_row, client)
        except HTTPException as exc:
            _oauth_cache.pop(token_row.id, None)
            await mark_token_error(token_row.id, str(exc.detail), deactivate=exc.status_code in (401, 403))
            if exc.status_code in (401, 403):
                last_error = exc
                _kick_token_pool_maintenance(http_request.app, reason="auth-refresh-failed")
                continue
            raise

        try:
            response = await _proxy_request_with_token(
                client,
                http_request,
                request_data,
                access_token=access_token,
                account_id=token_row.account_id,
            )
            await mark_token_success(token_row.id)
            return response
        except HTTPException as exc:
            status_code = getattr(exc, "status_code", 500)
            detail = str(getattr(exc, "detail", "") or exc)
            cooldown_seconds = _extract_usage_limit_cooldown_seconds(status_code, detail)
            permanently_disabled = _is_permanent_account_disable_error(status_code, detail)

            if cooldown_seconds is not None:
                await mark_token_error(
                    token_row.id,
                    detail,
                    cooldown_seconds=cooldown_seconds,
                )
                logger.warning(
                    "Codex account cooled down: token_id=%s account_id=%s cooldown_seconds=%s attempt=%s/%s",
                    token_row.id,
                    token_row.account_id,
                    cooldown_seconds,
                    attempt,
                    max_attempts,
                )
                last_error = exc
                _kick_token_pool_maintenance(http_request.app, reason="usage-limit-cooldown")
                continue

            if permanently_disabled:
                _oauth_cache.pop(token_row.id, None)
                await mark_token_error(token_row.id, detail, deactivate=True)
                logger.warning(
                    "Codex account permanently disabled: token_id=%s account_id=%s status=%s attempt=%s/%s",
                    token_row.id,
                    token_row.account_id,
                    status_code,
                    attempt,
                    max_attempts,
                )
                last_error = exc
                _kick_token_pool_maintenance(http_request.app, reason="account-permanently-disabled")
                continue

            if status_code in (401, 403):
                _oauth_cache.pop(token_row.id, None)
                await mark_token_error(token_row.id, detail)
                last_error = exc
                _kick_token_pool_maintenance(http_request.app, reason="upstream-auth-failed")
                continue

            raise
        except httpx.HTTPError as exc:
            message = f"Upstream request failed: {type(exc).__name__}: {exc}"
            await mark_token_error(token_row.id, message)
            raise HTTPException(status_code=502, detail=message) from exc

    _kick_token_pool_maintenance(http_request.app, reason="request-exhausted")
    if last_error is not None:
        raise HTTPException(
            status_code=503,
            detail=f"All available Codex accounts are exhausted or cooling down. Last error: {last_error.detail}",
        )
    raise HTTPException(status_code=503, detail="No available Codex token could satisfy this request")
