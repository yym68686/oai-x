"""
Pluggable temporary-email providers.

Each provider implements two operations:
  1. create_inbox  -> (email_address, opaque_handle)
  2. poll_verification_code(handle, email, ...) -> 6-digit code or ""
"""

from __future__ import annotations

import json
import re
import string
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

from curl_cffi import requests

CODE_RE = re.compile(r"(?<!\d)(\d{6})(?!\d)")


# ---------------------------------------------------------------------------
# Base helpers
# ---------------------------------------------------------------------------

def _extract_oai_code(messages: List[Dict[str, Any]]) -> str:
    """Return the latest 6-digit OAI verification code from a list of messages.

    Each message dict is expected to have at least some of:
      from, subject, body, html, date
    """
    candidates: list[tuple[int, str]] = []
    for msg in messages:
        sender = str(msg.get("from", "")).lower()
        blob = "\n".join(str(msg.get(f) or "") for f in ("from", "subject", "body", "html")).lower()
        if "openai" not in sender and "openai" not in blob:
            continue
        m = CODE_RE.search(blob)
        if not m:
            continue
        try:
            ts = int(msg.get("date", 0))
        except Exception:
            ts = 0
        candidates.append((ts, m.group(1)))
    if not candidates:
        return ""
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1]


# ===================================================================
# Provider: tempmail.lol  (default)
# ===================================================================

TEMPMAIL_API_BASE = "https://api.tempmail.lol/v2"


def tempmail_create_inbox(
    proxies: Optional[Dict[str, str]] = None,
    *,
    impersonate: str = "chrome",
) -> tuple[str, str]:
    try:
        resp = requests.post(
            f"{TEMPMAIL_API_BASE}/inbox/create",
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            json={},
            proxies=proxies,
            impersonate=impersonate,
            timeout=15,
        )
        if resp.status_code not in (200, 201):
            print(f"[ERROR] tempmail.lol: create inbox HTTP {resp.status_code}")
            return "", ""
        data = resp.json()
        email = str(data.get("address", "")).strip()
        token = str(data.get("token", "")).strip()
        if not email or not token:
            print("[ERROR] tempmail.lol: incomplete response")
            return "", ""
        return email, token
    except Exception as e:
        print(f"[ERROR] tempmail.lol: {e}")
        return "", ""


def tempmail_poll_code(
    handle: str,
    email: str,
    proxies: Optional[Dict[str, str]] = None,
    *,
    impersonate: str = "chrome",
) -> str:
    print(f"[*] Waiting for verification code in {email}...", end="", flush=True)
    for _ in range(40):
        print(".", end="", flush=True)
        try:
            resp = requests.get(
                f"{TEMPMAIL_API_BASE}/inbox",
                params={"token": handle},
                headers={"Accept": "application/json"},
                proxies=proxies,
                impersonate=impersonate,
                timeout=15,
            )
            if resp.status_code != 200:
                time.sleep(3)
                continue
            data = resp.json()
            if not isinstance(data, dict):
                print(" Email expired or invalid response.")
                return ""
            emails = data.get("emails", [])
            if not isinstance(emails, list):
                time.sleep(3)
                continue
            code = _extract_oai_code(emails)
            if code:
                print("\n[*] Verification code received!")
                return code
        except Exception as e:
            print(f"\n[ERROR] tempmail.lol poll: {e}")
        time.sleep(3)
    print(" Timeout waiting for verification code.")
    return ""


# ===================================================================
# Provider: mail.gw
# ===================================================================

MAILGW_API_BASE = "https://api.mail.gw"


class _MailGwSession:
    """Lightweight mail.gw REST wrapper (stdlib only)."""

    def __init__(self, timeout: int = 20) -> None:
        self.timeout = timeout

    def _req(
        self,
        method: str,
        path: str,
        payload: Optional[dict] = None,
        token: Optional[str] = None,
    ) -> Any:
        headers: dict[str, str] = {"Accept": "application/json"}
        body = None
        if payload is not None:
            body = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(
            f"{MAILGW_API_BASE}{path}",
            data=body,
            headers=headers,
            method=method,
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            raw = resp.read().decode()
        return json.loads(raw) if raw else None

    def get_domains(self) -> list[str]:
        data = self._req("GET", "/domains")
        items = data.get("hydra:member", []) if isinstance(data, dict) else data
        return [d["domain"] for d in items if d.get("isActive") and d.get("domain")]

    def create_account(self, address: str, password: str) -> dict:
        return self._req("POST", "/accounts", {"address": address, "password": password})

    def get_token(self, address: str, password: str) -> str:
        data = self._req("POST", "/token", {"address": address, "password": password})
        return data["token"]

    def list_messages(self, token: str) -> list[dict]:
        data = self._req("GET", "/messages", token=token)
        items = data.get("hydra:member", []) if isinstance(data, dict) else data
        return items if isinstance(items, list) else []

    def get_message(self, token: str, msg_id: str) -> dict:
        return self._req("GET", f"/messages/{msg_id}", token=token)


def mailgw_create_inbox(
    proxies: Optional[Dict[str, str]] = None,
    *,
    impersonate: str = "chrome",
) -> tuple[str, str]:
    """Returns (email, handle) where handle is ``address|password|bearer_token``."""
    gw = _MailGwSession()
    try:
        domains = gw.get_domains()
        if not domains:
            print("[ERROR] mail.gw: no active domains")
            return "", ""
    except Exception as e:
        print(f"[ERROR] mail.gw: domains lookup failed: {e}")
        return "", ""

    usable = [d for d in domains if d.lower() not in _blocked_domains]
    if not usable:
        print("[ERROR] mail.gw: all active domains are blocked")
        return "", ""

    alphabet = string.ascii_lowercase + string.digits
    for _ in range(5):
        domain = random.choice(usable)
        local = "".join(random.choice(alphabet) for _ in range(12))
        address = f"{local}@{domain}"
        password = "".join(random.choice(alphabet) for _ in range(18))
        try:
            gw.create_account(address, password)
            token = gw.get_token(address, password)
            # Pack credentials into the opaque handle
            handle = json.dumps({"a": address, "p": password, "t": token})
            return address, handle
        except Exception:
            continue

    print("[ERROR] mail.gw: failed to create mailbox after retries")
    return "", ""


def mailgw_poll_code(
    handle: str,
    email: str,
    proxies: Optional[Dict[str, str]] = None,
    *,
    impersonate: str = "chrome",
) -> str:
    creds = json.loads(handle)
    bearer = creds["t"]
    gw = _MailGwSession()

    print(f"[*] Waiting for verification code in {email}...", end="", flush=True)
    seen: set[str] = set()
    for _ in range(40):
        print(".", end="", flush=True)
        try:
            listing = gw.list_messages(bearer)
            new_ids = [m["id"] for m in listing if m.get("id") not in seen]
            seen.update(m.get("id", "") for m in listing)
            for mid in new_ids:
                full = gw.get_message(bearer, mid)
                # Normalise into the shape _extract_oai_code expects
                msg = {
                    "from": full.get("from", {}).get("address", ""),
                    "subject": full.get("subject", ""),
                    "body": full.get("text", ""),
                    "html": full.get("html", [""])[0] if isinstance(full.get("html"), list) else full.get("html", ""),
                    "date": full.get("createdAt", 0),
                }
                code = _extract_oai_code([msg])
                if code:
                    print("\n[*] Verification code received!")
                    return code
        except Exception as e:
            print(f"\n[ERROR] mail.gw poll: {e}")
        time.sleep(5)
    print(" Timeout waiting for verification code.")
    return ""


# ===================================================================
# Provider: YYDS Mail (https://vip.215.im)
# ===================================================================

YYDS_API_BASE = "https://maliapi.215.im/v1"

_yyds_api_key: str = ""
_yyds_good_domains: list[str] = []

# Probability of trying a fully random domain (no domain param) even when
# the good-domain list is large enough to pin.  If the random result lands
# on a blocked domain it is deleted and we fall back to a good-domain pick.
_YYDS_EXPLORE_CHANCE = 0.20


def _noop_post_use(
    handle: str,
    email: str,
    proxies: Optional[Dict[str, str]] = None,
    *,
    impersonate: str = "chrome",
) -> None:
    """Default no-op post-use hook for providers that don't need cleanup."""
    pass


def set_yyds_api_key(key: str) -> None:
    """Set the YYDS Mail API key (AC-... prefixed)."""
    global _yyds_api_key
    _yyds_api_key = key


def _yyds_create_one(
    proxies: Optional[Dict[str, str]],
    impersonate: str,
    domain: Optional[str] = None,
) -> tuple[str, str]:
    """Low-level: create a single YYDS inbox, optionally pinning *domain*."""
    payload: dict[str, Any] = {}
    if domain:
        payload["domain"] = domain
    try:
        resp = requests.post(
            f"{YYDS_API_BASE}/accounts",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-API-Key": _yyds_api_key,
            },
            json=payload,
            proxies=proxies,
            impersonate=impersonate,
            timeout=15,
        )
        if resp.status_code not in (200, 201):
            print(f"[ERROR] yyds: create inbox HTTP {resp.status_code}")
            return "", ""
        data = resp.json()
        if not data.get("success"):
            print(f"[ERROR] yyds: {data.get('error', 'unknown error')}")
            return "", ""
        inbox = data.get("data", {})
        email_addr = str(inbox.get("address", "")).strip()
        token = str(inbox.get("token", "")).strip()
        inbox_id = str(inbox.get("id", "")).strip()
        if not email_addr or not token:
            print("[ERROR] yyds: incomplete response")
            return "", ""
        handle = json.dumps({"token": token, "id": inbox_id})
        return email_addr, handle
    except Exception as e:
        print(f"[ERROR] yyds: {e}")
        return "", ""


def _yyds_delete_inbox(
    handle: str,
    proxies: Optional[Dict[str, str]],
    impersonate: str,
) -> None:
    """Silently delete a YYDS inbox (used when discarding a blocked-domain result)."""
    try:
        creds = json.loads(handle)
        bearer = creds["token"]
        inbox_id = creds.get("id", "")
        if not inbox_id:
            return
        requests.delete(
            f"{YYDS_API_BASE}/accounts/{inbox_id}",
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {bearer}",
            },
            proxies=proxies,
            impersonate=impersonate,
            timeout=15,
        )
    except Exception:
        pass


def _yyds_track_good_domain(email_addr: str) -> None:
    """Add the domain of *email_addr* to the good-domain list if not already there and not blocked."""
    domain = email_addr.rsplit("@", 1)[-1].lower()
    if domain and domain not in _blocked_domains and domain not in _yyds_good_domains:
        _yyds_good_domains.append(domain)
        print(f"[*] yyds: tracked good domain: {domain} (total good: {len(_yyds_good_domains)})")


def yyds_create_inbox(
    proxies: Optional[Dict[str, str]] = None,
    *,
    impersonate: str = "chrome",
) -> tuple[str, str]:
    if not _yyds_api_key:
        print("[ERROR] yyds: API key not configured (use --yyds-api-key)")
        return "", ""

    # Purge any good domains that got blocked since last call
    good = [d for d in _yyds_good_domains if d not in _blocked_domains]
    _yyds_good_domains[:] = good

    use_good_list = len(good) >= 3

    # --- exploration path (20% chance) ---
    if use_good_list and random.random() < _YYDS_EXPLORE_CHANCE:
        print("[*] yyds: exploring random domain (20% chance)")
        email, handle = _yyds_create_one(proxies, impersonate, domain=None)
        if email:
            domain = email.rsplit("@", 1)[-1].lower()
            if domain in _blocked_domains:
                print(f"[*] yyds: explored domain {domain} is blocked, deleting & retrying with good list")
                _yyds_delete_inbox(handle, proxies, impersonate)
            else:
                        return email, handle
        # fall through to good-domain pick

    # --- main path ---
    max_attempts = 3
    for attempt in range(max_attempts):
        chosen_domain: Optional[str] = None
        if use_good_list:
            chosen_domain = random.choice(good)
            print(f"[*] yyds: using good domain: {chosen_domain} (attempt {attempt + 1}/{max_attempts})")
        else:
            print(f"[*] yyds: randomizing domain (good list too small: {len(good)}, attempt {attempt + 1}/{max_attempts})")

        email, handle = _yyds_create_one(proxies, impersonate, domain=chosen_domain)
        if not email:
            continue

        domain = email.rsplit("@", 1)[-1].lower()
        if domain in _blocked_domains:
            print(f"[*] yyds: received blocked domain {domain}, deleting inbox & retrying")
            _yyds_delete_inbox(handle, proxies, impersonate)
            continue

        return email, handle

    print("[ERROR] yyds: failed to create inbox after retries")
    return "", ""


def yyds_poll_code(
    handle: str,
    email: str,
    proxies: Optional[Dict[str, str]] = None,
    *,
    impersonate: str = "chrome",
) -> str:
    creds = json.loads(handle)
    bearer = creds["token"]
    print(f"[*] Waiting for verification code in {email}...", end="", flush=True)
    for _ in range(40):
        print(".", end="", flush=True)
        try:
            resp = requests.get(
                f"{YYDS_API_BASE}/messages",
                params={"address": email},
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {bearer}",
                },
                proxies=proxies,
                impersonate=impersonate,
                timeout=15,
            )
            if resp.status_code != 200:
                time.sleep(3)
                continue
            data = resp.json()
            if not data.get("success"):
                time.sleep(3)
                continue
            messages_raw = data.get("data", {}).get("messages", [])
            if not isinstance(messages_raw, list) or not messages_raw:
                time.sleep(3)
                continue
            # Normalise into the shape _extract_oai_code expects
            normalised = []
            for m in messages_raw:
                sender = m.get("from", {})
                normalised.append({
                    "from": sender.get("address", "") if isinstance(sender, dict) else str(sender),
                    "subject": m.get("subject", ""),
                    "body": m.get("text", ""),
                    "html": m.get("html", [""])[0] if isinstance(m.get("html"), list) else m.get("html", ""),
                    "date": m.get("createdAt", 0),
                })
            code = _extract_oai_code(normalised)
            if code:
                print("\n[*] Verification code received!")
                return code
        except Exception as e:
            print(f"\n[ERROR] yyds poll: {e}")
        time.sleep(3)
    print(" Timeout waiting for verification code.")
    return ""


def yyds_post_use(
    handle: str,
    email: str,
    proxies: Optional[Dict[str, str]] = None,
    *,
    impersonate: str = "chrome",
) -> None:
    """Delete the temporary inbox to free up the quota slot."""
    creds = json.loads(handle)
    bearer = creds["token"]
    inbox_id = creds.get("id", "")
    if not inbox_id:
        print("[WARN] yyds: no inbox ID stored, skipping cleanup")
        return
    try:
        resp = requests.delete(
            f"{YYDS_API_BASE}/accounts/{inbox_id}",
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {bearer}",
            },
            proxies=proxies,
            impersonate=impersonate,
            timeout=15,
        )
        if resp.status_code in (200, 204):
            print(f"[*] yyds: inbox {email} deleted")
        else:
            print(f"[WARN] yyds: failed to delete inbox (HTTP {resp.status_code})")
    except Exception as e:
        print(f"[WARN] yyds: inbox cleanup failed: {e}")


# ===================================================================
# Provider registry
# ===================================================================

# ---------------------------------------------------------------------------
# Domain blocklist
# ---------------------------------------------------------------------------

_blocked_domains: set[str] = set()
_watched_domains: dict[str, int] = {}
_WATCH_THRESHOLD = 3


def watch_domain(email_address: str) -> None:
    """Record a delivery failure for the domain. Auto-block after repeated failures."""
    domain = email_address.rsplit("@", 1)[-1].lower()
    if not domain or domain in _blocked_domains:
        return
    count = _watched_domains.get(domain, 0) + 1
    _watched_domains[domain] = count
    print(f"[*] Domain {domain} delivery failure #{count}/{_WATCH_THRESHOLD}")
    if count >= _WATCH_THRESHOLD:
        _watched_domains.pop(domain, None)
        block_domain(email_address)


def clear_domain_watch(email_address: str) -> None:
    """Reset the failure counter for a domain (called on successful delivery)."""
    domain = email_address.rsplit("@", 1)[-1].lower()
    if domain in _watched_domains:
        _watched_domains.pop(domain, None)


def block_domain(email_address: str) -> None:
    """Extract and block the domain from an email address for future inbox creation."""
    domain = email_address.rsplit("@", 1)[-1].lower()
    if domain and domain not in _blocked_domains:
        _blocked_domains.add(domain)
        print(f"[*] Blocked email domain: {domain}")


def is_domain_blocked(email_address: str) -> bool:
    domain = email_address.rsplit("@", 1)[-1].lower()
    return domain in _blocked_domains


def mark_good_domain(email_address: str) -> None:
    """Track the domain as good after a successful registration (YYDS only)."""
    _yyds_track_good_domain(email_address)


PROVIDERS: Dict[str, Dict[str, Any]] = {
    "tempmail": {
        "create_inbox": tempmail_create_inbox,
        "poll_code": tempmail_poll_code,
        "post_use": _noop_post_use,
    },
    "mailgw": {
        "create_inbox": mailgw_create_inbox,
        "poll_code": mailgw_poll_code,
        "post_use": _noop_post_use,
    },
    "yyds": {
        "create_inbox": yyds_create_inbox,
        "poll_code": yyds_poll_code,
        "post_use": yyds_post_use,
    },
}

PROVIDER_NAMES = list(PROVIDERS.keys())
DEFAULT_PROVIDER = "tempmail"


def get_provider(name: str) -> Dict[str, Any]:
    if name not in PROVIDERS:
        raise ValueError(f"Unknown email provider '{name}'. Choose from: {', '.join(PROVIDER_NAMES)}")
    return PROVIDERS[name]
