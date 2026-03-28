import argparse
import base64
import getpass
import hashlib
import json
import random
import re
import secrets
import string
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional
from curl_cffi import CurlMime, requests

import browser_profile
import email_provider
import sentinel


# Constants for OAuth endpoints
OPENAI_AUTH_BASE = "https://auth.openai.com"
OPENAI_OAUTH_AUTHORIZE_URL = f"{OPENAI_AUTH_BASE}/oauth/authorize"
OPENAI_OAUTH_TOKEN_URL = f"{OPENAI_AUTH_BASE}/oauth/token"
OPENAI_REGISTER_AUTH_URL = f"{OPENAI_AUTH_BASE}/api/accounts/authorize"
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
DEFAULT_REDIRECT_URI = "http://localhost:1455/auth/callback"
DEFAULT_OAUTH_SCOPE = "openid email profile offline_access"


def truncate_text(text: str, max_length: int = 2048) -> str:
    """Truncate a string if it exceeds max_length, appending ellipsis."""
    if not text or len(text) <= max_length:
        return text or ""
    return text[: max_length - 3] + "..."


def log_http_error(label: str, response: Any, expected_codes=(200,), max_body=2048) -> None:
    """
    Log HTTP errors if response code is not within expected_codes.
    Includes method, URL, status code and truncated response body.
    """
    status = getattr(response, "status_code", None) or getattr(response, "status", None)
    if status in expected_codes:
        return
    try:
        url = getattr(response, "url", "?")
        method = getattr(getattr(response, "request", None), "method", "?")
        body = truncate_text(getattr(response, "text", "") or "", max_body)
        print(f"[ERROR] {label}: {method} {url} -> HTTP {status}")
        if body.strip():
            print(body)
    except Exception as exc:
        print(f"[ERROR] {label}: failed to read response content: {exc}")


def generate_random_password(length: int = 12) -> str:
    """Generate a random password with letters and digits."""
    chars = string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))


def fetch_workspace_id_from_session(session: requests.Session) -> Optional[str]:
    """
    Extract workspace ID from OpenAI auth session cookies.

    Uses 'oai-client-auth-session' JWT cookie first;
    falls back to '_account' UUID cookie.
    """
    jar = getattr(session, "cookies", None)
    if not jar:
        return None

    def extract_workspace_id_from_jwt(token: str) -> Optional[str]:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        payload_b64 = parts[1]
        padded = payload_b64 + "=" * ((4 - len(payload_b64) % 4) % 4)
        try:
            payload_json = base64.urlsafe_b64decode(padded).decode("utf-8")
            payload = json.loads(payload_json)
        except Exception:
            return None
        workspaces = payload.get("workspaces")
        if isinstance(workspaces, list) and workspaces:
            first_ws = workspaces[0]
            if isinstance(first_ws, dict):
                wid = first_ws.get("id")
                if wid:
                    return str(wid).strip()
        return None

    cookie_dict = jar.get_dict()  # get cookies as {name: value}

    tokens_seen = set()
    for name, value in cookie_dict.items():
        if name == "oai-client-auth-session":
            if value in tokens_seen:
                continue
            tokens_seen.add(value)
            wid = extract_workspace_id_from_jwt(value)
            if wid:
                return wid

    for name, value in cookie_dict.items():
        if name == "_account":
            val = value.strip()
            try:
                uuid.UUID(val)
                return val
            except Exception:
                continue

    return None


@dataclass(frozen=True)
class OAuthSessionDetails:
    """Encapsulates OAuth session data."""
    auth_url: str
    state: str
    code_verifier: str
    redirect_uri: str


def generate_oauth_url(
    redirect_uri: str = DEFAULT_REDIRECT_URI,
    scope: str = DEFAULT_OAUTH_SCOPE,
) -> OAuthSessionDetails:
    """
    Build OAuth authorization URL with PKCE and state for OpenAI.
    Returns a data class containing URL, state, code verifier, and redirect URI.
    """
    def base64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

    def sha256_base64url(text: str) -> str:
        return base64url_encode(hashlib.sha256(text.encode("ascii")).digest())

    state = secrets.token_urlsafe(16)
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = sha256_base64url(code_verifier)

    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "prompt": "login",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
    }
    auth_url = f"{OPENAI_OAUTH_AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"
    return OAuthSessionDetails(auth_url, state, code_verifier, redirect_uri)


def parse_callback_url(callback_url: str) -> Dict[str, str]:
    """
    Parse OAuth callback URL to extract query parameters: code, state, error, error_description.
    """
    # Normalize URL in case it is just query fragment or incomplete
    url_candidate = callback_url.strip()
    if not url_candidate:
        return {"code": "", "state": "", "error": "", "error_description": ""}

    if "://" not in url_candidate:
        if url_candidate.startswith("?"):
            url_candidate = "http://localhost" + url_candidate
        elif any(ch in url_candidate for ch in "/?#") or ":" in url_candidate:
            url_candidate = "http://" + url_candidate
        elif "=" in url_candidate:
            url_candidate = "http://localhost/?" + url_candidate

    parsed = urllib.parse.urlparse(url_candidate)
    query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    fragment_params = urllib.parse.parse_qs(parsed.fragment, keep_blank_values=True)

    # Merge fragment params into query if missing
    for k, v in fragment_params.items():
        if k not in query_params or not query_params[k] or not (query_params[k][0] or "").strip():
            query_params[k] = v

    def single_value(key: str) -> str:
        return (query_params.get(key, [""])[0] or "").strip()

    code = single_value("code")
    state = single_value("state")
    error = single_value("error")
    error_desc = single_value("error_description")

    # Handle cases where code contains state fragment
    if code and not state and "#" in code:
        code, state = code.split("#", 1)

    # Swap error and description if description exists but error missing (sometimes reversed)
    if not error and error_desc:
        error, error_desc = error_desc, ""

    return {
        "code": code,
        "state": state,
        "error": error,
        "error_description": error_desc,
    }


def exchange_oauth_code_for_tokens(
    authorization_code: str,
    code_verifier: str,
    redirect_uri: str = DEFAULT_REDIRECT_URI,
) -> Dict[str, Any]:
    """
    Exchange the OAuth authorization code for access, refresh, and ID tokens.
    Raises RuntimeError if token exchange fails.
    """
    data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code": authorization_code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }

    encoded_body = urllib.parse.urlencode(data).encode("utf-8")
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    req = urllib.request.Request(OPENAI_OAUTH_TOKEN_URL, data=encoded_body, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            if resp.status != 200:
                text = raw.decode("utf-8", errors="replace")
                print(f"[ERROR] Token exchange failed with status {resp.status}")
                print(truncate_text(text))
                raise RuntimeError(f"Token exchange failed: HTTP {resp.status}: {text}")
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as error:
        raw = error.read()
        text = raw.decode("utf-8", errors="replace")
        print(f"[ERROR] HTTP error during token exchange: {error.code}")
        print(truncate_text(text))
        raise RuntimeError(f"Token exchange failed: HTTP {error.code}: {text}") from error


def parse_jwt_claims(id_token: str) -> Dict[str, Any]:
    """Decode JWT payload without signature verification to read claims."""
    if not id_token or id_token.count(".") < 2:
        return {}

    payload_b64 = id_token.split(".")[1]
    padded = payload_b64 + "=" * ((4 - len(payload_b64) % 4) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded).decode("utf-8")
        claims = json.loads(decoded)
        return claims if isinstance(claims, dict) else {}
    except Exception:
        return {}


def serialize_token_response(
    token_resp: Dict[str, Any],
    *,
    password: str = "",
    mail_provider: str = "",
    mail_provider_token: str = "",
) -> str:
    """Convert token response to JSON string with metadata."""
    access_token = str(token_resp.get("access_token", "")).strip()
    refresh_token = str(token_resp.get("refresh_token", "")).strip()
    id_token = str(token_resp.get("id_token", "")).strip()
    expires_in = int(token_resp.get("expires_in") or 0)

    claims = parse_jwt_claims(id_token)
    email = str(claims.get("email") or "").strip()
    auth_claims = claims.get("https://api.openai.com/auth") or {}
    account_id = str(auth_claims.get("chatgpt_account_id") or "").strip()

    now_epoch = int(time.time())
    expired_rfc3339 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_epoch + max(expires_in, 0)))
    now_rfc3339 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_epoch))

    token_config = {
        "id_token": id_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "account_id": account_id,
        "last_refresh": now_rfc3339,
        "email": email,
        "type": "codex",
        "expired": expired_rfc3339,
    }

    recovery: Dict[str, Any] = {}
    if password:
        recovery["password"] = password
    if mail_provider:
        recovery["mail_provider"] = mail_provider
    # tempmail and mailgw inboxes are not deleted after use, so store
    # their credentials for potential recovery.
    # yyds inboxes are deleted in post_use, making recovery impossible.
    if mail_provider == "tempmail" and mail_provider_token:
        recovery["mail_provider_token"] = mail_provider_token
    elif mail_provider == "mailgw" and mail_provider_token:
        try:
            gw_creds = json.loads(mail_provider_token)
            recovery["mail_provider_token"] = {
                "address": gw_creds.get("a", ""),
                "password": gw_creds.get("p", ""),
            }
        except Exception:
            pass
    if recovery:
        token_config["recovery"] = recovery

    return json.dumps(token_config, ensure_ascii=False, separators=(",", ":"))


def submit_token_to_api(token_json: str, api_url: str, api_token: str) -> bool:
    """
    Submit the token JSON to management API.
    Uses multipart/form-data upload with authorization header.
    Returns True on success, False on failure.
    """
    try:
        token_data = json.loads(token_json)
        email = token_data.get("email", "unknown")
        file_name = f"token_{email.replace('@', '_')}_{int(time.time())}.json"

        mime = CurlMime()
        mime.addpart(
            name="file",
            filename=file_name,
            content_type="application/json",
            data=token_json.encode("utf-8"),
        )
        headers = {"Authorization": f"Bearer {api_token}"}
        response = requests.post(
            f"{api_url}/v0/management/auth-files",
            multipart=mime,
            headers=headers,
            timeout=60,
            impersonate="chrome",
        )
        if response.status_code in {200, 201, 202}:
            print(f"[*] Successfully submitted token file: {file_name}")
            return True
        print(f"[ERROR] Failed to submit token, HTTP status: {response.status_code}")
        log_http_error("submit auth-files", response, expected_codes=(200, 201, 202))
        return False
    except Exception as e:
        print(f"[ERROR] Exception while submitting token: {e}")
        return False


def perform_registration_flow(
    proxy_url: Optional[str] = None,
    mail_provider: str = email_provider.DEFAULT_PROVIDER,
) -> Optional[str]:
    """
    Full flow: get temp email, register with OpenAI, complete OAuth login,
    and retrieve tokens as JSON string.
    Returns token JSON string on success, else None.
    """
    provider = email_provider.get_provider(mail_provider)
    create_inbox = provider["create_inbox"]
    poll_code = provider["poll_code"]
    post_use = provider["post_use"]
    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
    reg_profile = browser_profile.random_registration_profile()
    session = requests.Session(
        proxies=proxies, impersonate=reg_profile.impersonate
    )

    # Check IP location; block CN/HK for compliance
    try:
        trace_resp = session.get("https://cloudflare.com/cdn-cgi/trace", timeout=10)
        trace_text = trace_resp.text
        loc_match = re.search(r"^loc=(.+)$", trace_text, re.MULTILINE)
        location = loc_match.group(1) if loc_match else None
        print(f"[*] Current IP location: {location}")
        if location in {"CN", "HK"}:
            print("[ERROR] IP location not supported for registration.")
            return None
    except Exception as e:
        print(f"[ERROR] Network reachability check failed: {e}")
        return None

    email, mail_handle = create_inbox(proxies, impersonate=reg_profile.impersonate)
    if not email or not mail_handle:
        print("[ERROR] Could not obtain temporary email.")
        return None
    print(f"[*] Temporary email obtained: {email}")

    try:
        return _perform_registration_inner(
            session, reg_profile, proxies, email, mail_handle, poll_code,
            mail_provider=mail_provider,
        )
    finally:
        post_use(mail_handle, email, proxies, impersonate=reg_profile.impersonate)


def _perform_registration_inner(
    session: requests.Session,
    reg_profile: Any,
    proxies: Optional[Dict[str, str]],
    email: str,
    mail_handle: str,
    poll_code,
    mail_provider: str = "",
) -> Optional[str]:
    device_id = str(uuid.uuid4())
    auth_session_logging_id = str(uuid.uuid4())

    # Step 1: Retrieve ChatGPT sign-in authorization URL
    authorize_url = get_chatgpt_authorize_url(
        session, email=email, device_id=device_id, auth_session_logging_id=auth_session_logging_id
    )
    if not authorize_url:
        return None
    print("[*] Obtained authorization URL, proceeding to registration...")

    # Access the authorization page to initialize cookies and device ID
    resp = session.get(authorize_url, timeout=15)
    if resp.status_code >= 400:
        log_http_error("register auth page", resp, expected_codes=())

    device_id_cookie = session.cookies.get("oai-did")
    if not device_id_cookie:
        print("[ERROR] Device ID cookie 'oai-did' missing after authorization request.")
        return None

    # Generate Sentinel fingerprint and obtain tokens needed for secured API calls
    sentinel_fingerprint = sentinel.make_fingerprint_for_registration(
        device_id_cookie, reg_profile
    )
    random_password = generate_random_password()
    print(f"[*] Generated password for registration: {random_password}")

    # Debug: log sentinel fingerprint details for diagnosing registration failures
    print(f"[DEBUG] registration_profile: {reg_profile.name} impersonate={reg_profile.impersonate}")
    print(f"[DEBUG] device_id_cookie: {device_id_cookie}")
    print(f"[DEBUG] sentinel_fingerprint UA: {sentinel_fingerprint[4]}")
    print(f"[DEBUG] sentinel_fingerprint nav_prop: {sentinel_fingerprint[10]}")
    print(f"[DEBUG] sentinel_fingerprint doc_keys: {sentinel_fingerprint[11]}")
    print(f"[DEBUG] sentinel_fingerprint win_keys: {sentinel_fingerprint[12]}")
    print(f"[DEBUG] sentinel_fingerprint screen: {sentinel_fingerprint[0]} (w+h)")
    print(f"[DEBUG] sentinel_fingerprint hw_concurrency: {sentinel_fingerprint[16]}")
    print(f"[DEBUG] sentinel_fingerprint lang: {sentinel_fingerprint[7]}, langs: {sentinel_fingerprint[8]}")
    print(f"[DEBUG] sentinel_fingerprint date_str: {sentinel_fingerprint[1]}")
    print(f"[DEBUG] sentinel_fingerprint script_url: {sentinel_fingerprint[5]}")

    # Call Sentinel for username/password registration flow
    sen_token, sen_turnstile, sen_p = sentinel.call_sentinel_req(
        device_id_cookie,
        "username_password_create",
        proxies=proxies,
        session=session,
        fingerprint=sentinel_fingerprint,
        profile=reg_profile,
    )
    if not sen_token:
        print("[ERROR] Failed to obtain Sentinel token for registration.")
        return None

    print(f"[DEBUG] sentinel username_password_create: token={sen_token[:32]}..., turnstile={sen_turnstile[:32] if sen_turnstile else None}..., p={'yes' if sen_p else 'no'}")

    sentinel_header = json.dumps({
        "p": sen_p or sen_token,
        "t": sen_turnstile,
        "c": sen_token,
        "id": device_id_cookie,
        "flow": "username_password_create",
    })

    registration_payload = json.dumps({"password": random_password, "username": email})

    print("[*] Submitting user registration data...")
    register_response = session.post(
        f"{OPENAI_AUTH_BASE}/api/accounts/user/register",
        headers={
            "referer": f"{OPENAI_AUTH_BASE}/create-account/password",
            "accept": "application/json",
            "content-type": "application/json",
            "openai-sentinel-token": sentinel_header,
        },
        data=registration_payload,
    )
    if register_response.status_code != 200:
        log_http_error("user/register", register_response)
        return None

    # Send email OTP request
    print("[*] Sending email verification code...")
    otp_send_resp = session.get(
        f"{OPENAI_AUTH_BASE}/api/accounts/email-otp/send",
        headers={"referer": f"{OPENAI_AUTH_BASE}/create-account/password", "accept": "application/json"},
    )
    if otp_send_resp.status_code != 200:
        log_http_error("email-otp/send", otp_send_resp)
        return None

    # Poll inbox for verification code
    otp_code = poll_code(mail_handle, email, proxies, impersonate=reg_profile.impersonate)
    if not otp_code:
        print("[ERROR] Failed to receive email verification code.")
        email_provider.watch_domain(email)
        return None
    email_provider.clear_domain_watch(email)
    time.sleep(2)  # Small delay before verification

    otp_validation_body = json.dumps({"code": otp_code})
    print("[*] Validating received email verification code...")
    validate_resp = session.post(
        f"{OPENAI_AUTH_BASE}/api/accounts/email-otp/validate",
        headers={
            "referer": f"{OPENAI_AUTH_BASE}/email-verification",
            "origin": OPENAI_AUTH_BASE,
            "accept": "application/json",
            "content-type": "application/json",
        },
        data=otp_validation_body,
    )
    if validate_resp.status_code != 200:
        log_http_error("email-otp/validate", validate_resp)
        return None

    # Submit additional account details (random plausible name + calendar-valid birthdate)
    display_name = sentinel.generate_random_display_name()
    birthdate = sentinel.generate_random_birthdate()
    account_info_payload = json.dumps({"name": display_name, "birthdate": birthdate})
    print("[*] Completing account creation with additional details...")
    print(f"[DEBUG] create_account payload: {account_info_payload}")
    create_account_resp = session.post(
        f"{OPENAI_AUTH_BASE}/api/accounts/create_account",
        headers={
            "referer": f"{OPENAI_AUTH_BASE}/about-you",
            "accept": "application/json",
            "content-type": "application/json",
        },
        data=account_info_payload,
    )
    if create_account_resp.status_code != 200:
        log_http_error("create_account", create_account_resp)
        try:
            err_body = create_account_resp.json()
            err_code = err_body.get("error", {}).get("code")
            if err_code in ("unsupported_email", "registration_disallowed"):
                email_provider.block_domain(email)
        except Exception:
            pass
        return None
    creation_response_json = create_account_resp.json()
    continue_url = creation_response_json.get("continue_url", "").strip()
    if not continue_url:
        print("[ERROR] create_account response missing continue_url")
        return None

    # Follow redirect to callback URL
    print("[*] Following callback redirect after account creation...")
    callback_resp = session.get(continue_url, allow_redirects=True, timeout=15)
    if callback_resp.status_code >= 400:
        log_http_error("oauth callback redirect", callback_resp, expected_codes=())

    # Start OAuth authorization (Codex flow)
    oauth_details = generate_oauth_url()
    print("[*] Opening OAuth authorization URL...")
    session.get(oauth_details.auth_url, allow_redirects=True, timeout=15)

    # Additional sentinel calls for authorization continue, password verify flows
    sen_token2, sen_turnstile2, sen_p2 = sentinel.call_sentinel_req(
        device_id_cookie,
        "authorize_continue",
        proxies=proxies,
        session=session,
        fingerprint=sentinel_fingerprint,
        profile=reg_profile,
    )
    if not sen_token2:
        print("[ERROR] Failed to obtain Sentinel token for authorize_continue.")
        return None

    sentinel_header2 = json.dumps({
        "p": sen_p2 or sen_token2,
        "t": sen_turnstile2,
        "c": sen_token2,
        "id": device_id_cookie,
        "flow": "authorize_continue",
    })

    auth_continue_body = json.dumps({"username": {"kind": "email", "value": email}})
    print("[*] Continuing authorization with username/email...")
    auth_continue_resp = session.post(
        f"{OPENAI_AUTH_BASE}/api/accounts/authorize/continue",
        headers={
            "referer": f"{OPENAI_AUTH_BASE}/log-in",
            "accept": "application/json",
            "content-type": "application/json",
            "openai-sentinel-token": sentinel_header2,
        },
        data=auth_continue_body,
    )
    if auth_continue_resp.status_code != 200:
        log_http_error("authorize/continue", auth_continue_resp)
        return None

    sen_token3, sen_turnstile3, sen_p3 = sentinel.call_sentinel_req(
        device_id_cookie,
        "password_verify",
        proxies=proxies,
        session=session,
        fingerprint=sentinel_fingerprint,
        profile=reg_profile,
    )
    if not sen_token3:
        print("[ERROR] Failed to obtain Sentinel token for password_verify.")
        return None
    sentinel_header3 = json.dumps({
        "p": sen_p3 or sen_token3,
        "t": sen_turnstile3,
        "c": sen_token3,
        "id": device_id_cookie,
        "flow": "password_verify",
    })
    password_verify_body = json.dumps({"password": random_password})
    print("[*] Verifying password with OpenAI auth service...")
    password_verify_resp = session.post(
        f"{OPENAI_AUTH_BASE}/api/accounts/password/verify",
        headers={
            "referer": f"{OPENAI_AUTH_BASE}/log-in/password",
            "accept": "application/json",
            "content-type": "application/json",
            "openai-sentinel-token": sentinel_header3,
        },
        data=password_verify_body,
    )
    if password_verify_resp.status_code != 200:
        log_http_error("password/verify", password_verify_resp)
        return None

    password_data = password_verify_resp.json()
    continue_url_after_password = password_data.get("continue_url", "").strip()
    if not continue_url_after_password:
        print("[ERROR] password/verify response missing continue_url")
        return None

    # Navigate to email verification page after password confirmation
    print("[*] Accessing email verification page...")
    email_verification_page = session.get(
        continue_url_after_password,
        allow_redirects=True,
        timeout=15,
        headers={
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "referer": f"{OPENAI_AUTH_BASE}/log-in/password",
        },
    )
    if email_verification_page.status_code >= 400:
        log_http_error("email-verification page", email_verification_page, expected_codes=())
        return None

    # Poll for second email OTP, validate again
    second_code = poll_code(mail_handle, email, proxies, impersonate=reg_profile.impersonate)
    if not second_code:
        print("[ERROR] Second email verification code not received.")
        email_provider.watch_domain(email)
        return None
    email_provider.clear_domain_watch(email)
    time.sleep(2)

    otp_validation_payload = json.dumps({"code": second_code})
    print("[*] Validating second email verification code...")
    otp_validation_response = session.post(
        f"{OPENAI_AUTH_BASE}/api/accounts/email-otp/validate",
        headers={
            "referer": f"{OPENAI_AUTH_BASE}/email-verification",
            "origin": OPENAI_AUTH_BASE,
            "accept": "application/json",
            "content-type": "application/json",
        },
        data=otp_validation_payload,
    )
    if otp_validation_response.status_code != 200:
        log_http_error("email-otp/validate", otp_validation_response)
        return None

    otp_response_data = otp_validation_response.json()
    otp_continue_url = otp_response_data.get("continue_url", "").strip()
    if otp_continue_url:
        session.get(otp_continue_url, allow_redirects=True, timeout=15)

    # Select workspace for the user
    workspace_id = fetch_workspace_id_from_session(session)
    if not workspace_id:
        print("[ERROR] Failed to find workspace ID from session cookies.")
        return None

    select_workspace_payload = json.dumps({"workspace_id": workspace_id}, separators=(",", ":"))
    print("[*] Selecting workspace for newly created account...")
    workspace_select_resp = session.post(
        f"{OPENAI_AUTH_BASE}/api/accounts/workspace/select",
        headers={
            "referer": f"{OPENAI_AUTH_BASE}/sign-in-with-chatgpt/codex/consent",
            "origin": OPENAI_AUTH_BASE,
            "accept": "application/json",
            "content-type": "application/json",
        },
        data=select_workspace_payload,
    )
    if workspace_select_resp.status_code != 200:
        log_http_error("workspace/select", workspace_select_resp)
        return None

    workspace_select_data = workspace_select_resp.json()
    continue_url_after_workspace_select = workspace_select_data.get("continue_url", "").strip()
    if not continue_url_after_workspace_select:
        print("[ERROR] workspace/select response missing continue_url")
        return None

    # Follow redirect chain to final OAuth callback with code and state
    print("[*] Following OAuth redirect chain to obtain authorization code...")
    current_url = continue_url_after_workspace_select
    max_redirects = 6
    for _ in range(max_redirects):
        final_resp = session.get(current_url, allow_redirects=False, timeout=15)
        if final_resp.status_code not in {301, 302, 303, 307, 308}:
            if final_resp.status_code >= 400:
                log_http_error("oauth redirect chain", final_resp, expected_codes=())
            break

        location = final_resp.headers.get("Location")
        if not location:
            print(f"[ERROR] Redirect without Location header at {current_url}")
            break

        next_url = urllib.parse.urljoin(current_url, location)
        if "code=" in next_url and "state=" in next_url:
            # Final OAuth callback detected
            callback_data = parse_callback_url(next_url)
            if callback_data["error"]:
                raise RuntimeError(f"OAuth error: {callback_data['error']} {callback_data['error_description']}")
            if callback_data["state"] != oauth_details.state:
                raise RuntimeError("OAuth state mismatch detected")
            # Exchange code for tokens
            token_response = exchange_oauth_code_for_tokens(
                authorization_code=callback_data["code"],
                code_verifier=oauth_details.code_verifier,
                redirect_uri=oauth_details.redirect_uri,
            )
            email_provider.mark_good_domain(email)
            return serialize_token_response(
                token_response,
                password=random_password,
                mail_provider=mail_provider,
                mail_provider_token=mail_handle,
            )

        current_url = next_url

    print("[ERROR] OAuth callback URL with code and state not found in redirect chain.")
    return None


def get_chatgpt_authorize_url(
    session: requests.Session,
    *,
    email: str,
    device_id: str,
    auth_session_logging_id: str,
) -> Optional[str]:
    """
    Performs initial warm-up and obtains the ChatGPT sign-in authorization URL,
    which redirects into the OpenAI account authorization flow.
    """
    print("[*] Warming up ChatGPT endpoint...")
    warmup_response = session.get("https://chatgpt.com/", timeout=15)
    if warmup_response.status_code >= 400:
        log_http_error("chatgpt warmup", warmup_response, expected_codes=())

    print("[*] Fetching CSRF token for sign-in...")
    csrf_response = session.get(
        "https://chatgpt.com/api/auth/csrf",
        headers={"Accept": "*/*", "Referer": "https://chatgpt.com/"},
        timeout=15,
    )
    if csrf_response.status_code != 200:
        print("[ERROR] Failed to obtain CSRF token")
        log_http_error("chatgpt csrf", csrf_response, expected_codes=(200,))
        return None

    try:
        csrf_json = csrf_response.json()
    except Exception:
        print("[ERROR] CSRF response is not valid JSON")
        return None

    csrf_token = str(csrf_json.get("csrfToken") or "").strip()
    if not csrf_token:
        print("[ERROR] CSRF token missing in response")
        return None

    signin_query = {
        "prompt": "login",
        "screen_hint": "login_or_signup",
        "ext-oai-did": device_id,
        "auth_session_logging_id": auth_session_logging_id,
        "login_hint": email,
    }
    signin_url = "https://chatgpt.com/api/auth/signin/openai?" + urllib.parse.urlencode(signin_query)

    form_body = urllib.parse.urlencode({
        "callbackUrl": "/create-free-workspace",
        "csrfToken": csrf_token,
        "json": "true",
    })

    print("[*] Initiating sign-in request to ChatGPT endpoint...")
    signin_response = session.post(
        signin_url,
        headers={
            "Accept": "*/*",
            "Referer": "https://chatgpt.com/",
            "Origin": "https://chatgpt.com",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data=form_body,
        timeout=15,
    )

    if signin_response.status_code != 200:
        print("[ERROR] Sign-in request failed")
        log_http_error("chatgpt signin/openai", signin_response)
        return None

    try:
        signin_resp_json = signin_response.json()
    except Exception:
        print("[ERROR] Sign-in response JSON parsing failed")
        log_http_error("chatgpt signin response", signin_response)
        return None

    auth_url = str(signin_resp_json.get("url") or "").strip()
    if not auth_url or OPENAI_REGISTER_AUTH_URL not in auth_url:
        print("[ERROR] Sign-in response missing or unexpected auth URL")
        return None

    return auth_url


def main():
    parser = argparse.ArgumentParser(description="OpenAI Automatic Registration Script")
    parser.add_argument("--proxy", help="Proxy address, e.g. http://127.0.0.1:7890")
    parser.add_argument(
        "--mail-provider",
        choices=email_provider.PROVIDER_NAMES,
        default=email_provider.DEFAULT_PROVIDER,
        help=f"Temp-email provider (default: {email_provider.DEFAULT_PROVIDER})",
    )
    parser.add_argument(
        "--once", action="store_true", help="Run only one registration cycle and exit"
    )
    parser.add_argument("--sleep-min", type=int, default=5, help="Minimum wait seconds between loops")
    parser.add_argument("--sleep-max", type=int, default=30, help="Maximum wait seconds between loops")
    parser.add_argument(
        "--auto-submit", action="store_true", help="Automatically submit tokens to API instead of saving locally"
    )
    parser.add_argument("--api-url", help="API URL for auto submission")
    parser.add_argument("--api-token", help="API authorization token for auto submission")
    parser.add_argument("--yyds-api-key", help="YYDS Mail API key (AC-...) for the 'yyds' mail provider")
    args = parser.parse_args()

    auto_submit = args.auto_submit
    api_url = args.api_url
    api_token = args.api_token

    if auto_submit:
        if not api_url:
            api_url = input("Please enter API URL: ").strip()
        if not api_token:
            api_token = getpass.getpass("Please enter API Authorization Token: ").strip()
        if not api_url or not api_token:
            print("[ERROR] API URL and Token cannot be empty in auto submit mode.")
            return
        print(f"[*] Auto-submit mode enabled. Submitting to: {api_url}")

    if args.mail_provider == "yyds":
        yyds_key = args.yyds_api_key
        if not yyds_key:
            yyds_key = input("Please enter YYDS Mail API Key (AC-...): ").strip()
        if not yyds_key:
            print("[ERROR] YYDS Mail API key is required for the 'yyds' provider.")
            return
        email_provider.set_yyds_api_key(yyds_key)

    sleep_min = max(1, args.sleep_min)
    sleep_max = max(sleep_min, args.sleep_max)

    iteration_count = 0
    print(f"[*] Starting OpenAI automatic registration script. (mail provider: {args.mail_provider})")
    while True:
        iteration_count += 1
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] >>> Starting registration iteration #{iteration_count} <<<")
        try:
            token_json = perform_registration_flow(args.proxy, mail_provider=args.mail_provider)
            if token_json:
                submitted = False
                if auto_submit:
                    submitted = submit_token_to_api(token_json, api_url, api_token)
                    if submitted:
                        print("[*] Token successfully submitted!")
                    else:
                        print("[WARN] Submission failed, saving locally as fallback...")
                if not submitted:
                    token_data = json.loads(token_json)
                    sanitized_email = token_data.get("email", "unknown").replace("@", "_")
                    file_name = f"token_{sanitized_email}_{int(time.time())}.json"
                    with open(file_name, "w", encoding="utf-8") as f:
                        f.write(token_json)
                    print(f"[*] Registration successful! Token saved to file: {file_name}")
            else:
                print("[WARN] Registration iteration failed.")
        except Exception as e:
            print(f"[ERROR] Unhandled exception during registration: {e}")

        if args.once:
            break

        wait_seconds = random.randint(sleep_min, sleep_max)
        print(f"[*] Sleeping for {wait_seconds} seconds before next iteration...")
        time.sleep(wait_seconds)


if __name__ == "__main__":
    main()
