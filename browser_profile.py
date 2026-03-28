"""
Per-registration browser profile: TLS impersonation (curl_cffi) + matching UA and
Sentinel fingerprint fields. Pick once at registration start and reuse for the whole flow.

Fingerprint pools (navigator / document / window / inWindow) come from real engine captures
see ``engine_fingerprint_pools.py`` — not hand-written comma-separated strings.
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass
from typing import Dict, Literal, Optional, Tuple

from curl_cffi.requests.impersonate import normalize_browser_type

from engine_fingerprint_pools import (
    CHROME_DOCUMENT_OWN_KEYS,
    CHROME_IN_WINDOW_BITS,
    CHROME_NAVIGATOR_PROTOTYPE_KEYS,
    CHROME_NAVIGATOR_STATIC_STRINGS,
    CHROME_WINDOW_ENUMERABLE_KEYS,
    FIREFOX_DOCUMENT_OWN_KEYS,
    FIREFOX_IN_WINDOW_BITS,
    FIREFOX_NAVIGATOR_PROTOTYPE_KEYS,
    FIREFOX_NAVIGATOR_STATIC_STRINGS,
    FIREFOX_WINDOW_ENUMERABLE_KEYS,
)


@dataclass(frozen=True)
class RegistrationBrowserProfile:
    """Single coherent browser identity for one registration run."""

    name: str
    impersonate: str
    ua: str
    heap_mode: Literal["chromium", "none"]
    navigator_prototype_keys: Tuple[str, ...]
    navigator_static_strings: Dict[str, str]
    document_own_keys: Tuple[str, ...]
    window_enumerable_keys: Tuple[str, ...]
    in_window_bits: Tuple[int, int, int, int, int, int, int]


def _major_version(normalized: str, prefix: str) -> int:
    match = re.match(rf"{re.escape(prefix)}(\d+)", normalized)
    if not match:
        raise ValueError(f"unexpected impersonation id: {normalized!r}")
    return int(match.group(1))


def _chrome_version_triple() -> str:
    normalized_chrome_target = normalize_browser_type("chrome")
    major = _major_version(normalized_chrome_target, "chrome")
    return f"{major}.0.0.0"


def _firefox_rv_version() -> str:
    normalized_firefox_target = normalize_browser_type("firefox")
    major = _major_version(normalized_firefox_target, "firefox")
    return f"{major}.0"


def _build_profiles() -> Tuple[RegistrationBrowserProfile, ...]:
    chrome_version_for_user_agent = _chrome_version_triple()
    firefox_version_for_user_agent = _firefox_rv_version()

    mac_chrome = RegistrationBrowserProfile(
        name="mac_chrome",
        impersonate="chrome",
        ua=(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{chrome_version_for_user_agent} Safari/537.36"
        ),
        heap_mode="chromium",
        navigator_prototype_keys=CHROME_NAVIGATOR_PROTOTYPE_KEYS,
        navigator_static_strings=CHROME_NAVIGATOR_STATIC_STRINGS,
        document_own_keys=CHROME_DOCUMENT_OWN_KEYS,
        window_enumerable_keys=CHROME_WINDOW_ENUMERABLE_KEYS,
        in_window_bits=CHROME_IN_WINDOW_BITS,
    )
    windows_chrome = RegistrationBrowserProfile(
        name="windows_chrome",
        impersonate="chrome",
        ua=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{chrome_version_for_user_agent} Safari/537.36"
        ),
        heap_mode="chromium",
        navigator_prototype_keys=CHROME_NAVIGATOR_PROTOTYPE_KEYS,
        navigator_static_strings=CHROME_NAVIGATOR_STATIC_STRINGS,
        document_own_keys=CHROME_DOCUMENT_OWN_KEYS,
        window_enumerable_keys=CHROME_WINDOW_ENUMERABLE_KEYS,
        in_window_bits=CHROME_IN_WINDOW_BITS,
    )
    linux_chrome = RegistrationBrowserProfile(
        name="linux_chrome",
        impersonate="chrome",
        ua=(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{chrome_version_for_user_agent} Safari/537.36"
        ),
        heap_mode="chromium",
        navigator_prototype_keys=CHROME_NAVIGATOR_PROTOTYPE_KEYS,
        navigator_static_strings=CHROME_NAVIGATOR_STATIC_STRINGS,
        document_own_keys=CHROME_DOCUMENT_OWN_KEYS,
        window_enumerable_keys=CHROME_WINDOW_ENUMERABLE_KEYS,
        in_window_bits=CHROME_IN_WINDOW_BITS,
    )
    windows_firefox = RegistrationBrowserProfile(
        name="windows_firefox",
        impersonate="firefox",
        ua=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:"
            f"{firefox_version_for_user_agent}) Gecko/20100101 Firefox/{firefox_version_for_user_agent}"
        ),
        heap_mode="none",
        navigator_prototype_keys=FIREFOX_NAVIGATOR_PROTOTYPE_KEYS,
        navigator_static_strings=FIREFOX_NAVIGATOR_STATIC_STRINGS,
        document_own_keys=FIREFOX_DOCUMENT_OWN_KEYS,
        window_enumerable_keys=FIREFOX_WINDOW_ENUMERABLE_KEYS,
        in_window_bits=FIREFOX_IN_WINDOW_BITS,
    )
    return (mac_chrome, windows_chrome, linux_chrome, windows_firefox)


_REGISTRATION_PROFILES: Tuple[RegistrationBrowserProfile, ...] = _build_profiles()


def random_registration_profile(
    rng: Optional[random.Random] = None,
) -> RegistrationBrowserProfile:
    """Choose one profile for a single registration (uniform over OS/engine variants)."""
    random_source = rng if rng is not None else random
    return random_source.choice(_REGISTRATION_PROFILES)
