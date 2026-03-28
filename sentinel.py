import base64
import copy
import hashlib
import json
import random
import time
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from browser_profile import RegistrationBrowserProfile, random_registration_profile
from engine_fingerprint_pools import sdk_r_pick, sdk_t_string

# Pools for registration display names (independent picks; uniformly random).
_FIRST_NAMES = (
    "James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael", "Linda",
    "William", "Elizabeth", "David", "Barbara", "Richard", "Susan", "Joseph", "Jessica",
    "Thomas", "Sarah", "Charles", "Karen", "Christopher", "Lisa", "Daniel", "Nancy",
    "Matthew", "Betty", "Anthony", "Margaret", "Mark", "Sandra", "Donald", "Ashley",
    "Steven", "Kimberly", "Paul", "Emily", "Andrew", "Donna", "Joshua", "Michelle",
    "Kenneth", "Carol", "Kevin", "Amanda", "Brian", "Melissa", "George", "Deborah",
    "Edward", "Stephanie", "Ronald", "Rebecca", "Timothy", "Sharon", "Jason", "Laura",
    "Jeffrey", "Cynthia", "Ryan", "Kathleen", "Jacob", "Amy", "Gary", "Angela",
    "Nicholas", "Shirley", "Eric", "Anna", "Jonathan", "Brenda", "Stephen", "Pamela",
    "Larry", "Emma", "Justin", "Nicole", "Scott", "Helen", "Brandon", "Samantha",
    "Benjamin", "Katherine", "Samuel", "Christine", "Frank", "Debra", "Gregory", "Rachel",
    "Raymond", "Carolyn", "Alexander", "Janet", "Patrick", "Catherine", "Jack", "Maria",
    "Dennis", "Heather", "Jerry", "Diane", "Tyler", "Ruth", "Aaron", "Julie",
    "Henry", "Olivia", "Jose", "Joyce", "Adam", "Virginia", "Douglas", "Victoria",
    "Nathan", "Kelly", "Zachary", "Lauren", "Kyle", "Christina", "Noah", "Joan",
    "Ethan", "Evelyn", "Jeremy", "Judith", "Walter", "Megan", "Christian", "Cheryl",
    "Keith", "Andrea", "Roger", "Hannah", "Terry", "Jacqueline", "Gerald", "Martha",
    "Harold", "Gloria", "Sean", "Teresa", "Austin", "Ann", "Carl", "Sara",
    "Arthur", "Madison", "Lawrence", "Frances", "Dylan", "Kathryn", "Jesse", "Janice",
    "Jordan", "Jean", "Bryan", "Abigail", "Billy", "Sophia", "Joe", "Alice",
    "Bruce", "Judy", "Gabriel", "Isabella", "Logan", "Julia", "Alan", "Grace",
    "Juan", "Amber", "Wayne", "Denise", "Roy", "Danielle", "Ralph", "Marilyn",
    "Randy", "Beverly", "Eugene", "Vincent", "Theresa", "Russell", "Diana",
    "Louis", "Natalie", "Philip", "Brittany", "Bobby", "Charlotte", "Johnny", "Marie",
    "Willie", "Kayla", "Albert", "Alexis", "Lori",
)
_LAST_NAMES = (
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas",
    "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson", "White",
    "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker", "Young",
    "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores",
    "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell",
    "Carter", "Roberts", "Gomez", "Phillips", "Evans", "Turner", "Diaz", "Parker",
    "Cruz", "Edwards", "Collins", "Reyes", "Stewart", "Morris", "Morales", "Murphy",
    "Cook", "Rogers", "Gutierrez", "Ortiz", "Morgan", "Cooper", "Peterson", "Bailey",
    "Reed", "Kelly", "Howard", "Ramos", "Kim", "Cox", "Ward", "Richardson",
    "Watson", "Brooks", "Chavez", "Wood", "James", "Bennett", "Gray", "Mendoza",
    "Ruiz", "Hughes", "Price", "Alvarez", "Castillo", "Sanders", "Patel", "Myers",
    "Long", "Ross", "Foster", "Jimenez", "Powell", "Jenkins", "Perry", "Russell",
    "Sullivan", "Bell", "Coleman", "Butler", "Henderson", "Barnes", "Gonzales", "Fisher",
    "Vasquez", "Simmons", "Romero", "Jordan", "Patterson", "Alexander", "Hamilton", "Graham",
    "Reynolds", "Griffin", "Wallace", "Moreno", "West", "Cole", "Hayes", "Bryant",
    "Herrera", "Gibson", "Ellis", "Tran", "Medina", "Aguilar", "Stevens", "Murray",
    "Ford", "Castro", "Marshall", "Owens", "Harrison", "Fernandez", "Mcdonald", "Woods",
    "Washington", "Kennedy", "Wells", "Vargas", "Henry", "Chen", "Freeman", "Webb",
    "Tucker", "Guzman", "Burns", "Crawford", "Olson", "Simpson", "Porter", "Hunter",
    "Gordon", "Mendez", "Silva", "Shaw", "Snyder", "Mason", "Dixon", "Munoz",
    "Hunt", "Hicks", "Holmes", "Palmer", "Wagner", "Black", "Robertson", "Boyd",
    "Rose", "Stone", "Salazar", "Fox", "Warren", "Mills", "Meyer", "Rice",
    "Schmidt", "Garza", "Daniels", "Ferguson", "Nichols", "Stephens", "Soto", "Weaver",
    "Ryan", "Gardner", "Payne", "Grant", "Dunn", "Kelley", "Spencer", "Hawkins",
    "Arnold", "Pierce", "Vazquez", "Hansen", "Peters", "Santos", "Hart", "Bradley",
    "Knight", "Elliott", "Cunningham", "Duncan", "Armstrong", "Hudson", "Carroll", "Lane",
    "Riley", "Andrews", "Alvarado", "Ray", "Delgado", "Berry", "Perkins", "Hoffman",
    "Johnston", "Matthews", "Pena", "Richards", "Contreras", "Willis", "Carpenter", "Lawrence",
    "Sandoval", "Guerrero", "George", "Chapman", "Rios", "Estrada", "Ortega", "Watkins",
    "Greene", "Nunez", "Wheeler", "Valencia", "Franklin", "Lawson", "Fields", "Bishop",
    "Schneider", "Muller", "Weber", "Becker", "Neumann", "Hartmann", "Wolf", "Zimmermann",
)


def generate_random_display_name() -> str:
    """Return a random first + last name (uniform independent choices)."""
    return f"{random.choice(_FIRST_NAMES)} {random.choice(_LAST_NAMES)}"


def generate_random_birthdate(min_year: int = 1985, max_year: int = 2005) -> str:
    """
    Return a random calendar-valid birthdate as YYYY-MM-DD.
    Bounds are inclusive; day/month are chosen so invalid dates cannot occur.
    """
    start = date(min_year, 1, 1)
    end = date(max_year, 12, 31)
    span = (end - start).days
    picked = start + timedelta(days=random.randint(0, span))
    return picked.isoformat()

FNV_OFFSET_BASIS = 2166136261
FNV_PRIME = 16777619
MIX_CONSTANT_1 = 2246822507
MIX_CONSTANT_2 = 3266489909

# Sentinel iframe `frame.html?sv=20260219f9f6`: sdk.js getConfig slots 5, 6, 15.
_SENTINEL_IFRAME_SCRIPT_SRC = "https://sentinel.openai.com/sentinel/20260219f9f6/sdk.js"
_SENTINEL_IFRAME_SLOT6 = None
_SENTINEL_IFRAME_URL_QUERY_KEYS = "sv"

def _fnv1a_32(data: str) -> int:
    """Compute 32-bit FNV-1a hash with additional mixing."""
    h = FNV_OFFSET_BASIS
    for c in data:
        h ^= ord(c)
        h = (h * FNV_PRIME) & 0xFFFFFFFF
    h ^= h >> 16
    h = (h * MIX_CONSTANT_1) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * MIX_CONSTANT_2) & 0xFFFFFFFF
    h ^= h >> 16
    return h & 0xFFFFFFFF

def _hex8(hash_val: int) -> str:
    """Format the hash as a zero-padded 8-digit lowercase hex string."""
    return f"{hash_val:08x}"

def _stable_rng(did: str) -> random.Random:
    """Deterministic RNG seeded by SHA-256 hash of device ID."""
    h = hashlib.sha256(did.encode("utf-8")).digest()
    seed = int.from_bytes(h[:8], "big")
    return random.Random(seed)

def _base64_encode(data: Any) -> str:
    """JSON encode and base64 encode a Python object."""
    s = json.dumps(data, separators=(",", ":"))
    return base64.b64encode(s.encode("utf-8")).decode("ascii")

def _format_js_gmt_suffix(offset_minutes: int) -> str:
    """Format offset like JavaScript Date: +0900, -0500, +0530."""
    sign = "+" if offset_minutes >= 0 else "-"
    total = abs(offset_minutes)
    h, m = divmod(total, 60)
    return f"{sign}{h:02d}{m:02d}"


def _locale_profile(
    langs: str, offset_minutes: int, timezone_name: str, timezone_id: str
) -> Dict[str, Any]:
    """Build one coherent locale/timezone profile."""
    return {
        "langs": langs,
        "offset_minutes": offset_minutes,
        "timezone_name": timezone_name,
        "timezone_id": timezone_id,
    }


# Modern Chromium-observed jsHeapSizeLimit values (bytes).
_CHROMIUM_JS_HEAP_LIMITS: Tuple[int, ...] = (
    4_294_967_296,  # 4 GiB
    4_294_705_152,  # common near-4 GiB variant
)


# World locale profiles: navigator.languages + UTC offset + timezone id/name in one place.
# Excludes mainland China (no zh-CN / Beijing-CST-only pairing). HK/TW/SG use non-mainland tags.
_LOCALE_PROFILES: Tuple[Dict[str, Any], ...] = (
    # Americas
    _locale_profile("en-US,en", -300, "Eastern Standard Time", "America/New_York"),
    _locale_profile("en-US,en", -360, "Central Standard Time", "America/Chicago"),
    _locale_profile("en-US,en", -420, "Mountain Standard Time", "America/Denver"),
    _locale_profile("en-US,en", -480, "Pacific Standard Time", "America/Los_Angeles"),
    _locale_profile("en-CA,en", -300, "Eastern Standard Time", "America/Toronto"),
    _locale_profile("fr-CA,fr", -300, "Eastern Standard Time", "America/Toronto"),
    _locale_profile("pt-BR,pt", -180, "Brasilia Standard Time", "America/Sao_Paulo"),
    _locale_profile("es-MX,es", -360, "Central Standard Time", "America/Mexico_City"),
    _locale_profile("es-AR,es", -180, "Argentina Standard Time", "America/Argentina/Buenos_Aires"),
    _locale_profile("es-CO,es", -300, "Colombia Standard Time", "America/Bogota"),
    # Europe & Africa
    _locale_profile("en-GB,en", 0, "Greenwich Mean Time", "Europe/London"),
    _locale_profile("de-DE,de", 60, "Central European Standard Time", "Europe/Berlin"),
    _locale_profile("fr-FR,fr", 60, "Central European Standard Time", "Europe/Paris"),
    _locale_profile("es-ES,es", 60, "Central European Standard Time", "Europe/Madrid"),
    _locale_profile("it-IT,it", 60, "Central European Standard Time", "Europe/Rome"),
    _locale_profile("nl-NL,nl", 60, "Central European Standard Time", "Europe/Amsterdam"),
    _locale_profile("pl-PL,pl", 60, "Central European Standard Time", "Europe/Warsaw"),
    _locale_profile("sv-SE,sv", 60, "Central European Standard Time", "Europe/Stockholm"),
    _locale_profile("no-NO,no", 60, "Central European Standard Time", "Europe/Oslo"),
    _locale_profile("fi-FI,fi", 120, "Eastern European Standard Time", "Europe/Helsinki"),
    _locale_profile("el-GR,el", 120, "Eastern European Standard Time", "Europe/Athens"),
    _locale_profile("tr-TR,tr", 180, "Turkey Time", "Europe/Istanbul"),
    _locale_profile("en-ZA,en", 120, "South Africa Standard Time", "Africa/Johannesburg"),
    # Middle East & South Asia
    _locale_profile("ar-SA,ar", 180, "Arabian Standard Time", "Asia/Riyadh"),
    _locale_profile("he-IL,he", 120, "Israel Standard Time", "Asia/Jerusalem"),
    _locale_profile("en-AE,en", 240, "Gulf Standard Time", "Asia/Dubai"),
    _locale_profile("hi-IN,hi", 330, "India Standard Time", "Asia/Kolkata"),
    _locale_profile("en-IN,en", 330, "India Standard Time", "Asia/Kolkata"),
    # East Asia & Pacific (non–mainland China)
    _locale_profile("ja-JP,ja", 540, "Japan Standard Time", "Asia/Tokyo"),
    _locale_profile("ko-KR,ko", 540, "Korea Standard Time", "Asia/Seoul"),
    _locale_profile("zh-TW,zh", 480, "Taipei Standard Time", "Asia/Taipei"),
    _locale_profile("en-SG,en", 480, "Singapore Standard Time", "Asia/Singapore"),
    _locale_profile("th-TH,th", 420, "Indochina Time", "Asia/Bangkok"),
    _locale_profile("vi-VN,vi", 420, "Indochina Time", "Asia/Ho_Chi_Minh"),
    _locale_profile("id-ID,id", 420, "Western Indonesia Time", "Asia/Jakarta"),
    _locale_profile("en-PH,en", 480, "Philippine Standard Time", "Asia/Manila"),
    _locale_profile("en-AU,en", 600, "Australian Eastern Standard Time", "Australia/Sydney"),
    _locale_profile("en-NZ,en", 780, "New Zealand Daylight Time", "Pacific/Auckland"),
)


def get_config(
    sid: Optional[str] = None,
    screen_width: Optional[int] = None,
    screen_height: Optional[int] = None,
    *,
    profile: RegistrationBrowserProfile,
    rng: Optional[random.Random] = None,
    wall_time_ms: Optional[float] = None,
) -> List[Any]:
    """
    Builds Sentinel PoW config blob.
    Uses deterministic RNG if provided, otherwise system random.
    UA and navigator fields follow ``profile`` (aligned with curl_cffi impersonate).
    """
    random_source = rng if rng is not None else random
    if sid is None:
        sid = str(uuid.uuid4())
    if screen_width is None:
        screen_width = random_source.choice([1920, 1366, 1536, 1440, 1280])
    if screen_height is None:
        screen_height = random_source.choice([1080, 768, 900, 864, 720])
    wall_ms = time.time() * 1000 if wall_time_ms is None else float(wall_time_ms)

    ua_chosen = profile.ua

    locale_profile = random_source.choice(_LOCALE_PROFILES)
    langs = locale_profile["langs"]
    lang = langs.split(",", 1)[0].strip()
    offset_minutes = int(locale_profile["offset_minutes"])
    tz_name = str(locale_profile["timezone_name"])
    tz = timezone(timedelta(minutes=offset_minutes))
    utc_dt = datetime.fromtimestamp(wall_ms / 1000.0, tz=timezone.utc)
    local_dt = utc_dt.astimezone(tz)
    gmt_suffix = _format_js_gmt_suffix(offset_minutes)
    date_str = local_dt.strftime("%a %b %d %Y %H:%M:%S") + f" GMT{gmt_suffix} ({tz_name})"

    if profile.heap_mode == "chromium":
        js_heap = random_source.choice(_CHROMIUM_JS_HEAP_LIMITS)
    else:
        js_heap = None

    hw_concurrency = random_source.choice([8, 12, 16])
    perf_origin = wall_ms + random_source.uniform(-500.0, 500.0)

    slot10_t = sdk_t_string(
        random_source,
        profile.navigator_prototype_keys,
        profile.navigator_static_strings,
        user_agent=ua_chosen,
        language=lang,
        languages_joined=langs,
    )
    slot11_doc = sdk_r_pick(profile.document_own_keys, random_source)
    slot12_win = sdk_r_pick(profile.window_enumerable_keys, random_source)
    # Fingerprint is generated once per short registration flow, so keep now() in
    # a short-lived document range instead of long-session values.
    perf_now_ms = random_source.uniform(200.0, 120_000.0)

    config: List[Any] = [
        screen_width + screen_height,  # 0
        date_str,                      # 1
        js_heap,                       # 2  performance.memory.jsHeapSizeLimit (Chromium) or null
        random_source.random(),        # 3
        ua_chosen,                     # 4
        _SENTINEL_IFRAME_SCRIPT_SRC,   # 5
        _SENTINEL_IFRAME_SLOT6,        # 6
        lang,                          # 7
        langs,                         # 8
        random_source.random(),        # 9
        slot10_t,                      # 10 T()
        slot11_doc,                    # 11 R(Object.keys(document))
        slot12_win,                    # 12 R(Object.keys(window))
        perf_now_ms,                   # 13 performance.now()
        sid,                           # 14
        _SENTINEL_IFRAME_URL_QUERY_KEYS,  # 15
        hw_concurrency,                # 16
        perf_origin,                   # 17 performance.timeOrigin
    ] + list(profile.in_window_bits)   # 18..24 Number(...) in window

    return config[:25]

def make_fingerprint_for_registration(
    did: str, profile: RegistrationBrowserProfile
) -> List[Any]:
    """
    Generate deterministic mock-browser config for registration,
    stable from device id, consistent with the chosen registration profile.
    """
    rng = _stable_rng(did)
    wall_ms = time.time() * 1000
    return get_config(
        sid=did, profile=profile, rng=rng, wall_time_ms=wall_ms
    )

def generate_p(config: List[Any], seed: str, difficulty: str) -> Optional[str]:
    """Generate proof p token candidate by hashing seed+fingerprint and testing difficulty."""
    base64_fingerprint = _base64_encode(config)
    hash_input = seed + base64_fingerprint
    hash_hex = _hex8(_fnv1a_32(hash_input))
    required_len = len(difficulty)
    if hash_hex[:required_len] <= difficulty:
        return f"{base64_fingerprint}~S"
    return None

def solve_proof_of_work(seed: str, difficulty: str, config: List[Any], max_attempts: int = 500_000) -> Optional[str]:
    """Brute-force mutate config to find proof p token below difficulty threshold."""
    for i in range(max_attempts):
        config[3] = i
        config[9] = random.randint(0, 100)
        proof_token = generate_p(config, seed, difficulty)
        if proof_token is not None:
            return proof_token
    return None

def call_sentinel_req(
    did: str,
    flow: str,
    proxies=None,
    session=None,
    fingerprint: Optional[List[Any]] = None,
    profile: Optional[RegistrationBrowserProfile] = None,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Execute Sentinel request flow with PoW solving if required."""
    if session is None:
        from curl_cffi import requests as req_session
        session = req_session
    active_registration_profile = profile or random_registration_profile()
    browser_impersonate = active_registration_profile.impersonate
    headers = {
        "origin": "https://sentinel.openai.com",
        "referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6",
        "content-type": "text/plain;charset=UTF-8",
    }
    payload_init = json.dumps({"p": "", "id": did, "flow": flow})
    resp1 = session.post(
        "https://sentinel.openai.com/backend-api/sentinel/req",
        headers=headers,
        data=payload_init,
        proxies=proxies,
        impersonate=browser_impersonate,
        timeout=30,
    )
    if resp1.status_code != 200:
        return None, None, None
    data1 = resp1.json()
    token = data1.get("token")
    turnstile_dx = data1.get("turnstile", {}).get("dx", "")
    pow_data = data1.get("proofofwork", {})
    if not pow_data.get("required", False):
        print(f"[DEBUG] sentinel {flow}: PoW not required, token={token[:32] if token else None}...")
        return token, turnstile_dx, None
    seed = pow_data.get("seed", "e")
    difficulty = pow_data.get("difficulty", "0632ff")
    print(f"[DEBUG] sentinel {flow}: PoW required, seed={seed}, difficulty={difficulty}")
    if fingerprint is not None:
        config = copy.deepcopy(fingerprint)
    else:
        config = get_config(
            sid=str(uuid.uuid4()), profile=active_registration_profile
        )
    proof_p = solve_proof_of_work(seed, difficulty, config)
    if proof_p is None:
        print(f"[DEBUG] sentinel {flow}: PoW solve FAILED after max attempts")
        return None, None, None
    print(f"[DEBUG] sentinel {flow}: PoW solved, p={proof_p[:40]}...")
    payload_submit = json.dumps({"p": proof_p, "id": did, "flow": flow})
    resp2 = session.post(
        "https://sentinel.openai.com/backend-api/sentinel/req",
        headers=headers,
        data=payload_submit,
        proxies=proxies,
        impersonate=browser_impersonate,
        timeout=30,
    )
    if resp2.status_code != 200:
        return None, None, None
    data2 = resp2.json()
    return data2.get("token"), data2.get("turnstile", {}).get("dx", ""), proof_p
