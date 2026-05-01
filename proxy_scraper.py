#!/usr/bin/env python3
"""
XTM Proxy Scraper v3.0
Fixes: token security, protocol-aware testing, proper error handling,
       no credential leakage in git remote, no DDoS on single test endpoint.
"""

import os
import sys
import requests
import re
import time
import json
import base64
import logging
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ── Optional SOCKS support ────────────────────────────────────────────────────
try:
    import socks  # noqa: F401
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False

# ── Optional encryption (Termux: pip install cryptography) ───────────────────
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    filename="xtm_errors.log",
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# ── Colors ────────────────────────────────────────────────────────────────────
G   = "\033[38;5;46m"
GGG = "\033[38;5;49m"
XX  = "\033[1;92m"
RST = "\033[0m"

CONFIG_FILE = "config.json"   # username + repo only — no token
TOKEN_FILE  = ".xtm_token"    # encrypted token file


# ═══════════════════════════════════════════════════════════════════════════════
#  TOKEN ENCRYPTION  (Termux-compatible — no keychain needed)
# ═══════════════════════════════════════════════════════════════════════════════

def _machine_key() -> bytes:
    """Stable machine-bound key derived from device environment."""
    parts = [
        os.environ.get("HOME", ""),
        os.environ.get("USER", os.environ.get("LOGNAME", "")),
        str(os.getuid()) if hasattr(os, "getuid") else "0",
    ]
    seed = "|".join(parts).encode()
    salt = hashlib.sha256(seed + b"xtm_salt").digest()[:16]
    if CRYPTO_AVAILABLE:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
        return base64.urlsafe_b64encode(kdf.derive(seed))
    return base64.urlsafe_b64encode(hashlib.sha256(seed + salt).digest())


def save_token(token: str):
    """Encrypt and save token. Falls back to XOR obfuscation without cryptography."""
    key = _machine_key()
    if CRYPTO_AVAILABLE:
        encrypted = Fernet(key).encrypt(token.encode())
        with open(TOKEN_FILE, "wb") as fh:
            fh.write(encrypted)
    else:
        k = key * (len(token) // len(key) + 1)
        obfuscated = bytes(a ^ b for a, b in zip(token.encode(), k[:len(token)]))
        with open(TOKEN_FILE, "wb") as fh:
            fh.write(base64.b64encode(obfuscated))
    os.chmod(TOKEN_FILE, 0o600)


def load_token() -> str | None:
    """Decrypt and return token."""
    if not os.path.exists(TOKEN_FILE):
        return None
    try:
        key = _machine_key()
        with open(TOKEN_FILE, "rb") as fh:
            data = fh.read()
        if CRYPTO_AVAILABLE:
            return Fernet(key).decrypt(data).decode()
        obfuscated = base64.b64decode(data)
        k = key * (len(obfuscated) // len(key) + 1)
        return bytes(a ^ b for a, b in zip(obfuscated, k[:len(obfuscated)])).decode()
    except Exception as exc:
        logging.warning("load_token failed: %s", exc)
        return None

LOGO = f"""
╔━━━━━━━━━━━━━━━━━━━━━━╗━━━━━━━━━━━╗
║      \x1b[38;5;47m┳┳┓┏┓┓┏┳┓┳      ║PROXY      ║
║      \x1b[38;5;49m┃┃┃┣┫┣┫┃┃┃      ║SCRAPER    ║
║      \x1b[38;5;50m┛ ┗┛┗┛┗┻┛┻      ║VERSION:3.1║
╚━━━━━━━━━━━━━━━━━━━━━━╝━━━━━━━━━━━╝
{G}⋆{GGG}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{G}⋆
\x1b[1;92m {XX}[\x1b[1;92m⍣{XX}]\x1b[38;5;46m OWNER     : MAHDI
\x1b[1;92m {XX}[\x1b[1;92m⍣{XX}] \x1b[38;5;47mFACEBOOK  : MAHDI
\x1b[1;92m {XX}[\x1b[1;92m⍣{XX}] \x1b[38;5;48mGITHUB    : MAHDI-143
{G}⋆{GGG}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{G}⋆{RST}"""


# ═══════════════════════════════════════════════════════════════════════════════
#  UI HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def linex():
    print(f'{G}⋆{GGG}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{G}⋆{RST}')

def clear():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(LOGO)

def wait_for_enter():
    input("\n\033[93m[+] Press Enter to continue...\033[0m")

def info(msg):  print(f"\033[96m[+] {msg}{RST}")
def ok(msg):    print(f"\033[92m[✓] {msg}{RST}")
def warn(msg):  print(f"\033[93m[!] {msg}{RST}")
def err(msg):   print(f"\033[91m[✗] {msg}{RST}")


# ═══════════════════════════════════════════════════════════════════════════════
#  SECURE CONFIG  (token in encrypted file, not plaintext JSON)
# ═══════════════════════════════════════════════════════════════════════════════

def load_config():
    """Return {username, repo, token} or None."""
    if not os.path.exists(CONFIG_FILE):
        return None
    try:
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
        token = load_token()
        if not token:
            warn("Token file missing or corrupted — re-run setup.")
            return None
        cfg["token"] = token
        return cfg
    except Exception as exc:
        logging.warning("load_config failed: %s", exc)
        return None


def save_config(username: str, token: str, repo: str):
    """Save non-secret fields to JSON; token goes to encrypted file."""
    with open(CONFIG_FILE, "w") as f:
        json.dump({"username": username, "repo": repo}, f)
    save_token(token)


# ═══════════════════════════════════════════════════════════════════════════════
#  GITHUB API  (no credentials in git remote URLs)
# ═══════════════════════════════════════════════════════════════════════════════

GH_API = "https://api.github.com"

def _gh_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def gh_create_or_verify_repo(username: str, token: str, repo: str) -> bool:
    """Create repo if it doesn't exist. Return True on success."""
    headers = _gh_headers(token)
    # Check existence first
    r = requests.get(f"{GH_API}/repos/{username}/{repo}", headers=headers, timeout=10)
    if r.status_code == 200:
        ok(f"Repository '{repo}' found.")
        return True
    if r.status_code != 404:
        err(f"GitHub API error: {r.status_code} — {r.json().get('message','')}")
        return False
    # Create it
    r = requests.post(
        f"{GH_API}/user/repos",
        headers=headers,
        json={"name": repo, "public": True, "description": "Proxy list — XTM tool"},
        timeout=10,
    )
    if r.status_code == 201:
        ok(f"Repository '{repo}' created.")
        return True
    err(f"Could not create repo: {r.json().get('message','unknown error')}")
    return False


def gh_push_file(username: str, token: str, repo: str, content: str) -> bool:
    """
    Push proxies.txt via the Contents API — no git binary, no credential leakage.
    Uses PUT /repos/{owner}/{repo}/contents/{path}.
    """
    headers = _gh_headers(token)
    api_url = f"{GH_API}/repos/{username}/{repo}/contents/proxies.txt"

    # Fetch current SHA (required for updates)
    sha = None
    r = requests.get(api_url, headers=headers, timeout=10)
    if r.status_code == 200:
        sha = r.json().get("sha")

    encoded = base64.b64encode(content.encode()).decode()
    payload = {
        "message": f"Update proxies — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "content": encoded,
        "branch": "main",
    }
    if sha:
        payload["sha"] = sha

    r = requests.put(api_url, headers=headers, json=payload, timeout=20)
    if r.status_code in (200, 201):
        return True
    err(f"Push failed: {r.status_code} — {r.json().get('message','')}")
    logging.warning("gh_push_file failed: %s %s", r.status_code, r.text)
    return False


# ═══════════════════════════════════════════════════════════════════════════════
#  SETUP / CHANGE LINK
# ═══════════════════════════════════════════════════════════════════════════════

def setup() -> dict | None:
    config = load_config()
    if config:
        return config

    clear()
    warn("FIRST TIME SETUP")
    if CRYPTO_AVAILABLE:
        info("Token will be encrypted with Fernet (AES-128) — install cryptography for this.")
    else:
        info("cryptography not installed — token stored with XOR obfuscation.")
        info("For stronger security: pip install cryptography")

    username = input("\033[96m[?] GitHub username: \033[0m").strip()
    token    = input("\033[96m[?] GitHub token (repo scope): \033[0m").strip()

    if not username or not token:
        err("Username and token are required.")
        wait_for_enter()
        return None

    create = input("\033[96m[?] Create a new repository? (y/n): \033[0m").lower()
    if create == "y":
        repo = input("\033[96m[?] Repository name [proxies]: \033[0m").strip() or "proxies"
    else:
        repo = input("\033[96m[?] Existing repository name: \033[0m").strip()
        if not repo:
            err("Repository name required.")
            wait_for_enter()
            return None

    if not gh_create_or_verify_repo(username, token, repo):
        wait_for_enter()
        return None

    save_config(username, token, repo)
    ok("Setup complete — token saved to encrypted file.")
    wait_for_enter()
    return load_config()


def change_link():
    clear()
    cfg = load_config()
    current_user = cfg["username"] if cfg else "None"
    current_repo = cfg["repo"]     if cfg else "proxies"

    warn("CHANGE GITHUB SETTINGS")
    username = input(f"\033[96m[?] New username (current: {current_user}): \033[0m").strip()
    token    = input("\033[96m[?] New token: \033[0m").strip()
    repo     = input(f"\033[96m[?] New repo (current: {current_repo}): \033[0m").strip() or current_repo

    if not username or not token:
        err("Username and token required.")
    else:
        save_config(username, token, repo)
        ok("Settings updated.")
    wait_for_enter()


# ═══════════════════════════════════════════════════════════════════════════════
#  PROXY SOURCES  (tagged by protocol so we keep type info)
# ═══════════════════════════════════════════════════════════════════════════════

SOURCES: dict[str, list[str]] = {
    "http": [
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all",
        "https://proxy-list.download/api/v1/get?type=http",
    ],
    "socks4": [
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4&timeout=10000&country=all",
        "https://proxy-list.download/api/v1/get?type=socks4",
    ],
    "socks5": [
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all",
        "https://proxy-list.download/api/v1/get?type=socks5",
    ],
}

# Multiple test endpoints — rotated to avoid hammering one service
TEST_ENDPOINTS = [
    "http://httpbin.org/ip",
    "http://ip-api.com/json",
    "http://api.ipify.org",
    "http://checkip.amazonaws.com",
]


def fetch_all_proxies() -> list[dict]:
    """
    Fetch from all sources. Each proxy entry: {proxy, protocol}.
    Deduplicates per (proxy, protocol) pair so type info is preserved.
    """
    seen: set[tuple] = set()
    result: list[dict] = []

    info("FETCHING PROXIES FROM SOURCES...\n")

    for protocol, urls in SOURCES.items():
        for url in urls:
            try:
                r = requests.get(url, timeout=15)
                r.raise_for_status()
                found = re.findall(r'\d+\.\d+\.\d+\.\d+:\d+', r.text)
                added = 0
                for p in found:
                    key = (p, protocol)
                    if key not in seen:
                        seen.add(key)
                        result.append({"proxy": p, "protocol": protocol})
                        added += 1
                ok(f"+{added} {protocol} from {url.split('/')[2]}")
            except requests.RequestException as exc:
                err(f"Failed: {url.split('/')[2]}")
                logging.warning("fetch %s: %s", url, exc)

    return result


# ═══════════════════════════════════════════════════════════════════════════════
#  PROTOCOL-AWARE PROXY TESTER
# ═══════════════════════════════════════════════════════════════════════════════

def _proxy_dict(protocol: str, proxy: str) -> dict:
    """Build the requests proxies dict for the correct protocol."""
    if protocol == "http":
        return {"http": f"http://{proxy}", "https": f"http://{proxy}"}
    if protocol == "socks4":
        return {"http": f"socks4://{proxy}", "https": f"socks4://{proxy}"}
    if protocol == "socks5":
        return {"http": f"socks5://{proxy}", "https": f"socks5://{proxy}"}
    return {}


def test_proxy(entry: dict, timeout: int = 5) -> dict | None:
    """
    Test a proxy against rotating endpoints.
    Returns {proxy, protocol, speed} or None if all endpoints fail.
    SOCKS proxies skipped gracefully if PySocks not installed.
    """
    proxy    = entry["proxy"]
    protocol = entry["protocol"]

    if protocol in ("socks4", "socks5") and not SOCKS_AVAILABLE:
        return None  # silently skip — warn user once at startup

    proxies = _proxy_dict(protocol, proxy)
    if not proxies:
        return None

    # Rotate through endpoints — first success wins
    for i, url in enumerate(TEST_ENDPOINTS):
        try:
            start = time.monotonic()
            r = requests.get(url, proxies=proxies, timeout=timeout)
            elapsed = time.monotonic() - start
            if r.status_code == 200:
                return {"proxy": proxy, "protocol": protocol, "speed": round(elapsed, 2)}
        except Exception as exc:
            logging.debug("test_proxy %s %s endpoint %s: %s", protocol, proxy, i, exc)
            continue

    return None


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN HARVEST FLOW
# ═══════════════════════════════════════════════════════════════════════════════

def update_proxies():
    clear()
    config = setup()
    if not config:
        return

    if not SOCKS_AVAILABLE:
        warn("PySocks not installed — SOCKS4/SOCKS5 proxies will be skipped.")
        warn("Install with: pip install requests[socks]")

    all_proxies = fetch_all_proxies()
    if not all_proxies:
        err("No proxies fetched from any source.")
        wait_for_enter()
        return

    info(f"TOTAL UNIQUE PROXIES FETCHED: {len(all_proxies)}")

    # ── Intensity selection ──────────────────────────────────────────────────
    print("\n\033[93m╔════════════════════════════════════════════════════╗")
    print("║  SELECT TESTING INTENSITY:                          ║")
    print("║  [1] LIGHT   — Test 500  proxies (fast)            ║")
    print("║  [2] MEDIUM  — Test 2000 proxies (recommended)     ║")
    print(f"║  [3] EXTREME — Test ALL  {len(all_proxies):<5} proxies (thorough)   ║")
    print(f"\033[93m╚════════════════════════════════════════════════════╝{RST}")

    intensity = input("\033[96m[?] Choose (1/2/3): \033[0m").strip()
    limits    = {"1": (500, 100), "2": (2000, 150), "3": (len(all_proxies), 200)}
    test_limit, workers = limits.get(intensity, (1000, 100))
    test_limit = min(test_limit, len(all_proxies))

    info(f"Testing {test_limit} proxies with {workers} workers...\n")

    # ── Testing ──────────────────────────────────────────────────────────────
    working: list[dict] = []
    proxy_list = all_proxies[:test_limit]

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(test_proxy, p): p for p in proxy_list}
        for i, future in enumerate(as_completed(futures), 1):
            try:
                result = future.result()
            except Exception as exc:
                logging.warning("future.result() raised: %s", exc)
                result = None

            if result:
                working.append(result)
                icon = "⚡" if result["speed"] < 1 else "✓" if result["speed"] < 3 else "🐢"
                print(f"\033[92m   [{len(working)}] {icon} {result['protocol']:<6} {result['proxy']} — {result['speed']}s{RST}")

            if i % 100 == 0:
                pct = i * 100 // test_limit
                info(f"Progress: {i}/{test_limit} ({pct}%)")

    ok(f"TESTING COMPLETE — {len(working)} working proxies found.")

    if not working:
        err("No working proxies found.")
        wait_for_enter()
        return

    speeds = [p["speed"] for p in working]
    print(f"\n\033[96m   Fastest : {min(speeds)}s")
    print(f"   Slowest : {max(speeds)}s")
    print(f"   Average : {sum(speeds)/len(speeds):.2f}s")
    print(f"   Success : {len(working)*100//test_limit}%{RST}")

    # ── Speed filter ─────────────────────────────────────────────────────────
    print("\n\033[93m╔══════════════════════════════════════════════════╗")
    print("║  [1] ULTRA FAST — < 1s                          ║")
    print("║  [2] FAST       — < 2s                          ║")
    print("║  [3] GOOD       — ≤ 4s                          ║")
    print(f"║  [4] ALL        — keep everything               ║")
    print(f"\033[93m╚══════════════════════════════════════════════════╝{RST}")

    fc = input("\033[96m[?] Filter (1/2/3/4): \033[0m").strip()
    thresholds = {"1": 1.0, "2": 2.0, "3": 4.0}
    if fc in thresholds:
        filtered = [p for p in working if p["speed"] < thresholds[fc]]
        if filtered:
            working = filtered
            ok(f"Kept {len(working)} proxies.")
        else:
            warn(f"No proxies met that threshold — keeping all {len(working)}.")

    # ── Build output ─────────────────────────────────────────────────────────
    speeds = [p["speed"] for p in working]
    header = (
        f"# Proxy List — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"# Total   : {len(working)}\n"
        f"# Fastest : {min(speeds)}s | Slowest : {max(speeds)}s | "
        f"Average : {sum(speeds)/len(speeds):.2f}s\n"
        f"# Format  : protocol://ip:port\n"
        f"# {'='*50}\n\n"
    )
    # Each proxy tagged with its protocol — actually usable
    lines = "\n".join(f"{p['protocol']}://{p['proxy']}" for p in working)
    file_content = header + lines + "\n"

    # ── Save / push ──────────────────────────────────────────────────────────
    print("\n\033[93m╔══════════════════════════════════════════════════╗")
    print("║  [A] AUTO   — save locally + push to GitHub     ║")
    print("║  [M] MANUAL — preview first, then choose        ║")
    print("║  [S] SAVE   — save locally only (no GitHub)     ║")
    print(f"\033[93m╚══════════════════════════════════════════════════╝{RST}")

    choice = input("\033[96m[?] (A/M/S): \033[0m").upper().strip()

    if choice == "M":
        print(f"\n\033[96mPREVIEW (first 30):{RST}")
        linex()
        for p in working[:30]:
            print(f"\033[92m  {p['protocol']:<6} {p['proxy']} — {p['speed']}s{RST}")
        if len(working) > 30:
            warn(f"... and {len(working)-30} more")
        linex()
        print("\n\033[93m╔══════════════════════════════════════════════════╗")
        print("║  [A] Save locally + push to GitHub             ║")
        print("║  [S] Save locally only                         ║")
        print(f"║  [X] Discard                                   ║")
        print(f"\033[93m╚══════════════════════════════════════════════════╝{RST}")
        choice = input("\033[96m[?] (A/S/X): \033[0m").upper().strip()
        if choice == "X":
            warn("Discarded — nothing saved.")
            wait_for_enter()
            return

    if choice not in ("A", "S"):
        warn("Invalid choice — nothing saved.")
        wait_for_enter()
        return

    # Save locally
    local_path = "proxies.txt"
    with open(local_path, "w") as f:
        f.write(file_content)
    ok(f"Saved {len(working)} proxies → {local_path}")

    # Push if requested
    if choice == "A":
        info("Pushing to GitHub via API...")
        success = gh_push_file(
            config["username"], config["token"], config["repo"], file_content
        )
        if success:
            raw_url = (
                f"https://raw.githubusercontent.com/"
                f"{config['username']}/{config['repo']}/main/proxies.txt"
            )
            ok(f"Pushed! Live at:\n   {raw_url}")
        else:
            warn("Push failed — proxies saved locally only.")

    wait_for_enter()


# ═══════════════════════════════════════════════════════════════════════════════
#  MENU
# ═══════════════════════════════════════════════════════════════════════════════

def show_link():
    clear()
    config = load_config()
    if not config:
        err("Not configured. Run setup first.")
        wait_for_enter()
        return
    url = f"https://raw.githubusercontent.com/{config['username']}/{config['repo']}/main/proxies.txt"
    ok(f"Your live proxy URL:\n   {url}")
    try:
        r = requests.get(url, timeout=8)
        if r.status_code == 200:
            count = len([l for l in r.text.splitlines() if re.match(r'\w+://\d', l)])
            info(f"Currently {count} proxies online.")
        else:
            warn("URL not yet active — harvest proxies first.")
    except requests.RequestException as exc:
        warn(f"Could not reach URL: {exc}")
    wait_for_enter()


def main():
    if not SOCKS_AVAILABLE:
        # Warn once at startup — not on every test
        pass  # handled inside update_proxies()

    while True:
        clear()
        linex()
        print("\033[93m  [1] HARVEST PROXIES")
        print("  [2] SHOW MY LINK")
        print("  [3] CHANGE GITHUB SETTINGS")
        print(f"  [0] EXIT{RST}")
        linex()

        choice = input("\033[96m[?] Choice: \033[0m").strip()
        if choice == "1":
            update_proxies()
        elif choice == "2":
            show_link()
        elif choice == "3":
            change_link()
        elif choice == "0":
            ok("Goodbye.")
            sys.exit(0)
        else:
            warn("Invalid choice.")
            time.sleep(0.8)


if __name__ == "__main__":
    main()
