# Lantern: Attack Surface Management

Lantern is a self-hosted web tool that tracks an organization's external assets (domains and IPs) and detects exposure: subdomains, risky open ports, web misconfigurations, and known CVEs on detected services. Scans can run on a schedule, and results can be exported as reports.

> **Legal notice:** Only scan assets you own or have explicit written permission to test. Scanning systems you do not control may be illegal. The author is not responsible for misuse.

## Features

- **Asset inventory** for domains, IPs, and CIDR ranges, with bulk import (up to 200 targets at once) and asset groups
- **Subdomain discovery** with [subfinder](https://github.com/projectdiscovery/subfinder) (optional; without it only the root domain is checked)
- **Port scanning and service fingerprinting** with [nmap](https://nmap.org/)
- **Web checks**: HTTP, TLS, and security header inspection
- **Web application scanning** through [OWASP ZAP](https://www.zaproxy.org/) (optional): spider plus passive scan by default; active scanning (payload injection) is off unless explicitly enabled. If ZAP is not running, this step is skipped without affecting the rest of the scan
- **CVE matching**: detected service names and versions are looked up on the [NVD API](https://nvd.nist.gov/developers/vulnerabilities), filtered by a minimum CVSS score. Only software name and version are sent to NVD, never your IPs or domains
- **Scheduled scanning** per asset (hourly, 6h, 12h, daily, weekly) with missed-run catch-up
- **Change tracking** between scans and findings you can close or reopen
- **Reports** in HTML (printable to PDF), CSV (formula-injection safe, opens in Excel), and JSON
- **Multi-user** with role-based access (admin / user); each user only sees their own assets and findings
- **Authentication**: email OTP registration, login, and password reset
- **User preferences**: light/dark theme, accent color, density, Vietnamese / English UI

## Security design

- Passwords hashed with scrypt and a per-user salt
- Session cookies are `HttpOnly` and `SameSite=Strict`; only token hashes are stored server-side
- OTPs are stored hashed, expire after 10 minutes, lock after 5 wrong attempts, and are single-use
- Login lockout after 5 failed attempts (per username + IP pair) for 15 minutes
- Rate limit of 8 OTP requests per IP per 15 minutes
- Password reset logs the user out of all devices
- Admin safeguards enforced server-side (cannot delete yourself or demote the last admin)
- Known trade-off: the password reset form tells users when an email is not registered ("account does not exist"). This improves usability but allows account enumeration, so it is limited by the rate limit above.

## Tech stack

| Component | Technology |
|-----------|------------|
| Backend | Python, FastAPI, Uvicorn |
| Database | SQLite (automatic migrations) |
| Frontend | Static HTML / CSS / JavaScript |
| Recon | subfinder, nmap, OWASP ZAP (optional) |
| Vulnerability data | NVD API |
| Email | SMTP (falls back to printing OTP in the terminal in dev mode) |
| Deployment | Docker, Windows background service scripts |

## Getting started

### Prerequisites

- Python 3.10+
- [nmap](https://nmap.org/download.html) in your `PATH`
- (Optional) [subfinder](https://github.com/projectdiscovery/subfinder) in your `PATH`
- (Optional) [OWASP ZAP](https://www.zaproxy.org/) running as a daemon for web application scanning, e.g. `zap.sh -daemon -port 8090` (see ZAP variables below)
- (Optional) a free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) for roughly 10x faster CVE lookups

### Install and run

```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env             # Windows: copy .env.example .env

uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000 and click **Register**. The first registered account becomes the admin. If `LANTERN_SMTP_HOST` is empty, no real email is sent and the OTP is printed in the terminal.

### Configuration

Copy `.env.example` to `.env` and edit it. Never commit `.env`.

| Variable | Description | Default |
|----------|-------------|---------|
| `LANTERN_DB` | SQLite file path | `lantern.db` |
| `LANTERN_MAX_HOSTS` | Max hosts per scan | `50` |
| `LANTERN_CVE_LOOKUP` | Enable CVE lookup (1/0) | `1` |
| `LANTERN_NVD_API_KEY` | NVD API key | empty |
| `LANTERN_CVE_MIN_SCORE` | Minimum CVSS score to report | `7.0` |
| `LANTERN_CVE_MAX_LOOKUPS` | Max NVD lookups per scan | `15` |
| `LANTERN_WEBVULN` | Enable ZAP web scanning (1/0) | `1` |
| `LANTERN_ZAP_API` | ZAP API address | `http://127.0.0.1:8090` |
| `LANTERN_ZAP_ACTIVE_SCAN` | Set `1` to enable active scan (intrusive, authorized targets only) | `0` |
| `LANTERN_ZAP_MAX_URLS` | Max web hosts sent to ZAP per scan | `20` |
| `LANTERN_ZAP_MIN_RISK` | Minimum ZAP risk level to report | `Low` |
| `LANTERN_SECURE_COOKIE` | Set `1` when served over HTTPS | `0` |
| `LANTERN_SMTP_HOST` / `PORT` / `USER` / `PASSWORD` / `FROM` / `SECURITY` | SMTP settings for OTP emails (`starttls`, `ssl`, or `none`) | empty |
| `LANTERN_ADMIN_USERNAME` / `PASSWORD` / `EMAIL` / `NAME` | Optionally create or promote an admin at startup. Remove the password after the first run | unset |

For Gmail, enable 2-step verification and use an **App password**, not your normal password.

### Docker

```bash
cp .env.example .env
docker compose up -d --build
```

Data is stored in `./data`. The app is published on `127.0.0.1:8080`. Put Caddy or Nginx with HTTPS in front of it for public access, and set `LANTERN_SECURE_COOKIE=1`. The Dockerfile has not been extensively tested; if the subfinder build step fails, use the manual install above.

### Run in the background (Windows)

Run `install-background.bat` once. Lantern then starts hidden at every login, restarts if stopped, and a desktop shortcut is created. Remove it with `uninstall-background.bat`. Logs are written to `lantern.log`.

> Scheduled scans live inside the server process, so the server must be running. Run **a single Uvicorn worker**; multiple workers would each schedule their own scans.

## Usage

1. Add an asset you are authorized to scan (single or bulk, optionally grouped).
2. Click **Scan**, or scan a whole group (targets are scanned one after another).
3. Review subdomains, open ports, CVEs, and findings; close findings you have handled.
4. Set a schedule per asset under **Schedules**.
5. Export a report under **Reports**.

## API

All endpoints except `/api/health` and `/api/auth/*` require a session cookie. Interactive docs are available at `/docs` when the server is running.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/register`, `/verify`, `/resend` | Registration with email OTP |
| POST | `/api/auth/login`, `/logout` | Session login / logout |
| POST | `/api/auth/forgot`, `/forgot/resend`, `/reset` | Password reset with OTP |
| GET/POST | `/api/assets`, `/api/assets/bulk` | List / add assets |
| POST | `/api/scans` | Start a scan `{"asset_id": 1}` |
| GET | `/api/findings` | List findings |
| PUT | `/api/schedules/{asset_id}` | Set scan schedule |
| GET | `/api/reports/export` | `?format=html\|csv\|json` |
| GET/POST/PATCH/DELETE | `/api/admin/users` | User management (admin) |

Example:

```bash
curl -c cj.txt -H "Content-Type: application/json" \
  -d '{"username":"you","password":"your-password"}' http://127.0.0.1:8000/api/auth/login
curl -b cj.txt -H "Content-Type: application/json" \
  -d '{"name":"example.com","authorized":true}' http://127.0.0.1:8000/api/assets
```

## Project structure

```
app/
  main.py       API, background scans, page serving
  auth.py       registration + OTP, password reset, login, sessions
  admin.py      user management (admin only)
  mailer.py     SMTP email sending
  scanner.py    subfinder, HTTP/TLS/header checks, nmap
  vulns.py      CVE lookup by service version (NVD)
  webvuln.py    web application scanning via OWASP ZAP (optional)
  reports.py    HTML / CSV / JSON report builder
  db.py         SQLite with automatic migrations
pages/          HTML pages (index, login, register, verify, forgot, reset)
static/         shared CSS, preferences, i18n
serve.py        background / Windows service entry point
```

## Limitations

- CVE matching relies on version detection from nmap, so results can include false positives or miss issues when version information is unavailable. Verify findings manually.
- User preferences are stored in the browser (localStorage), not in the account.
- Server error messages and exported reports are in Vietnamese only.

## Roadmap

- Auto-close findings that are no longer detected
- Telegram / email alerts when a scheduled scan detects changes
- Asset graph and scan-to-scan comparison view
- Change password while logged in, option to disable public registration

## Vietnamese documentation

A detailed Vietnamese guide is available in [README.vi.md](README.vi.md).

## License

MIT, see `LICENSE`.

## Author

**Le Van Kien**, SOC Analyst / SOC Engineer
lvkien19112001@gmail.com
