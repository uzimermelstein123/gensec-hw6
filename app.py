#!/usr/bin/env python3
"""Page Network Inspector

Loads a web page in headless Chromium (Playwright) and reports every network
request the page makes: which hosts, IPs and ports it talks to, what kind of
resources it loads, and which calls are insecure or unusual.

Usage:
    python app.py https://www.espn.com
    python app.py https://www.nba.com --json

SECURITY NOTES
  Threat: SSRF. This tool fetches whatever URL it is given, so an attacker could
  point it at localhost, the LAN, or a cloud metadata service (169.254.169.254).
  Defenses:
    * Only http/https URLs, max 2,048 chars, no embedded credentials, no
      whitespace or control characters.
    * The hostname is resolved first; every resolved address must be globally
      routable. Loopback, private, link-local, reserved, multicast and
      unspecified addresses are refused (this also catches odd encodings such as
      http://2130706433 and IPv4-mapped IPv6).
    * The same check runs on EVERY request the browser makes (subresources,
      iframes, fetch/XHR). Non-http(s) schemes (file:, ftp:) are blocked.
    * Redirects: Chromium follows redirects without re-running our checks (we
      proved this with a test), so the tool follows redirect chains itself,
      checks every hop (max 10), and gives the browser only the final response.
    * Limits: 500 requests, 30 seconds total, downloads disabled, service
      workers blocked.
    * All printed text has ANSI/control characters stripped and is truncated.
    * No eval, exec, subprocess or shell. Errors are short messages, no tracebacks.
  Known limits: DNS rebinding (a host that changes its answer between our check
  and Chromium's lookup) and WebSocket connections are not covered.
"""

import argparse
import ipaddress
import json
import re
import socket
import sys
import time
from collections import Counter, defaultdict
from urllib.parse import urljoin, urlparse

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import TimeoutError as PlaywrightTimeout
from playwright.sync_api import sync_playwright

NETWORK_IDLE_TIMEOUT_MS = 20_000  # 20-second cap for the page to go idle
TOTAL_TIMEOUT_S = 30              # hard cap on total run time
MAX_URL_LEN = 2048
MAX_REQUESTS = 500
MAX_FIELD_LEN = 200
MAX_REDIRECTS = 10
REDIRECT_CODES = {301, 302, 303, 307, 308}

STANDARD_PORTS = {80, 443}
DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}
# Common two-part public suffixes, so "bbc.co.uk" is treated as one site.
MULTI_PART_SUFFIXES = {"co.uk", "com.au", "co.jp", "com.br", "co.nz", "co.in"}

_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


class InputError(Exception):
    """The user-supplied URL is invalid or not allowed."""


class PageError(Exception):
    """The page could not be loaded."""


# --------------------------------------------------------------------------- #
# Sanitizing and validation
# --------------------------------------------------------------------------- #

def sanitize(value, limit=MAX_FIELD_LEN):
    """Strip ANSI escapes and control characters, then truncate."""
    text = _ANSI_RE.sub("", str(value))
    text = _CTRL_RE.sub("", text)
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text


def host_public_check(host):
    """Return (ok, reason). ok only if every resolved address is globally routable."""
    try:
        addrs = [ipaddress.ip_address(host.strip("[]"))]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except (socket.gaierror, UnicodeError):
            return False, "hostname could not be resolved"
        addrs = []
        for info in infos:
            try:
                addrs.append(ipaddress.ip_address(info[4][0].split("%")[0]))
            except ValueError:
                return False, "hostname resolved to an unparseable address"
    if not addrs:
        return False, "hostname could not be resolved"
    for addr in addrs:
        if addr.version == 6 and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        if not addr.is_global:
            return False, f"resolves to a non-public address ({addr})"
    return True, ""


def validate_url(url):
    """Raise InputError unless `url` is a safe, public http(s) URL."""
    if not url or not url.strip():
        raise InputError("URL is empty")
    if len(url) > MAX_URL_LEN:
        raise InputError(f"URL is longer than {MAX_URL_LEN} characters")
    if _CTRL_RE.search(url) or re.search(r"\s", url):
        raise InputError("URL contains whitespace or control characters")
    try:
        parsed = urlparse(url)
        parsed.port  # raises ValueError on an invalid port
    except ValueError:
        raise InputError("URL is malformed")
    if parsed.scheme not in ("http", "https"):
        raise InputError("only http:// and https:// URLs are allowed")
    if parsed.username is not None or parsed.password is not None:
        raise InputError("URLs with embedded credentials are not allowed")
    if not parsed.hostname:
        raise InputError("URL has no hostname")
    ok, reason = host_public_check(parsed.hostname)
    if not ok:
        raise InputError(f"blocked host '{sanitize(parsed.hostname, 80)}': {reason}")
    return url


# --------------------------------------------------------------------------- #
# Page loading
# --------------------------------------------------------------------------- #

def registrable_domain(host):
    """Naive registrable domain: last two labels (three for known suffixes)."""
    parts = host.lower().rstrip(".").split(".")
    if len(parts) <= 2:
        return host.lower()
    if ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def make_record(request, response=None, size=0, ip_hint=None):
    parsed = urlparse(request.url)
    port = None
    try:
        port = parsed.port or DEFAULT_PORTS.get(parsed.scheme)
    except ValueError:
        pass
    ip = None
    status = None
    if response is not None:
        status = response.status
        try:
            addr = response.server_addr()
            if addr:
                ip = addr.get("ipAddress")
                port = addr.get("port", port)
        except Exception:
            pass
    if ip is None and ip_hint:
        # Fulfilled responses carry no server address; use the IP we resolved.
        ip = ip_hint.get(parsed.hostname or "")
    return {
        "url": sanitize(request.url),
        "scheme": parsed.scheme,
        "host": sanitize(parsed.hostname or "", 100),
        "ip": sanitize(ip, 64) if ip else None,
        "port": port,
        "resource_type": sanitize(request.resource_type, 30),
        "status": status,
        "size": size,
    }


def inspect_page(url):
    """Load `url` and return (request records, blocked URLs, notes, final URL)."""
    records = []
    blocked = []
    notes = []
    host_cache = {}
    ip_hint = {}
    deadline = time.monotonic() + TOTAL_TIMEOUT_S
    allowed_count = 0

    def remaining_ms():
        return max(1000, int((deadline - time.monotonic()) * 1000))

    def allowed(target_url):
        """True if target_url is http(s) and its host resolves only to public IPs."""
        parsed_target = urlparse(target_url)
        host = parsed_target.hostname or ""
        if parsed_target.scheme not in ("http", "https") or not host:
            return False
        if host not in host_cache:
            host_cache[host] = host_public_check(host)
            if host_cache[host][0]:
                try:
                    ip_hint[host] = socket.getaddrinfo(
                        host, None, proto=socket.IPPROTO_TCP)[0][4][0]
                except (socket.gaierror, UnicodeError, IndexError):
                    pass
        return host_cache[host][0]

    def resolve_start_url(context, start):
        """Follow the start URL's redirects (checking each hop) and return the
        final URL, so the browser loads the page at its real address."""
        current = start
        for _ in range(MAX_REDIRECTS + 1):
            if not allowed(current):
                raise InputError("redirect leads to a blocked address: "
                                 + sanitize(current, 100))
            try:
                resp = context.request.get(current, max_redirects=0,
                                           timeout=remaining_ms(),
                                           fail_on_status_code=False)
            except PlaywrightError as exc:
                first = str(exc).strip().splitlines()[0] if str(exc).strip() else "unknown error"
                raise PageError(sanitize(first, 150))
            location = resp.headers.get("location")
            status = resp.status
            resp.dispose()
            if status in REDIRECT_CODES and location:
                current = urljoin(current, location)
                continue
            return current
        raise PageError("too many redirects")

    def route_handler(route):
        """Gatekeeper: runs for every request the browser wants to make."""
        nonlocal allowed_count
        request_url = route.request.url
        parsed = urlparse(request_url)

        if parsed.scheme in ("data", "blob", "about"):
            route.continue_()
            return
        if time.monotonic() > deadline or allowed_count >= MAX_REQUESTS:
            if "limit" not in notes:
                notes.append("limit")
            route.abort("blockedbyclient")
            return

        if not allowed(request_url):
            blocked.append(sanitize(request_url, 120))
            route.abort("blockedbyclient")
            return

        allowed_count += 1

        # Chromium follows redirects on its own WITHOUT sending the next hop back
        # through this handler (verified by testing: a 302 to 127.0.0.1 got through
        # even after route.fulfill). So we follow redirects ourselves, check every
        # hop, and give the browser only the final, non-redirect response.
        try:
            response = route.fetch(max_redirects=0, timeout=remaining_ms())
            hops = 0
            while response.status in REDIRECT_CODES and response.headers.get("location"):
                hops += 1
                target = urljoin(response.url, response.headers["location"])
                if hops > MAX_REDIRECTS:
                    route.abort("failed")
                    return
                if not allowed(target):
                    blocked.append(sanitize(target, 120))
                    route.abort("blockedbyclient")
                    return
                allowed_count += 1
                response = route.fetch(url=target, max_redirects=0, timeout=remaining_ms())
            route.fulfill(response=response)
        except PlaywrightError:
            try:
                route.abort("failed")
            except PlaywrightError:
                pass

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            context = browser.new_context(accept_downloads=False, service_workers="block")
            context.route("**/*", route_handler)
            page = context.new_page()

            def on_finished(request):
                try:
                    response = request.response()
                    size = request.sizes().get("responseBodySize", 0) or 0
                except Exception:
                    response, size = None, 0
                records.append(make_record(request, response, size, ip_hint))

            def on_failed(request):
                if sanitize(request.url, 120) in blocked:
                    return  # already counted as blocked
                records.append(make_record(request, ip_hint=ip_hint))

            page.on("requestfinished", on_finished)
            page.on("requestfailed", on_failed)

            start_url = resolve_start_url(context, url)

            try:
                page.goto(start_url, wait_until="networkidle", timeout=NETWORK_IDLE_TIMEOUT_MS)
            except PlaywrightTimeout:
                notes.append("timeout")
            except PlaywrightError as exc:
                if blocked:
                    raise InputError("the page tried to reach a blocked address: "
                                     + sanitize(blocked[0], 100))
                first_line = str(exc).strip().splitlines()[0] if str(exc).strip() else "unknown error"
                raise PageError(sanitize(first_line, 150))

            final_url = page.url
        finally:
            browser.close()

    # Ignore non-network schemes (data:, blob:, about:).
    records = [r for r in records if r["scheme"] in DEFAULT_PORTS]
    return records, blocked, notes, final_url


# --------------------------------------------------------------------------- #
# Analysis and reporting
# --------------------------------------------------------------------------- #

def analyze(records, page_url, blocked=(), notes=()):
    """Aggregate raw request records into a report dictionary."""
    first_party_domain = registrable_domain(urlparse(page_url).hostname or "")

    by_type = Counter(r["resource_type"] for r in records)
    hosts = defaultdict(lambda: {"ips": set(), "ports": set(), "requests": 0, "bytes": 0})
    for r in records:
        h = hosts[r["host"]]
        if r["ip"]:
            h["ips"].add(r["ip"])
        if r["port"]:
            h["ports"].add(r["port"])
        h["requests"] += 1
        h["bytes"] += r["size"]

    # Heuristic: same registrable domain, or a domain whose name starts with the
    # site's brand (espn.com -> espncdn.com). Not perfect, but close for demos.
    brand = first_party_domain.split(".")[0]

    def is_first_party(host):
        domain = registrable_domain(host)
        return domain == first_party_domain or (
            len(brand) >= 4 and domain.split(".")[0].startswith(brand))

    first_party, third_party = [], []
    for host in hosts:
        if is_first_party(host):
            first_party.append(host)
        else:
            third_party.append(host)

    plain_http = sorted({r["url"] for r in records if r["scheme"] in ("http", "ws")})
    odd_ports = sorted({(r["host"], r["port"]) for r in records
                        if r["port"] and r["port"] not in STANDARD_PORTS})

    top_hosts = sorted(hosts.items(), key=lambda kv: kv[1]["requests"], reverse=True)[:10]

    return {
        "page_url": sanitize(page_url),
        "total_requests": len(records),
        "total_bytes": sum(r["size"] for r in records),
        "by_resource_type": dict(by_type.most_common()),
        "top_hosts": [
            {
                "host": host,
                "ips": sorted(info["ips"]),
                "ports": sorted(info["ports"]),
                "requests": info["requests"],
                "bytes": info["bytes"],
                "party": "first" if host in first_party else "third",
            }
            for host, info in top_hosts
        ],
        "first_party_hosts": sorted(first_party),
        "third_party_hosts": sorted(third_party),
        "flags": {
            "plain_http_requests": plain_http,
            "non_standard_ports": [{"host": h, "port": p} for h, p in odd_ports],
            "blocked_requests": list(blocked),
        },
        "notes": list(notes),
    }


def human_bytes(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def print_report(report):
    line = "=" * 78
    print(line)
    print(f"Page Network Inspector  -  {report['page_url']}")
    print(line)
    print(f"Total requests: {report['total_requests']}")
    print(f"Total bytes:    {human_bytes(report['total_bytes'])}\n")

    print("Requests by resource type")
    print("-" * 40)
    for rtype, count in report["by_resource_type"].items():
        print(f"  {rtype:<18}{count:>6}")

    print("\nTop 10 hosts")
    print("-" * 78)
    print(f"  {'HOST':<30}{'IP':<27}{'PORT':<6}{'REQS':>5}  PARTY")
    for h in report["top_hosts"]:
        ip = h["ips"][0] if h["ips"] else "-"
        if len(h["ips"]) > 1:
            ip += f" (+{len(h['ips']) - 1})"
        port = ",".join(str(p) for p in h["ports"]) or "-"
        print(f"  {h['host'][:29]:<30}{ip[:26]:<27}{port:<6}{h['requests']:>5}  {h['party']}")

    fp, tp = report["first_party_hosts"], report["third_party_hosts"]
    print(f"\nFirst-party hosts: {len(fp)}   Third-party hosts: {len(tp)}")
    for host in tp[:15]:
        print(f"  third-party: {host}")
    if len(tp) > 15:
        print(f"  ... and {len(tp) - 15} more")

    print("\nFlags")
    print("-" * 40)
    flags = report["flags"]
    plain, odd, blocked = (flags["plain_http_requests"], flags["non_standard_ports"],
                           flags["blocked_requests"])
    if plain:
        print(f"  [!] {len(plain)} plain-HTTP request(s):")
        for u in plain[:10]:
            print(f"      {u}")
    else:
        print("  [ok] no plain-HTTP requests")
    if odd:
        print("  [!] non-80/443 ports:")
        for o in odd:
            print(f"      {o['host']}:{o['port']}")
    else:
        print("  [ok] only ports 80/443 used")
    if blocked:
        print(f"  [!] {len(blocked)} request(s) blocked by the SSRF guard:")
        for u in blocked[:10]:
            print(f"      {u}")

    if "timeout" in report["notes"]:
        print("\nnote: page did not reach network idle in 20s; partial results shown.")
    if "limit" in report["notes"]:
        print(f"\nnote: request or time limit reached ({MAX_REQUESTS} requests / "
              f"{TOTAL_TIMEOUT_S}s); partial results shown.")


def main():
    parser = argparse.ArgumentParser(description="Page Network Inspector")
    parser.add_argument("url", help="page to inspect, e.g. https://www.espn.com")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args()

    try:
        validate_url(args.url)
        records, blocked, notes, final_url = inspect_page(args.url)
        report = analyze(records, final_url, blocked, notes)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except PageError as exc:
        print(f"error: could not load page: {exc}", file=sys.stderr)
        return 1
    except PlaywrightError as exc:
        first_line = str(exc).strip().splitlines()[0] if str(exc).strip() else "unknown error"
        print(f"error: browser problem: {sanitize(first_line, 150)}", file=sys.stderr)
        print("hint: did you run 'playwright install chromium'?", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
