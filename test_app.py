"""Tests for Page Network Inspector (app.py).

Run:  python -m pytest -v
The live-network test is skipped automatically when example.com is unreachable.
"""
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import app


# --------------------------------------------------------------------------- #
# URL validator and SSRF blocklist
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("url", [
    "https://example.com",
    "http://example.com/path?q=1",
    "https://example.com:8443/x",
])
def test_valid_public_urls_pass(url):
    assert app.validate_url(url) == url


@pytest.mark.parametrize("url", [
    "http://localhost",
    "http://localhost:8080/admin",
    "http://127.0.0.1",
    "http://127.1",                      # short form of 127.0.0.1
    "http://2130706433",                 # decimal form of 127.0.0.1
    "http://0x7f.0.0.1",                 # hex form
    "http://[::1]",
    "http://[::ffff:127.0.0.1]",         # IPv4-mapped IPv6
    "http://0.0.0.0",
    "http://169.254.169.254",            # cloud metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.5",
    "http://172.16.0.1",
    "http://192.168.1.1",
    "http://100.64.0.1",                 # carrier-grade NAT
])
def test_internal_addresses_are_blocked(url):
    with pytest.raises(app.InputError):
        app.validate_url(url)


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "ftp://example.com",
    "javascript:alert(1)",
    "data:text/html,hi",
    "gopher://example.com",
])
def test_non_http_schemes_are_rejected(url):
    with pytest.raises(app.InputError, match="http"):
        app.validate_url(url)


def test_embedded_credentials_rejected():
    with pytest.raises(app.InputError, match="credentials"):
        app.validate_url("http://user:pass@example.com")
    with pytest.raises(app.InputError, match="credentials"):
        app.validate_url("http://user@example.com")


@pytest.mark.parametrize("url", ["", "   ", None])
def test_empty_url_rejected(url):
    with pytest.raises(app.InputError):
        app.validate_url(url)


def test_url_length_limit():
    ok = "https://example.com/" + "x" * (app.MAX_URL_LEN - len("https://example.com/"))
    assert len(ok) == app.MAX_URL_LEN
    assert app.validate_url(ok) == ok
    with pytest.raises(app.InputError, match="longer"):
        app.validate_url("https://example.com/" + "x" * 5000)


@pytest.mark.parametrize("url", [
    "http://exa mple.com",
    "http://example.com/\nHost: evil",
    "http://example.com/\x00",
    "http://example.com/\x1b[31m",
])
def test_whitespace_and_control_chars_rejected(url):
    with pytest.raises(app.InputError, match="whitespace|control"):
        app.validate_url(url)


@pytest.mark.parametrize("url", ["http://example.com:99999", "http://example.com:abc"])
def test_bad_ports_rejected(url):
    with pytest.raises(app.InputError, match="malformed"):
        app.validate_url(url)


def test_unresolvable_host_rejected():
    with pytest.raises(app.InputError, match="resolved"):
        app.validate_url("http://nonexistent-host-zzz123.invalid")


def test_host_resolving_to_private_ip_is_blocked(monkeypatch):
    """A public-looking name that resolves to 10.x must be refused."""
    fake = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 0))]
    monkeypatch.setattr(app.socket, "getaddrinfo", lambda *a, **k: fake)
    with pytest.raises(app.InputError, match="non-public"):
        app.validate_url("http://innocent-looking.example")


def test_mixed_public_and_private_answers_are_blocked(monkeypatch):
    """If ANY resolved address is private, refuse (defends against DNS tricks)."""
    fake = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
    monkeypatch.setattr(app.socket, "getaddrinfo", lambda *a, **k: fake)
    with pytest.raises(app.InputError, match="non-public"):
        app.validate_url("http://mixed.example")


# --------------------------------------------------------------------------- #
# Output sanitizing
# --------------------------------------------------------------------------- #

def test_sanitize_strips_ansi_and_control_chars():
    assert app.sanitize("\x1b[31mred\x1b[0m") == "red"
    assert app.sanitize("a\x00b\x07c\rd\ne") == "abcde"
    assert app.sanitize("\x1b]0;evil title\x07ok") == "ok"


def test_sanitize_truncates():
    out = app.sanitize("a" * 1000, limit=50)
    assert len(out) == 50 and out.endswith("...")


# --------------------------------------------------------------------------- #
# Analysis and report
# --------------------------------------------------------------------------- #

def _rec(host, rtype="script", scheme="https", port=443, ip="1.2.3.4", size=100):
    return {"url": f"{scheme}://{host}/x", "scheme": scheme, "host": host, "ip": ip,
            "port": port, "resource_type": rtype, "status": 200, "size": size}


def test_analyze_counts_and_party_split():
    records = [
        _rec("www.site.com", "document"),
        _rec("cdn.site.com"),
        _rec("sitecdn.net"),                      # brand heuristic: first-party
        _rec("tracker.ads.com", "image", size=50),
        _rec("tracker.ads.com", "image", size=50),
    ]
    report = app.analyze(records, "https://www.site.com/")
    assert report["total_requests"] == 5
    assert report["total_bytes"] == 400
    assert report["by_resource_type"] == {"script": 2, "image": 2, "document": 1}
    assert "tracker.ads.com" in report["third_party_hosts"]
    assert {"www.site.com", "cdn.site.com", "sitecdn.net"} <= set(report["first_party_hosts"])
    assert report["top_hosts"][0]["host"] == "tracker.ads.com"


def test_analyze_flags_plain_http_and_odd_ports():
    records = [_rec("a.com", scheme="http", port=80),
               _rec("b.com", port=8443)]
    report = app.analyze(records, "https://a.com/")
    assert report["flags"]["plain_http_requests"] == ["http://a.com/x"]
    assert report["flags"]["non_standard_ports"] == [{"host": "b.com", "port": 8443}]


def test_analyze_clean_page_has_no_flags():
    report = app.analyze([_rec("a.com")], "https://a.com/")
    assert report["flags"]["plain_http_requests"] == []
    assert report["flags"]["non_standard_ports"] == []


def test_registrable_domain():
    assert app.registrable_domain("a.b.example.com") == "example.com"
    assert app.registrable_domain("www.bbc.co.uk") == "bbc.co.uk"
    assert app.registrable_domain("example.com") == "example.com"


# --------------------------------------------------------------------------- #
# End-to-end SSRF guard: local servers + real headless Chromium
# --------------------------------------------------------------------------- #

class _Servers:
    """A 'public' page server and an 'internal secret' server on free ports."""

    def __init__(self):
        self.secret_hits = []
        outer = self

        class Secret(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                outer.secret_hits.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"secret")

        self.secret = HTTPServer(("127.0.0.1", 0), Secret)
        secret_port = self.secret.server_address[1]

        class Page(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{secret_port}/secret")
                    self.end_headers()
                    return
                if self.path == "/chain":  # public hop first, then internal
                    self.send_response(302)
                    self.send_header("Location", "/redirect")
                    self.end_headers()
                    return
                body = (f"<html><body>"
                        f"<img src='http://127.0.0.1:{secret_port}/img.png'>"
                        f"<img src='http://169.254.169.254/latest/meta-data/'>"
                        f"<img src='http://192.168.1.1/x.png'>"
                        f"<img src='/redirect'>"
                        f"</body></html>").encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body)

        self.page = HTTPServer(("127.0.0.1", 0), Page)
        self.page_port = self.page.server_address[1]
        for srv in (self.secret, self.page):
            threading.Thread(target=srv.serve_forever, daemon=True).start()

    def close(self):
        for srv in (self.secret, self.page):
            srv.shutdown()
            srv.server_close()


@pytest.fixture
def servers(monkeypatch):
    # Pretend only the hostname "localhost" is public so we can serve a test page;
    # every other internal address (127.0.0.1, 169.254..., 192.168...) stays blocked.
    real_check = app.host_public_check
    monkeypatch.setattr(app, "host_public_check",
                        lambda host: (True, "") if host == "localhost" else real_check(host))
    s = _Servers()
    yield s
    s.close()


def test_subresources_to_internal_addresses_are_blocked(servers):
    records, blocked, notes, final = app.inspect_page(f"http://localhost:{servers.page_port}/")
    blocked_text = " ".join(blocked)
    assert "169.254.169.254" in blocked_text
    assert "192.168.1.1" in blocked_text
    assert f"127.0.0.1:{servers.secret.server_address[1]}" in blocked_text
    assert servers.secret_hits == [], "internal server must never be contacted"
    assert {r["host"] for r in records} == {"localhost"}


def test_redirect_to_internal_address_is_blocked(servers):
    with pytest.raises(app.InputError, match="blocked"):
        app.inspect_page(f"http://localhost:{servers.page_port}/redirect")
    assert servers.secret_hits == []


def test_redirect_chain_with_internal_final_hop_is_blocked(servers):
    with pytest.raises(app.InputError, match="blocked"):
        app.inspect_page(f"http://localhost:{servers.page_port}/chain")
    assert servers.secret_hits == []


# --------------------------------------------------------------------------- #
# Live network (skipped when offline)
# --------------------------------------------------------------------------- #

def _online():
    try:
        socket.create_connection(("example.com", 443), timeout=3).close()
        return True
    except OSError:
        return False


@pytest.mark.skipif(not _online(), reason="no internet access")
def test_live_example_com():
    app.validate_url("https://example.com")
    records, blocked, notes, final = app.inspect_page("https://example.com")
    report = app.analyze(records, final, blocked, notes)
    assert report["total_requests"] >= 1
    assert report["top_hosts"][0]["host"] == "example.com"
    assert report["top_hosts"][0]["ports"] == [443]
    assert report["flags"]["blocked_requests"] == []


# --------------------------------------------------------------------------- #
# CLI behaviour
# --------------------------------------------------------------------------- #

def test_cli_blocks_localhost_with_exit_code_2(capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["app.py", "http://localhost"])
    assert app.main() == 2
    err = capsys.readouterr().err
    assert err.startswith("error: blocked host")
    assert "Traceback" not in err


def test_cli_rejects_file_scheme(capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["app.py", "file:///etc/passwd"])
    assert app.main() == 2
    assert "only http" in capsys.readouterr().err
