"""Stateful scanner orchestration: Burp Suite Professional and OWASP ZAP.

Unlike the subprocess tools in :mod:`arachne.external`, Burp and ZAP are
long-running services driven over an HTTP API:

* **ZAP** — a daemon with a JSON API (``/JSON/<component>/<view|action>/<name>/``).
  arachne can connect to a running daemon or launch one (``--zap-launch``), inject
  the session via Replacer rules, run the spider (+ optional AJAX spider), and
  fold the discovered URLs into the crawl.
* **Burp Pro** — the official REST API (``http://127.0.0.1:1337/<key>/v0.1/``).
  arachne POSTs an authenticated scan, polls to completion, and folds the URLs
  from the reported issues (the official API exposes issues, not the full
  sitemap — for the whole sitemap, export it from the GUI and use ``--burp-import``).

Both reuse :class:`arachne.external.Finding`, so the crawler folds their results
through the same path as every other tool. Network failures degrade to an empty
result with a logged reason — never fatal. The request-building and
response-parsing cores are pure (no I/O) so they're unit-tested without a live
service.
"""
from __future__ import annotations

import json
import os
import socket
import time
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Dict, List, Optional, Tuple

from .config import Config
from .external import Finding

LogFn = Callable[[str], None]


def _port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# Common macOS/Linux Burp install locations for --burp-headless auto-detection.
_BURP_JARS = [
    "/Applications/Burp Suite Professional.app/Contents/Resources/app/burpsuite_pro.jar",
    "/Applications/Burp Suite Community Edition.app/Contents/Resources/app/burpsuite_community.jar",
    os.path.expanduser("~/BurpSuitePro/burpsuite_pro.jar"),
    os.path.expanduser("~/BurpSuiteCommunity/burpsuite_community.jar"),
]


def detect_burp_jar() -> Optional[str]:
    for p in _BURP_JARS:
        if os.path.exists(p):
            return p
    return None


def _http(method: str, url: str, headers: Optional[Dict[str, str]] = None,
          body: Optional[dict] = None, timeout: float = 30.0):
    """Minimal blocking JSON HTTP. Returns (status, headers, text); status is
    None when the host is unreachable (so callers can skip gracefully)."""
    data = None
    h = dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        h.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, \
                resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        text = ""
        try:
            text = exc.read().decode("utf-8", "replace")
        except Exception:
            pass
        hdrs = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        return exc.code, hdrs, text
    except (urllib.error.URLError, OSError, ValueError):
        return None, {}, ""


class Scanner:
    """Base for a stateful scanner integration."""
    name = "scanner"

    def __init__(self, cfg: Config):
        self.cfg = cfg

    def _auth_header_lines(self) -> List[str]:
        lines: List[str] = []
        for k, v in (self.cfg.headers or {}).items():
            lines.append(f"{k}: {v}")
        if self.cfg.bearer:
            scheme = (self.cfg.auth_scheme + " ") if self.cfg.auth_scheme else ""
            lines.append(f"{self.cfg.auth_header or 'Authorization'}: {scheme}{self.cfg.bearer}")
        return lines

    def _cookie_header(self) -> Optional[str]:
        if not self.cfg.cookies:
            return None
        return "; ".join(f"{k}={v}" for k, v in self.cfg.cookies.items())

    def run(self, seeds: List[str], log: LogFn) -> List[Finding]:  # pragma: no cover
        raise NotImplementedError


# ---------------------------------------------------------------------------
# OWASP ZAP — daemon + JSON API
# ---------------------------------------------------------------------------

class ZapScanner(Scanner):
    name = "zap"

    def __init__(self, cfg: Config):
        super().__init__(cfg)
        self.base = (cfg.zap_url or "http://127.0.0.1:8080").rstrip("/")
        self.api_key = cfg.zap_api_key
        self._proc: Optional[subprocess.Popen] = None

    # -- pure helpers (unit-tested) ---------------------------------------
    def api_url(self, component: str, kind: str, name: str,
                params: Optional[Dict[str, str]] = None) -> str:
        """Build a ZAP API URL, e.g. /JSON/spider/action/scan/?apikey=..&url=.."""
        q = dict(params or {})
        if self.api_key:
            q["apikey"] = self.api_key
        qs = ("?" + urllib.parse.urlencode(q)) if q else ""
        return f"{self.base}/JSON/{component}/{kind}/{name}/{qs}"

    def replacer_rules(self) -> List[Dict[str, str]]:
        """Replacer addRule param sets that inject arachne's session into every
        ZAP request (Authorization / arbitrary headers / Cookie)."""
        rules: List[Dict[str, str]] = []
        for i, line in enumerate(self._auth_header_lines()):
            if ":" not in line:
                continue
            hname, hval = line.split(":", 1)
            rules.append({"description": f"arachne-auth-{i}", "enabled": "true",
                          "matchType": "REQ_HEADER", "matchRegex": "false",
                          "matchString": hname.strip(), "replacement": hval.strip()})
        cookie = self._cookie_header()
        if cookie:
            rules.append({"description": "arachne-cookie", "enabled": "true",
                          "matchType": "REQ_HEADER", "matchRegex": "false",
                          "matchString": "Cookie", "replacement": cookie})
        return rules

    @staticmethod
    def parse_urls(text: str) -> List[str]:
        """Pull URLs from a ZAP view response (spider results or core/view/urls)."""
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            return []
        if isinstance(data, dict):
            for key in ("urls", "results"):
                val = data.get(key)
                if isinstance(val, list):
                    return [str(u) for u in val if isinstance(u, str) and u.startswith("http")]
        return []

    # -- network ----------------------------------------------------------
    def _alive(self) -> bool:
        status, _, _ = _http("GET", self.api_url("core", "view", "version"), timeout=5)
        return status == 200

    def _launch(self, log: LogFn) -> bool:
        if shutil.which(self.cfg.zap_path) is None:
            return False
        host, port = "127.0.0.1", "8080"
        try:
            parsed = urllib.parse.urlsplit(self.base)
            host = parsed.hostname or host
            port = str(parsed.port or 8080)
        except ValueError:
            pass
        cmd = [self.cfg.zap_path, "-daemon", "-host", host, "-port", port,
               "-config", "api.addrs.addr.name=.*", "-config", "api.addrs.addr.regex=true"]
        if self.api_key:
            cmd += ["-config", f"api.key={self.api_key}"]
        else:
            cmd += ["-config", "api.disablekey=true"]
        log(f"[*] zap: launching daemon ({self.cfg.zap_path} on {host}:{port})")
        try:
            self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL)
        except OSError as exc:
            log(f"[!] zap: could not launch daemon: {exc}")
            return False
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            if self._alive():
                return True
            time.sleep(2)
        log("[!] zap: daemon did not become ready in time")
        return False

    def _poll_spider(self, scan_id: str, log: LogFn) -> None:
        deadline = time.monotonic() + self.cfg.tool_timeout
        while time.monotonic() < deadline:
            status, _, text = _http("GET", self.api_url(
                "spider", "view", "status", {"scanId": scan_id}), timeout=15)
            try:
                pct = int(json.loads(text).get("status", "0"))
            except (ValueError, AttributeError, TypeError):
                pct = 0
            if pct >= 100:
                return
            time.sleep(2)
        log("[!] zap: spider timed out (partial results kept)")

    def run(self, seeds: List[str], log: LogFn) -> List[Finding]:
        launched = False
        if not self._alive():
            if self.cfg.zap_launch:
                launched = self._launch(log)
                if not launched:
                    log("[!] zap: API not reachable and daemon launch failed — skipping")
                    return []
            else:
                log(f"[!] zap: API not reachable at {self.base} — start ZAP "
                    "(zap.sh -daemon) or pass --zap-launch; skipping")
                return []
        try:
            for rule in self.replacer_rules():
                _http("GET", self.api_url("replacer", "action", "addRule", rule), timeout=15)
            urls: set = set()
            for seed in seeds:
                _http("GET", self.api_url("core", "action", "accessUrl",
                                          {"url": seed, "followRedirects": "true"}), timeout=30)
                status, _, text = _http("GET", self.api_url(
                    "spider", "action", "scan",
                    {"url": seed, "recurse": "true",
                     "subtreeOnly": "false" if self.cfg.include_subdomains else "true"}),
                    timeout=30)
                if status != 200:
                    continue
                try:
                    scan_id = str(json.loads(text).get("scan", ""))
                except (ValueError, TypeError):
                    scan_id = ""
                if scan_id:
                    self._poll_spider(scan_id, log)
                    _, _, res = _http("GET", self.api_url(
                        "spider", "view", "results", {"scanId": scan_id}), timeout=30)
                    urls.update(self.parse_urls(res))
                if self.cfg.zap_ajax:
                    _http("GET", self.api_url("ajaxSpider", "action", "scan",
                                              {"url": seed}), timeout=30)
                    self._poll_ajax(log)
            # sweep everything ZAP has seen, in case spider results were partial
            _, _, allres = _http("GET", self.api_url("core", "view", "urls"), timeout=30)
            urls.update(self.parse_urls(allres))
            return [Finding(kind="url", url=u, source=self.name) for u in sorted(urls)]
        finally:
            if launched:
                _http("GET", self.api_url("core", "action", "shutdown"), timeout=10)
                if self._proc is not None:
                    try:
                        self._proc.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        self._proc.kill()

    def _poll_ajax(self, log: LogFn) -> None:
        deadline = time.monotonic() + self.cfg.tool_timeout
        while time.monotonic() < deadline:
            _, _, text = _http("GET", self.api_url("ajaxSpider", "view", "status"), timeout=15)
            try:
                if json.loads(text).get("status") != "running":
                    return
            except (ValueError, AttributeError, TypeError):
                return
            time.sleep(2)


# ---------------------------------------------------------------------------
# Burp Suite Professional — official REST API
# ---------------------------------------------------------------------------

class BurpScanner(Scanner):
    name = "burp"

    def __init__(self, cfg: Config):
        super().__init__(cfg)
        self.api_url = (cfg.burp_api_url or "http://127.0.0.1:1337").rstrip("/")
        self.api_key = cfg.burp_api_key or ""

    def _endpoint(self, suffix: str = "") -> str:
        key = ("/" + self.api_key) if self.api_key else ""
        return f"{self.api_url}{key}/v0.1/scan{suffix}"

    # -- pure helpers (unit-tested) ---------------------------------------
    def build_scan_request(self, seeds: List[str]) -> dict:
        """Build the POST body for an authenticated Burp scan."""
        origins = []
        seen = set()
        for s in seeds:
            sp = urllib.parse.urlsplit(s)
            if sp.scheme and sp.netloc:
                origin = f"{sp.scheme}://{sp.netloc}/"
                if origin not in seen:
                    seen.add(origin)
                    origins.append(origin)
        body: dict = {
            "urls": list(seeds),
            "scope": {
                "type": "SimpleScope",
                "include": [{"rule": o} for o in origins] or [{"rule": s} for s in seeds],
            },
        }
        if not self.cfg.allow_active:
            from .config import DEFAULT_ACTIVE_DENY
            body["scope"]["exclude"] = [{"rule": p.strip("\\b")} for p in DEFAULT_ACTIVE_DENY]
        if self.cfg.login_username and self.cfg.login_password:
            body["application_logins"] = [{
                "username": self.cfg.login_username,
                "password": self.cfg.login_password,
            }]
        if self.cfg.burp_config_name:
            body["scan_configurations"] = [{
                "type": "NamedConfiguration", "name": self.cfg.burp_config_name}]
        return body

    @staticmethod
    def issue_urls(data: dict) -> List[str]:
        """Extract URLs from a Burp scan-status payload's issue events."""
        urls: set = set()
        events = []
        if isinstance(data, dict):
            events = data.get("issue_events") or data.get("issues") or []
        for ev in events:
            issue = ev.get("issue", ev) if isinstance(ev, dict) else None
            if not isinstance(issue, dict):
                continue
            origin = issue.get("origin") or ""
            path = issue.get("path") or ""
            url = issue.get("url") or (origin + path if origin else "")
            if url.startswith("http"):
                urls.add(url)
        return sorted(urls)

    @staticmethod
    def scan_status(data: dict) -> str:
        if isinstance(data, dict):
            return str(data.get("scan_status") or data.get("status") or "")
        return ""

    # -- network ----------------------------------------------------------
    def run(self, seeds: List[str], log: LogFn) -> List[Finding]:
        body = self.build_scan_request(seeds)
        status, headers, text = _http("POST", self._endpoint(), body=body, timeout=30)
        if status is None:
            log(f"[!] burp: REST API not reachable at {self.api_url} — start Burp + enable "
                "the REST API (Settings > Suite > REST API); skipping")
            return []
        if status not in (200, 201):
            log(f"[!] burp: scan request rejected (HTTP {status}) — check the API key/scope; skipping")
            return []
        location = headers.get("location", "")
        task_id = location.rstrip("/").rsplit("/", 1)[-1] if location else ""
        if not task_id:
            log("[!] burp: no scan id returned — skipping")
            return []
        log(f"[*] burp: scan {task_id} started; polling to completion")
        deadline = time.monotonic() + self.cfg.tool_timeout
        last = {}
        while time.monotonic() < deadline:
            s, _, body_text = _http("GET", self._endpoint("/" + task_id), timeout=20)
            try:
                last = json.loads(body_text)
            except (ValueError, TypeError):
                last = {}
            st = self.scan_status(last).lower()
            if st in ("succeeded", "failed", "paused", "cancelled"):
                log(f"[*] burp: scan {task_id} finished ({st or 'unknown'})")
                break
            time.sleep(5)
        else:
            log("[!] burp: scan timed out (folding partial issues)")
        self._last_result = last  # exposed so the crawler can persist issues
        return [Finding(kind="url", url=u, source=self.name) for u in self.issue_urls(last)]


# ---------------------------------------------------------------------------
# Burp Pro headless — drive Burp from the CLI with NO REST API
# ---------------------------------------------------------------------------

class BurpHeadless:
    """Launch Burp Pro headless (the licensed ``burpsuite_pro.jar``) and route the
    crawl through its proxy listener — no REST API, no GUI clicks.

    Burp records every (authenticated) request arachne sends into a saved ``.burp``
    project and, if the supplied project config enables live audit, scans it. Since
    arachne *is* the proxy client, it already owns the URL set; Burp adds the
    passive/active analysis and a project you can open in the GUI afterwards.
    """

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.jar = cfg.burp_jar or detect_burp_jar()
        self.port = cfg.burp_headless_port or 8080
        self.proc: Optional[subprocess.Popen] = None
        self._lf = None
        self._logpath = ""

    def available(self) -> bool:
        return bool(self.jar) and os.path.exists(self.jar) and shutil.which("java") is not None

    def proxy_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def project_path(self) -> str:
        return self.cfg.burp_project or os.path.join(self.cfg.output_dir, "burp-headless.burp")

    def build_command(self, project_path: str) -> List[str]:
        cmd = ["java", "-Djava.awt.headless=true", "-jar", self.jar,
               "--project-file=" + project_path,
               "--unpause-spider-and-scanner", "--disable-auto-update"]
        for c in self.cfg.burp_config_files:
            cmd.append("--config-file=" + c)
        return cmd

    def start(self, log: LogFn) -> bool:
        if not self.available():
            log("[!] burp-headless: burpsuite_pro.jar or java not found "
                "(pass --burp-jar); skipping")
            return False
        if _port_open("127.0.0.1", self.port):
            log(f"[!] burp-headless: 127.0.0.1:{self.port} is already in use — close the "
                "GUI Burp or set --burp-headless-port; skipping")
            return False
        proj = self.project_path()
        try:
            os.makedirs(os.path.dirname(proj) or ".", exist_ok=True)
            self._logpath = os.path.join(self.cfg.output_dir, "burp-headless.log")
            self._lf = open(self._logpath, "w")
            self.proc = subprocess.Popen(self.build_command(proj), stdin=subprocess.DEVNULL,
                                         stdout=self._lf, stderr=self._lf)
        except OSError as exc:
            log(f"[!] burp-headless: launch failed: {exc}")
            return False
        log(f"[*] burp-headless: launching {os.path.basename(self.jar)} "
            f"(project {proj}, log {self._logpath})")
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            if _port_open("127.0.0.1", self.port):
                return True
            if self.proc.poll() is not None:
                log(f"[!] burp-headless: process exited early (see {self._logpath})")
                return False
            time.sleep(2)
        log("[!] burp-headless: proxy did not come up in time (see log); skipping")
        self.stop(log)
        return False

    def stop(self, log: LogFn) -> None:
        if self.proc is not None:
            log("[*] burp-headless: shutting down Burp (project saved)")
            self.proc.terminate()
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.proc = None
        if self._lf is not None:
            try:
                self._lf.close()
            except Exception:
                pass
            self._lf = None


# ---------------------------------------------------------------------------
# Registry / builder
# ---------------------------------------------------------------------------

_SCANNERS = {"zap": ZapScanner, "burp": BurpScanner}


def build_scanners(cfg: Config) -> List[Scanner]:
    out: List[Scanner] = []
    for name in cfg.scanners:
        cls = _SCANNERS.get(name)
        if cls is not None:
            out.append(cls(cfg))
    return out
