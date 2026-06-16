"""External recon-tool orchestration.

arachne's spine — the async crawler, ``Frontier``, ``Scope`` and ``extract``
mining — stays native. This module lets that spine *drive* best-of-breed
external CLIs and fold their findings back into the same crawl and unified
output, with per-tool provenance via ``Result.source``.

It generalises the contract proven by ``passive.run_urlfinder``: a
``shutil.which`` availability gate, a blocking ``subprocess.run`` with a
timeout, a graceful skip (empty result) when the binary is absent, and
normalised :class:`Finding` records handed back to the crawler.

The crawler runs each tool's blocking :meth:`ExternalTool.run` off the event
loop via ``loop.run_in_executor`` and then awaits ``Frontier.add`` back on the
loop, so no subprocess ever blocks the asyncio worker pool.

Two families of tool, distinguished by :attr:`ExternalTool.active`:

* **discovery** (``active = False``) — passive archives (gau, waybackurls,
  urlfinder) and JS-aware crawlers (katana, hakrawler, gospider). They expand
  the URL surface; arachne re-crawls and re-mines every in-scope hit. Run in the
  discovery phase whenever the tool is selected.
* **active** (``active = True``) — brute-force enumeration (ffuf, feroxbuster
  for content; arjun for parameters). Gated behind ``--fuzz`` and kept GET-only.

Every tool also carries human metadata (``purpose``/``install``/``doc``) so
``arachne --check-tools`` can report what's installed and how to get the rest.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Type
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from .config import Config

# Pull every absolute URL out of an arbitrary tool's stdout. Crawlers differ in
# output shape (plain URLs vs ``[tag] - URL`` lines vs JSONL), so a tolerant
# extractor survives flag/format drift across tool versions.
_URL_RE = re.compile(r"https?://[^\s\"'<>\\)\]}]+")


@dataclass
class Finding:
    """A normalised result from an external tool, ready to fold into the crawl."""
    kind: str                                  # "url" | "param"
    url: Optional[str] = None
    params: List[str] = field(default_factory=list)
    status: Optional[int] = None
    source: str = ""


# ---------------------------------------------------------------------------
# Wordlist resolution — fuzzers need fuel; resolve it without forcing config.
# ---------------------------------------------------------------------------

_WORDLIST_DIR = os.path.join(os.path.dirname(__file__), "data", "wordlists")

# Vendored, curated lists shipped in the package — lean, high-signal defaults so
# zero-config fuzzing works offline. The heavy lists come from SecLists (auto-
# discovered below, or fetched with `arachne --fetch-wordlists`). Reference any
# of these on the CLI by shortcut, e.g. --fuzz-wordlist @common.
VENDORED_WORDLISTS = {
    "starter": "content-starter.txt",   # tiny, fast smoke list
    "common": "content-common.txt",     # richest curated content default
    "api": "api-routes.txt",            # API path segments
    "params": "params-common.txt",      # common parameter names
}

# SecLists checkout locations probed when no explicit wordlist is given. Includes
# the directory `--fetch-wordlists` clones into, so a fetch is picked up for free.
_SECLISTS_ROOTS = [
    os.path.expanduser("~/.arachne/wordlists/SecLists"),
    "/usr/share/seclists", "/usr/share/wordlists/seclists",
    "/opt/SecLists", "/opt/seclists", "/usr/share/wordlists/SecLists",
]
_SECLISTS_CONTENT = [
    "Discovery/Web-Content/raft-medium-directories.txt",
    "Discovery/Web-Content/common.txt",
    "Discovery/Web-Content/directory-list-2.3-medium.txt",
]


def vendored_path(name: str) -> Optional[str]:
    """Resolve a vendored wordlist by shortcut (e.g. 'common') or by filename."""
    fname = VENDORED_WORDLISTS.get(name, name)
    p = os.path.join(_WORDLIST_DIR, fname)
    return p if os.path.exists(p) else None


def vendored_wordlist() -> Optional[str]:
    """The richest curated content list in the package (last-resort default)."""
    return vendored_path("common") or vendored_path("starter")


def _shortcut(value: str) -> Optional[str]:
    """Resolve an '@name' vendored shortcut to a path, or None if not a shortcut/unknown."""
    if value and value.startswith("@"):
        return vendored_path(value[1:])
    return None


def seclists_content(cfg: Config) -> Optional[str]:
    """Best SecLists content list across configured/env/standard roots, or None."""
    roots: List[str] = []
    if cfg.seclists_root:
        roots.append(cfg.seclists_root)
    env = os.environ.get("SECLISTS_ROOT")
    if env:
        roots.append(env)
    roots.extend(_SECLISTS_ROOTS)
    for root in roots:
        if not root:
            continue
        for rel in _SECLISTS_CONTENT:
            cand = os.path.join(root, rel)
            if os.path.exists(cand):
                return cand
    return None


def resolve_content_wordlist(cfg: Config) -> Optional[str]:
    """Pick a content wordlist: explicit/@shortcut -> SecLists -> vendored curated list.

    Returns None only if an explicit override is missing AND no fallback exists
    (so the caller can skip ffuf/feroxbuster gracefully, like a missing binary).
    """
    if cfg.fuzz_wordlist:
        if cfg.fuzz_wordlist.startswith("@"):
            return _shortcut(cfg.fuzz_wordlist)
        return cfg.fuzz_wordlist if os.path.exists(cfg.fuzz_wordlist) else None
    return seclists_content(cfg) or vendored_wordlist()


def resolve_param_wordlist(cfg: Config) -> Optional[str]:
    """Pick a parameter wordlist: explicit/@shortcut path, else None (use arjun's
    larger built-in list rather than downgrading to a vendored fallback)."""
    if cfg.param_wordlist:
        if cfg.param_wordlist.startswith("@"):
            return _shortcut(cfg.param_wordlist)
        return cfg.param_wordlist if os.path.exists(cfg.param_wordlist) else None
    return None


# ---------------------------------------------------------------------------
# Tool abstraction
# ---------------------------------------------------------------------------

class ExternalTool:
    """Base class for an orchestrated external binary.

    Subclasses set the identity/metadata attributes and implement :meth:`run`.
    ``run`` is *blocking* (subprocess + parse) and is invoked off the event loop
    by the crawler. The :attr:`input_kind` declares what the crawler should feed
    it (``domains`` / ``origins`` / ``urls`` / ``seeds``).
    """
    name: str = "tool"
    binary: str = "tool"
    active: bool = False          # active tools require an explicit --fuzz opt-in
    category: str = "tool"        # content | param | crawl | passive (for --check-tools)
    input_kind: str = "origins"   # domains | origins | urls | seeds
    purpose: str = ""             # one-line description for --check-tools
    install: str = ""             # install command for --check-tools
    doc: str = ""                 # project URL

    def __init__(self, cfg: Config, binary: Optional[str] = None):
        self.cfg = cfg
        if binary:
            self.binary = binary

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def skip_reason(self) -> Optional[str]:
        """A human reason to skip this run (e.g. missing wordlist), or None to run."""
        return None

    def run(self, inputs: List[str]) -> List[Finding]:  # pragma: no cover - abstract
        raise NotImplementedError

    # shared subprocess contracts -----------------------------------------
    def _exec(self, cmd: List[str]) -> bool:
        """Run a command (argv list, never shell). Returns False on timeout/OSError.

        For tools that write their results to a file (ffuf -o, arjun -oJ)."""
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=self.cfg.tool_timeout)
            return True
        except (subprocess.TimeoutExpired, OSError):
            return False

    def _run_stdout(self, cmd: List[str], stdin_data: Optional[str] = None) -> Optional[str]:
        """Run a command and return its stdout. None on OSError (e.g. binary vanished).

        A timeout still returns whatever the tool printed before being killed, so
        a long crawler that runs out the clock keeps its partial results."""
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=self.cfg.tool_timeout, input=stdin_data)
            return proc.stdout or ""
        except subprocess.TimeoutExpired as exc:
            partial = exc.stdout
            if isinstance(partial, bytes):
                partial = partial.decode("utf-8", "replace")
            return partial or ""
        except OSError:
            return None

    def _urls_from_text(self, text: Optional[str]) -> List[str]:
        """Extract de-duplicated absolute URLs from arbitrary tool stdout."""
        seen: set = set()
        out: List[str] = []
        for m in _URL_RE.finditer(text or ""):
            u = m.group(0).rstrip(".,;")
            if u and u not in seen:
                seen.add(u)
                out.append(u)
        cap = self.cfg.tool_max_results
        return out[:cap] if cap and cap > 0 else out

    def _url_findings(self, text: Optional[str]) -> List[Finding]:
        return [Finding(kind="url", url=u, source=self.name) for u in self._urls_from_text(text)]

    # auth material shared by every tool ----------------------------------
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


# ---------------------------------------------------------------------------
# Active content discovery
# ---------------------------------------------------------------------------

class FfufTool(ExternalTool):
    """Directory / content discovery via ffuf, one FUZZ run per in-scope origin."""
    name = "ffuf"
    binary = "ffuf"
    active = True
    category = "content"
    input_kind = "origins"
    purpose = "directory / content discovery (unlinked paths)"
    install = "go install github.com/ffuf/ffuf/v2@latest"
    doc = "https://github.com/ffuf/ffuf"

    def skip_reason(self) -> Optional[str]:
        if resolve_content_wordlist(self.cfg) is None:
            return "no content wordlist found (pass --fuzz-wordlist or --seclists-root)"
        return None

    def run(self, origins: List[str]) -> List[Finding]:
        wordlist = resolve_content_wordlist(self.cfg)
        if not wordlist:
            return []
        out: List[Finding] = []
        for origin in origins:
            out.extend(self._run_one(origin, wordlist))
        if self.cfg.tool_max_results and self.cfg.tool_max_results > 0:
            out = out[: self.cfg.tool_max_results]
        return out

    def _run_one(self, origin: str, wordlist: str) -> List[Finding]:
        fd, out_path = tempfile.mkstemp(prefix="arachne-ffuf-", suffix=".json")
        os.close(fd)
        try:
            self._exec(self.build_command(origin, wordlist, out_path))
            return self.parse_output(out_path)
        finally:
            try:
                os.unlink(out_path)
            except OSError:
                pass

    def build_command(self, origin: str, wordlist: str, out_path: str) -> List[str]:
        cmd = [
            self.binary,
            "-u", origin.rstrip("/") + "/FUZZ",
            "-w", wordlist,
            "-of", "json", "-o", out_path,
            "-s",                # silent
            "-ac",               # auto-calibrate to suppress soft-404s
            "-noninteractive",
            "-t", str(max(1, self.cfg.concurrency)),
            "-timeout", str(int(self.cfg.timeout)),
            "-H", f"User-Agent: {self.cfg.user_agent}",
        ]
        # Inherit arachne's politeness budget — external binaries don't share its
        # httpx rate limiter, so pass equivalents through ffuf's own flags.
        if self.cfg.rate and self.cfg.rate > 0:
            cmd += ["-rate", str(int(self.cfg.rate))]
        if self.cfg.delay and self.cfg.delay > 0:
            cmd += ["-p", str(self.cfg.delay)]
        if self.cfg.proxy:
            cmd += ["-x", self.cfg.proxy]
        for h in self._auth_header_lines():
            cmd += ["-H", h]
        cookie = self._cookie_header()
        if cookie:
            cmd += ["-b", cookie]
        return cmd

    def parse_output(self, out_path: str) -> List[Finding]:
        try:
            with open(out_path, "r", encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return []
        results = data.get("results") if isinstance(data, dict) else None
        out: List[Finding] = []
        for r in results or []:
            if not isinstance(r, dict):
                continue
            url = r.get("url")
            if url:
                out.append(Finding(kind="url", url=str(url),
                                   status=r.get("status"), source=self.name))
        return out


class FeroxbusterTool(ExternalTool):
    """Recursive directory / content discovery via feroxbuster, per in-scope origin.

    Complements ffuf: feroxbuster recurses into discovered directories and
    extracts links from response bodies, so it reaches nested unlinked paths a
    single-level FUZZ run misses. ``--silent`` makes it print URLs only."""
    name = "feroxbuster"
    binary = "feroxbuster"
    active = True
    category = "content"
    input_kind = "origins"
    purpose = "recursive directory / content discovery"
    install = "brew install feroxbuster   # or: cargo install feroxbuster"
    doc = "https://github.com/epi052/feroxbuster"

    def skip_reason(self) -> Optional[str]:
        if resolve_content_wordlist(self.cfg) is None:
            return "no content wordlist found (pass --fuzz-wordlist or --seclists-root)"
        return None

    def run(self, origins: List[str]) -> List[Finding]:
        wordlist = resolve_content_wordlist(self.cfg)
        if not wordlist:
            return []
        seen: set = set()
        urls: List[str] = []
        for origin in origins:
            out = self._run_stdout(self.build_command(origin, wordlist))
            if not out:
                continue
            for u in self._urls_from_text(out):
                if u not in seen:
                    seen.add(u)
                    urls.append(u)
        cap = self.cfg.tool_max_results
        if cap and cap > 0:
            urls = urls[:cap]
        return [Finding(kind="url", url=u, source=self.name) for u in urls]

    def build_command(self, origin: str, wordlist: str) -> List[str]:
        cmd = [
            self.binary,
            "-u", origin.rstrip("/") + "/",
            "-w", wordlist,
            "--silent",                # URLs only on stdout
            "--no-state",              # don't drop a resume-state file
            "-d", str(max(1, self.cfg.max_depth)),
            "-t", str(max(1, self.cfg.concurrency)),
            "-a", self.cfg.user_agent,
        ]
        if self.cfg.insecure:
            cmd += ["-k"]
        if self.cfg.rate and self.cfg.rate > 0:
            cmd += ["--rate-limit", str(int(self.cfg.rate))]
        if self.cfg.proxy:
            cmd += ["--proxy", self.cfg.proxy]
        for h in self._auth_header_lines():
            cmd += ["-H", h]
        for k, v in (self.cfg.cookies or {}).items():
            cmd += ["-b", f"{k}={v}"]
        return cmd


# ---------------------------------------------------------------------------
# Active parameter discovery
# ---------------------------------------------------------------------------

class ArjunTool(ExternalTool):
    """Active parameter discovery via arjun over a batch of in-scope endpoints.

    arjun's ``-oJ`` output is a dict keyed by URL:
    ``{"https://h/ep": {"params": ["id", ...], "method": "GET", "headers": {}}}``.
    """
    name = "arjun"
    binary = "arjun"
    active = True
    category = "param"
    input_kind = "urls"
    purpose = "hidden parameter discovery (anomaly diffing)"
    install = "pipx install arjun"
    doc = "https://github.com/s0md3v/Arjun"

    def run(self, urls: List[str]) -> List[Finding]:
        if not urls:
            return []
        cap = self.cfg.fuzz_max_endpoints
        targets = urls[:cap] if cap and cap > 0 else list(urls)
        in_fd, in_path = tempfile.mkstemp(prefix="arachne-arjun-in-", suffix=".txt")
        out_fd, out_path = tempfile.mkstemp(prefix="arachne-arjun-out-", suffix=".json")
        os.close(out_fd)
        try:
            with os.fdopen(in_fd, "w", encoding="utf-8") as fh:
                fh.write("\n".join(targets) + "\n")
            self._exec(self.build_command(in_path, out_path))
            return self.parse_output(out_path)
        finally:
            for p in (in_path, out_path):
                try:
                    os.unlink(p)
                except OSError:
                    pass

    def build_command(self, in_path: str, out_path: str) -> List[str]:
        cmd = [self.binary, "-i", in_path, "-oJ", out_path, "-q", "-m", "GET",
               "--stable", "-T", str(int(self.cfg.timeout))]
        wl = resolve_param_wordlist(self.cfg)
        if wl:
            cmd += ["-w", wl]
        if self.cfg.delay and self.cfg.delay > 0:
            cmd += ["-d", str(self.cfg.delay)]
        if self.cfg.rate and self.cfg.rate > 0:
            cmd += ["--rate-limit", str(int(self.cfg.rate))]
        header_block = "\n".join(self._auth_header_lines()
                                 + ([f"Cookie: {self._cookie_header()}"] if self._cookie_header() else []))
        if header_block:
            cmd += ["--headers", header_block]
        return cmd

    def parse_output(self, out_path: str) -> List[Finding]:
        try:
            with open(out_path, "r", encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return []
        out: List[Finding] = []
        if isinstance(data, dict):
            for url, info in data.items():
                params: List[str] = []
                if isinstance(info, dict):
                    params = [str(p) for p in (info.get("params") or []) if p]
                elif isinstance(info, list):
                    params = [str(p) for p in info if p]
                if params:
                    out.append(Finding(kind="param", url=str(url),
                                       params=params, source=self.name))
        return out


# ---------------------------------------------------------------------------
# Discovery: JS-aware crawlers
# ---------------------------------------------------------------------------

class KatanaTool(ExternalTool):
    """JS-aware crawling via projectdiscovery/katana, seeded from the targets.

    katana parses JavaScript for endpoints, follows known files
    (robots/sitemap), and carries the session through ``-H`` headers/cookies —
    so it reaches authenticated, JS-rendered routes arachne's static pass may
    not link to. Default (non-headless) mode keeps it dependency-free; use
    arachne's own ``--render`` for browser execution."""
    name = "katana"
    binary = "katana"
    active = False
    category = "crawl"
    input_kind = "seeds"
    purpose = "JS-aware crawl (links, JS endpoints, known files)"
    install = "go install github.com/projectdiscovery/katana/cmd/katana@latest"
    doc = "https://github.com/projectdiscovery/katana"

    def run(self, seeds: List[str]) -> List[Finding]:
        if not seeds:
            return []
        out = self._run_stdout(self.build_command(seeds))
        if out is None:
            return []
        return self._url_findings(out)

    def build_command(self, seeds: List[str]) -> List[str]:
        cmd = [self.binary, "-silent",
               "-d", str(max(1, self.cfg.max_depth)),
               "-jc",                 # crawl endpoints found in JavaScript
               "-kf", "all"]          # robots.txt + sitemap.xml
        for s in seeds:
            cmd += ["-u", s]
        if self.cfg.include_subdomains:
            cmd += ["-fs", "rdn"]     # field-scope: whole root domain
        if self.cfg.concurrency:
            cmd += ["-c", str(self.cfg.concurrency)]
        if self.cfg.rate and self.cfg.rate > 0:
            cmd += ["-rl", str(int(self.cfg.rate))]
        if self.cfg.proxy:
            cmd += ["-proxy", self.cfg.proxy]
        for h in self._auth_header_lines():
            cmd += ["-H", h]
        cookie = self._cookie_header()
        if cookie:
            cmd += ["-H", f"Cookie: {cookie}"]
        return cmd


class HakrawlerTool(ExternalTool):
    """Fast breadth crawl via hakrawler (reads target URLs from stdin)."""
    name = "hakrawler"
    binary = "hakrawler"
    active = False
    category = "crawl"
    input_kind = "seeds"
    purpose = "fast breadth crawl + JS link extraction"
    install = "go install github.com/hakluke/hakrawler@latest"
    doc = "https://github.com/hakluke/hakrawler"

    def run(self, seeds: List[str]) -> List[Finding]:
        if not seeds:
            return []
        cmd, stdin_data = self.build_command(seeds)
        out = self._run_stdout(cmd, stdin_data=stdin_data)
        if out is None:
            return []
        return self._url_findings(out)

    def build_command(self, seeds: List[str]):
        cmd = [self.binary, "-u", "-d", str(max(1, self.cfg.max_depth)),
               "-t", str(max(1, self.cfg.concurrency))]
        if self.cfg.include_subdomains:
            cmd += ["-subs"]
        if self.cfg.insecure:
            cmd += ["-insecure"]
        if self.cfg.proxy:
            cmd += ["-proxy", self.cfg.proxy]
        # hakrawler takes custom headers as one -h string, entries split by ";;"
        headers = self._auth_header_lines()
        cookie = self._cookie_header()
        if cookie:
            headers.append(f"Cookie: {cookie}")
        if headers:
            cmd += ["-h", ";;".join(headers)]
        return cmd, "\n".join(seeds) + "\n"


class GospiderTool(ExternalTool):
    """Fast crawl + passive-source gathering via gospider."""
    name = "gospider"
    binary = "gospider"
    active = False
    category = "crawl"
    input_kind = "seeds"
    purpose = "fast crawl + passive source gathering"
    install = "go install github.com/jaeles-project/gospider@latest"
    doc = "https://github.com/jaeles-project/gospider"

    def run(self, seeds: List[str]) -> List[Finding]:
        if not seeds:
            return []
        out = self._run_stdout(self.build_command(seeds))
        if out is None:
            return []
        return self._url_findings(out)

    def build_command(self, seeds: List[str]) -> List[str]:
        # Conservative flag set: -q/-d/-c/-s/-p/-H/--cookie are stable across
        # gospider versions; the tolerant URL extractor handles its tagged output.
        cmd = [self.binary, "-q",                 # quiet: print discovered URLs only
               "-d", str(max(1, self.cfg.max_depth)),
               "-c", str(max(1, self.cfg.concurrency))]
        for s in seeds:
            cmd += ["-s", s]
        if self.cfg.proxy:
            cmd += ["-p", self.cfg.proxy]
        for h in self._auth_header_lines():
            cmd += ["-H", h]
        cookie = self._cookie_header()
        if cookie:
            cmd += ["--cookie", cookie]
        return cmd


# ---------------------------------------------------------------------------
# Discovery: passive URL archives
# ---------------------------------------------------------------------------

class GauTool(ExternalTool):
    """Passive historical URLs via gau (Wayback / CommonCrawl / OTX / URLScan)."""
    name = "gau"
    binary = "gau"
    active = False
    category = "passive"
    input_kind = "domains"
    purpose = "passive URLs from Wayback/CommonCrawl/OTX/URLScan"
    install = "go install github.com/lc/gau/v2/cmd/gau@latest"
    doc = "https://github.com/lc/gau"

    def run(self, domains: List[str]) -> List[Finding]:
        return self._collect(domains, lambda d: self.build_command(d))

    def build_command(self, domain: str) -> List[str]:
        cmd = [self.binary, "--threads", str(max(1, self.cfg.concurrency))]
        if self.cfg.include_subdomains:
            cmd += ["--subs"]
        cmd += [domain]
        return cmd

    def _collect(self, domains, build) -> List[Finding]:
        seen: set = set()
        urls: List[str] = []
        for d in domains:
            out = self._run_stdout(build(d))
            if not out:
                continue
            for u in self._urls_from_text(out):
                if u not in seen:
                    seen.add(u)
                    urls.append(u)
        cap = self.cfg.tool_max_results
        if cap and cap > 0:
            urls = urls[:cap]
        return [Finding(kind="url", url=u, source=self.name) for u in urls]


class WaybackurlsTool(GauTool):
    """Passive historical URLs via tomnomnom/waybackurls (Wayback Machine)."""
    name = "waybackurls"
    binary = "waybackurls"
    category = "passive"
    purpose = "passive URLs from the Wayback Machine"
    install = "go install github.com/tomnomnom/waybackurls@latest"
    doc = "https://github.com/tomnomnom/waybackurls"

    def build_command(self, domain: str) -> List[str]:
        return [self.binary, domain]


class UrlfinderTool(ExternalTool):
    """Passive URL discovery via projectdiscovery/urlfinder (wraps passive.py)."""
    name = "urlfinder"
    binary = "urlfinder"
    active = False
    category = "passive"
    input_kind = "domains"
    purpose = "passive URL discovery (projectdiscovery)"
    install = "go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest"
    doc = "https://github.com/projectdiscovery/urlfinder"

    def run(self, domains: List[str]) -> List[Finding]:
        from . import passive
        urls = passive.run_urlfinder(domains, self.binary, self.cfg.tool_timeout)
        if not urls:
            return []
        cap = self.cfg.tool_max_results
        if cap and cap > 0:
            urls = urls[:cap]
        return [Finding(kind="url", url=u, source=self.name) for u in urls]


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_REGISTRY: Dict[str, Type[ExternalTool]] = {
    # active (require --fuzz)
    "ffuf": FfufTool,
    "feroxbuster": FeroxbusterTool,
    "arjun": ArjunTool,
    # discovery (passive archives + JS-aware crawlers)
    "katana": KatanaTool,
    "hakrawler": HakrawlerTool,
    "gospider": GospiderTool,
    "gau": GauTool,
    "waybackurls": WaybackurlsTool,
    "urlfinder": UrlfinderTool,
}


def known_tools() -> List[str]:
    return sorted(_REGISTRY)


def is_active(name: str) -> bool:
    cls = _REGISTRY.get(name)
    return bool(cls and cls.active)


def _binary_for(cfg: Config, name: str, cls: Type[ExternalTool]) -> str:
    """Resolve the binary path: --tool-path override -> <name>_path field -> default."""
    return (cfg.tool_paths.get(name)
            or getattr(cfg, name + "_path", None)
            or cls.binary)


def build_tools(cfg: Config) -> List[ExternalTool]:
    """Instantiate the enabled tools from cfg.external_tools, honouring path overrides."""
    tools: List[ExternalTool] = []
    seen = set()
    for name in cfg.external_tools:
        if name in seen:
            continue
        seen.add(name)
        cls = _REGISTRY.get(name)
        if cls is None:
            continue
        tools.append(cls(cfg, binary=_binary_for(cfg, name, cls)))
    return tools


def tool_catalog() -> List[dict]:
    """Metadata + PATH availability for every registered tool (for --check-tools)."""
    rows: List[dict] = []
    for name in known_tools():
        cls = _REGISTRY[name]
        rows.append({
            "name": name,
            "binary": cls.binary,
            "active": cls.active,
            "category": cls.category,
            "purpose": cls.purpose,
            "install": cls.install,
            "doc": cls.doc,
            "available": shutil.which(cls.binary) is not None,
        })
    return rows


SECLISTS_REPO = "https://github.com/danielmiessler/SecLists.git"
DEFAULT_SECLISTS_DEST = os.path.expanduser("~/.arachne/wordlists/SecLists")


def fetch_seclists(dest: Optional[str] = None):
    """Shallow-clone SecLists so the resolver can use its heavy lists.

    Returns (ok, message). git streams its own progress to the terminal (output
    is not captured). Idempotent: an existing checkout is reported, not re-cloned.
    """
    dest = dest or DEFAULT_SECLISTS_DEST
    if os.path.isdir(os.path.join(dest, "Discovery")):
        return True, f"SecLists already present at {dest}"
    if shutil.which("git") is None:
        return False, ("git not found on PATH — install git, or download SecLists "
                       "manually and point --seclists-root at it")
    try:
        os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
        proc = subprocess.run(["git", "clone", "--depth", "1", SECLISTS_REPO, dest],
                              timeout=3600)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return False, f"clone failed: {exc}"
    if proc.returncode != 0:
        return False, f"git clone exited with status {proc.returncode}"
    return True, f"SecLists ready at {dest}"


def synthesize_param_url(url: str, names: List[str], value: str = "1") -> Optional[str]:
    """Append discovered param names (with a probe value) to a URL so the crawler
    fetches the parameterised endpoint and extract.py can mine the response."""
    try:
        sp = urlsplit(url)
    except ValueError:
        return None
    if not sp.scheme or not sp.netloc:
        return None
    pairs = parse_qsl(sp.query, keep_blank_values=True)
    have = {k for k, _ in pairs}
    for n in names:
        if n and n not in have:
            pairs.append((n, value))
    pairs.sort()
    return urlunsplit((sp.scheme, sp.netloc, sp.path or "/", urlencode(pairs), ""))
