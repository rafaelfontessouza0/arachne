"""Runtime configuration."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

# Asset extensions we record but never recurse into (and skip entirely unless --include-assets).
DEFAULT_SKIP_EXT = {
    "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp", "tiff",
    "woff", "woff2", "ttf", "eot", "otf",
    "css", "scss", "less",
    "mp4", "webm", "ogg", "mp3", "wav", "avi", "mov", "flv",
    "pdf", "zip", "gz", "tar", "rar", "7z", "dmg", "exe", "apk", "ipa",
}

# Paths that change state or destroy a session — denied by default during authed crawls.
DEFAULT_ACTIVE_DENY = [
    r"/logout", r"/log-out", r"/signout", r"/sign-out", r"/log_off",
    r"/delete", r"/remove", r"/destroy", r"/deactivate", r"/cancel\b",
    r"/withdraw", r"/transfer", r"/pay\b", r"/purchase", r"/checkout",
    r"/unsubscribe", r"/disable",
]

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 arachne/0.1"
)


@dataclass
class Config:
    seeds: List[str] = field(default_factory=list)

    # Scope
    extra_scope: List[str] = field(default_factory=list)
    include_subdomains: bool = True
    allow_regex: List[str] = field(default_factory=list)
    deny_regex: List[str] = field(default_factory=list)
    skip_ext: set = field(default_factory=lambda: set(DEFAULT_SKIP_EXT))
    include_assets: bool = False
    dedup_params: bool = True

    # Budget / traversal
    concurrency: int = 20
    rate: float = 0.0          # requests/sec, 0 = unlimited
    delay: float = 0.0         # fixed per-request delay (sec)
    timeout: float = 20.0
    retries: int = 2
    max_depth: int = 3
    max_pages: int = 1000

    # Methods / safety
    allow_active: bool = False
    methods: List[str] = field(default_factory=lambda: ["GET", "HEAD"])
    respect_robots: bool = False
    crawl_sitemap: bool = True

    # Transport
    proxy: Optional[str] = None
    insecure: bool = False
    user_agent: str = DEFAULT_USER_AGENT
    follow_redirects: bool = True
    impersonate: Optional[str] = None    # curl_cffi browser profile, e.g. "chrome124"
    per_host_concurrency: int = 0        # 0 = no per-host cap (global concurrency only)

    # Auth
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    cookies_file: Optional[str] = None
    bearer: Optional[str] = None
    storage_state: Optional[str] = None  # Playwright storage_state json
    auth_header: str = "Authorization"
    auth_scheme: str = "Bearer"          # set "" for a raw token with no scheme
    auto_token: bool = True              # bridge a localStorage token from storage_state
    auth_token_key: Optional[str] = None
    token_bridged: bool = False          # set when a token was auto-bridged (for logging)

    # Re-authentication (recover an expired session mid-crawl)
    login_url: Optional[str] = None
    login_username: Optional[str] = None
    login_password: Optional[str] = None
    login_user_selector: Optional[str] = None
    login_pass_selector: Optional[str] = None
    login_submit_selector: Optional[str] = None
    login_success: Optional[str] = None   # selector or URL substring signalling success
    login_wait: int = 3000
    reauth_command: Optional[str] = None  # shell cmd printing {cookies,headers,bearer}
    reauth_max: int = 3

    # Passive seeding (HAR / Postman / Burp import, urlfinder)
    import_entries: List[Tuple[str, str]] = field(default_factory=list)  # (method, url)
    auth_fail_threshold: int = 10
    urlfinder: bool = False
    urlfinder_path: str = "urlfinder"

    # External-tool orchestration
    #   discovery tools (katana/gau/waybackurls/hakrawler/gospider/urlfinder) run
    #     whenever selected; active tools (ffuf/feroxbuster/arjun) need --fuzz.
    fuzz: bool = False                       # run the active enumeration phase
    external_tools: List[str] = field(default_factory=list)  # registry names to drive
    tool_paths: Dict[str, str] = field(default_factory=dict)  # name -> binary path override
    fuzz_wordlist: Optional[str] = None      # content wordlist for ffuf/feroxbuster (else SecLists/vendored)
    param_wordlist: Optional[str] = None     # wordlist for arjun (else its built-in)
    seclists_root: Optional[str] = None      # SecLists checkout for wordlist resolution
    ffuf_path: str = "ffuf"
    arjun_path: str = "arjun"
    tool_timeout: int = 180                  # per-tool subprocess timeout
    tool_max_results: int = 0                # cap results folded back per tool (0 = unlimited)
    fuzz_max_endpoints: int = 50             # max in-scope endpoints to probe for params
    auth_preflight: bool = True              # verify the session is live before crawling

    # Stateful scanner orchestration (Burp Pro REST API, OWASP ZAP daemon)
    scanners: List[str] = field(default_factory=list)  # "zap" | "burp"
    zap_url: str = "http://127.0.0.1:8080"   # ZAP daemon API base
    zap_api_key: Optional[str] = None
    zap_path: str = "zap.sh"                  # binary used by --zap-launch
    zap_launch: bool = False                  # launch a ZAP daemon if none is reachable
    zap_ajax: bool = False                    # also run the AJAX spider (SPA coverage)
    burp_api_url: str = "http://127.0.0.1:1337"  # Burp Pro REST API base
    burp_api_key: Optional[str] = None
    burp_config_name: Optional[str] = None    # Burp named scan configuration
    # Burp Pro headless (no REST API): launch burpsuite_pro.jar, crawl through its proxy
    burp_headless: bool = False
    burp_jar: Optional[str] = None            # path to burpsuite_pro.jar (else auto-detect)
    burp_headless_port: int = 8080            # proxy listener Burp opens headless
    burp_project: Optional[str] = None        # .burp project file (else <out>/burp-headless.burp)
    burp_config_files: List[str] = field(default_factory=list)  # project config(s) for scope/audit

    # Browser / render
    render: bool = False
    render_pages: int = 50
    render_wait: int = 2500      # ms to settle after load
    render_scroll: bool = True
    headful: bool = False
    browser_first: bool = False          # render seeds before the static crawl (SPA-first)
    stealth: bool = False                # apply playwright-stealth in render/login

    # Discovery / extraction
    fetch_candidates: bool = False   # also fetch weak (low-confidence) mined endpoints
    scan_secrets: bool = True        # scan bodies for secrets -> secrets.jsonl
    redact_secrets: bool = True
    api_docs: bool = True            # probe + parse OpenAPI/Swagger specs
    graphql: bool = True             # probe GraphQL endpoints with introspection

    # Output
    output_dir: str = "arachne-out"
    quiet: bool = False
    verbose: bool = False

    def effective_deny(self) -> List[str]:
        deny = list(self.deny_regex)
        if not self.allow_active:
            deny.extend(DEFAULT_ACTIVE_DENY)
        return deny
