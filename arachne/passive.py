"""Optional integration with projectdiscovery/urlfinder for passive URL discovery.

urlfinder (https://github.com/projectdiscovery/urlfinder) is an external Go
binary. If installed, arachne runs it over the in-scope domains and folds the
passively discovered URLs into the crawl frontier. If the binary is absent the
crawl continues without it.

Install:  go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest
"""
from __future__ import annotations

import shutil
import subprocess
from typing import List, Optional, Iterable


def available(binary: str = "urlfinder") -> bool:
    return shutil.which(binary) is not None


def run_urlfinder(domains: Iterable[str], binary: str = "urlfinder",
                  timeout: int = 180, extra_args: Optional[List[str]] = None) -> Optional[List[str]]:
    """Run urlfinder for each domain; return discovered URLs (deduped, sorted).

    Returns None if the binary is not found on PATH.
    """
    if not available(binary):
        return None
    urls = set()
    for domain in domains:
        cmd = [binary, "-d", domain, "-silent"]
        if extra_args:
            cmd.extend(extra_args)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError):
            continue
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if line.startswith(("http://", "https://")):
                urls.add(line)
    return sorted(urls)
