"""Mid-crawl re-authentication: recover an expired session and resume.

Two recipes:
  * browser login (Playwright) — fill a login form, capture a fresh
    storage_state (cookies + localStorage token).
  * --reauth-command — run a shell command that prints fresh auth JSON
    {"cookies": {...}, "headers": {...}, "bearer": "..."} (e.g. an OAuth
    refresh or a curl-based login).

A single re-auth runs at a time (lock + generation counter) so a burst of
concurrent 401s triggers exactly one login, and total attempts are capped.
"""
from __future__ import annotations

import asyncio
import json
import os
from typing import Optional, Dict, Callable

from .config import Config


class ReAuth:
    def __init__(self, cfg: Config, http, log: Callable[[str], None]):
        self.cfg = cfg
        self.http = http
        self.log = log
        self._lock = None  # created lazily inside the running loop
        self.generation = 0
        self.attempts = 0
        self.reauths = 0
        self.enabled = bool(cfg.login_url or cfg.reauth_command)

    async def refresh(self, seen_gen: int) -> bool:
        """Ensure credentials are newer than seen_gen. Returns True if fresh
        credentials are now active (whether obtained by us or a peer worker)."""
        if not self.enabled:
            return False
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            if self.generation > seen_gen:
                return True  # another worker already re-authed
            if self.attempts >= self.cfg.reauth_max:
                return False
            self.attempts += 1
            self.log(f"[*] session expired — re-authenticating "
                     f"(attempt {self.attempts}/{self.cfg.reauth_max})...")
            material = await self._run_recipe()
            if not material or not (material.get("cookies") or material.get("headers")
                                    or material.get("bearer")):
                self.log("[!] re-auth failed (no fresh credentials obtained)")
                return False
            self._apply(material)
            self.generation += 1
            self.reauths += 1
            self.log("[+] re-auth succeeded — resuming crawl with a fresh session")
            return True

    async def _run_recipe(self) -> Optional[Dict]:
        if self.cfg.reauth_command:
            return await self._run_command()
        if self.cfg.login_url:
            return await self._run_browser_login()
        return None

    async def _run_command(self) -> Optional[Dict]:
        try:
            proc = await asyncio.create_subprocess_shell(
                self.cfg.reauth_command,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        except Exception as exc:
            self.log(f"[!] re-auth command error: {exc}")
            return None
        try:
            data = json.loads(out.decode("utf-8", "replace"))
        except Exception:
            self.log("[!] re-auth command did not print JSON {cookies,headers,bearer}")
            return None
        return self._normalize(data.get("cookies") or {}, data.get("headers") or {},
                               data.get("bearer"))

    async def _run_browser_login(self) -> Optional[Dict]:
        try:
            from .browser import login_to_storage_state
            from .auth import extract_token_from_storage
        except Exception:
            return None
        state = await login_to_storage_state(self.cfg)
        if not isinstance(state, dict):
            return None
        cookies = {c["name"]: c["value"] for c in state.get("cookies", [])
                   if c.get("name") and c.get("value") is not None}
        token = extract_token_from_storage(state, self.cfg.auth_token_key)
        # persist the fresh session so the render phase reuses it too
        path = self.cfg.storage_state or os.path.join(self.cfg.output_dir, ".session.json")
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(state, fh)
            self.cfg.storage_state = path
        except Exception:
            pass
        return self._normalize(cookies, {}, token)

    def _normalize(self, cookies, headers, bearer) -> Dict:
        headers = dict(headers or {})
        if bearer:
            scheme = (self.cfg.auth_scheme + " ") if self.cfg.auth_scheme else ""
            headers.setdefault(self.cfg.auth_header, f"{scheme}{bearer}")
        return {"cookies": cookies or {}, "headers": headers, "bearer": bearer}

    def _apply(self, material: Dict) -> None:
        self.http.update_auth(cookies=material.get("cookies"), headers=material.get("headers"))
        if material.get("cookies"):
            self.cfg.cookies.update(material["cookies"])
        if material.get("bearer"):
            self.cfg.bearer = material["bearer"]
        for k, v in (material.get("headers") or {}).items():
            self.cfg.headers[k] = v
