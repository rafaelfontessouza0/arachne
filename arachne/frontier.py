"""Async frontier with de-duplication and budget enforcement."""
from __future__ import annotations

import asyncio
from typing import Optional

from .models import Task
from .scope import Scope
from .config import Config


class Frontier:
    def __init__(self, cfg: Config, scope: Scope):
        self.cfg = cfg
        self.scope = scope
        self._queue: "asyncio.Queue[Task]" = asyncio.Queue()
        self._seen: set = set()
        self._queued = 0          # number of tasks ever admitted
        self._lock = asyncio.Lock()

    @property
    def queued(self) -> int:
        return self._queued

    async def add(self, task: Task) -> bool:
        """Admit a task if novel, in budget, and an allowed method. Returns True if queued."""
        if task.method not in self.cfg.methods and task.method != "RENDER":
            return False
        if task.depth > self.cfg.max_depth:
            return False
        key = self.scope.dedup_key(task.url, task.method)
        async with self._lock:
            if key in self._seen:
                return False
            if self._queued >= self.cfg.max_pages:
                return False
            self._seen.add(key)
            self._queued += 1
        await self._queue.put(task)
        return True

    async def get(self) -> Task:
        return await self._queue.get()

    def task_done(self) -> None:
        self._queue.task_done()

    def empty(self) -> bool:
        return self._queue.empty()

    async def join(self) -> None:
        await self._queue.join()

    def mark_seen(self, url: str, method: str = "GET") -> None:
        self._seen.add(self.scope.dedup_key(url, method))
