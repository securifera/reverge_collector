"""Unified process/future handle for scan tool execution.

A ProcessHandle tracks either or both:
- a subprocess PID
- a concurrent.futures.Future

It provides a single kill() operation and a done-callback hook for cleanup.
"""

import os
import signal
from dataclasses import dataclass
from typing import Any, Callable, Optional


@dataclass
class ProcessHandle:
    """Track a tool execution unit (future and/or PID)."""

    future: Optional[Any] = None
    pid: Optional[int] = None
    on_cleanup: Optional[Callable[["ProcessHandle"], None]] = None

    def add_done_callback(self, callback: Callable[[Any], None]) -> None:
        """Attach a callback to the underlying future if present."""
        if self.future is not None:
            self.future.add_done_callback(callback)

    def is_done(self) -> bool:
        """Return True when the future is complete (or absent)."""
        return self.future is None or self.future.done()

    def is_pid_alive(self) -> bool:
        """Return True if PID exists."""
        if self.pid is None:
            return False
        try:
            os.kill(self.pid, 0)
            return True
        except OSError:
            return False

    def kill(self) -> None:
        """Best-effort termination of PID and cancellation of future."""
        if self.pid is not None:
            try:
                os.kill(self.pid, signal.SIGKILL)
            except OSError:
                pass

        if self.future is not None:
            try:
                self.future.cancel()
            except Exception:
                pass

        if self.on_cleanup:
            try:
                self.on_cleanup(self)
            except Exception:
                pass
