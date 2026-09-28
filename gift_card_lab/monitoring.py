"""Optional local monitoring helpers for lab demos.

This module is import-safe:
- no threads/listeners start at import time
- no infinite loops run automatically
- all collectors are explicitly started/stopped by the caller

It keeps compatibility names (listener, clipboard_thread, screen_thread,
activity_thread) so older callers do not crash on import.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Callable

try:
    import pyperclip
except Exception:  # pragma: no cover - optional dependency
    pyperclip = None

try:
    from PIL import ImageGrab
except Exception:  # pragma: no cover - optional dependency
    ImageGrab = None

try:
    import psutil
except Exception:  # pragma: no cover - optional dependency
    psutil = None

try:
    import pygetwindow as gw  # type: ignore[import-untyped]
except Exception:  # pragma: no cover - optional dependency
    gw = None


# Backward-compatible names expected by older imports.
listener = None
clipboard_thread: threading.Thread | None = None
screen_thread: threading.Thread | None = None
activity_thread: threading.Thread | None = None


def _safe_log(log_fn: Callable[[str], None], msg: str) -> None:
    try:
        log_fn(msg)
    except Exception:
        pass


def _clipboard_worker(stop: threading.Event, interval_s: float, log_fn: Callable[[str], None]) -> None:
    if pyperclip is None:
        _safe_log(log_fn, "[monitoring] clipboard disabled: pyperclip not installed")
        return
    recent = None
    while not stop.is_set():
        try:
            current = pyperclip.paste()
            if current != recent:
                recent = current
                _safe_log(log_fn, f"[monitoring] clipboard changed ({len(str(current))} chars)")
        except Exception as exc:
            _safe_log(log_fn, f"[monitoring] clipboard read error: {exc}")
        stop.wait(max(0.1, interval_s))


def _screen_worker(
    stop: threading.Event,
    interval_s: float,
    out_dir: Path,
    log_fn: Callable[[str], None],
) -> None:
    if ImageGrab is None:
        _safe_log(log_fn, "[monitoring] screenshots disabled: pillow not installed")
        return
    out_dir.mkdir(parents=True, exist_ok=True)
    while not stop.is_set():
        try:
            stamp = int(time.time())
            path = out_dir / f"screenshot_{stamp}.png"
            ImageGrab.grab().save(path)
            _safe_log(log_fn, f"[monitoring] screenshot saved: {path}")
        except Exception as exc:
            _safe_log(log_fn, f"[monitoring] screenshot error: {exc}")
        stop.wait(max(0.5, interval_s))


def _activity_worker(stop: threading.Event, interval_s: float, log_fn: Callable[[str], None]) -> None:
    prev_window = None
    while not stop.is_set():
        if gw is not None:
            try:
                current = gw.getActiveWindowTitle()
                if current != prev_window:
                    prev_window = current
                    _safe_log(log_fn, f"[monitoring] active window: {current}")
            except Exception as exc:
                _safe_log(log_fn, f"[monitoring] window probe error: {exc}")

        if psutil is not None:
            try:
                count = sum(1 for _ in psutil.process_iter(["pid"]))
                _safe_log(log_fn, f"[monitoring] running processes: {count}")
            except Exception as exc:
                _safe_log(log_fn, f"[monitoring] process probe error: {exc}")

        stop.wait(max(0.5, interval_s))


def start_monitoring(
    *,
    enable_clipboard: bool = False,
    enable_screenshots: bool = False,
    enable_activity: bool = False,
    screenshot_dir: str | Path = "screenshots",
    clipboard_interval_s: float = 5.0,
    screenshot_interval_s: float = 60.0,
    activity_interval_s: float = 5.0,
    log_fn: Callable[[str], None] = print,
) -> tuple[threading.Event, list[threading.Thread]]:
    """Start selected monitors and return (stop_event, threads).

    Caller must signal stop_event.set() and join returned threads.
    """
    stop = threading.Event()
    threads: list[threading.Thread] = []

    if enable_clipboard:
        t = threading.Thread(
            target=_clipboard_worker,
            args=(stop, clipboard_interval_s, log_fn),
            name="monitoring-clipboard",
            daemon=True,
        )
        t.start()
        threads.append(t)

    if enable_screenshots:
        t = threading.Thread(
            target=_screen_worker,
            args=(stop, screenshot_interval_s, Path(screenshot_dir), log_fn),
            name="monitoring-screen",
            daemon=True,
        )
        t.start()
        threads.append(t)

    if enable_activity:
        t = threading.Thread(
            target=_activity_worker,
            args=(stop, activity_interval_s, log_fn),
            name="monitoring-activity",
            daemon=True,
        )
        t.start()
        threads.append(t)

    return stop, threads
