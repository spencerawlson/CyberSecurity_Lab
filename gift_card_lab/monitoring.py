from __future__ import annotations

import os
import threading
import time

try:
    from pynput import keyboard
except Exception:  # optional dependency
    keyboard = None

try:
    import pyperclip
except Exception:  # optional dependency
    pyperclip = None

try:
    from PIL import ImageGrab
except Exception:  # optional dependency
    ImageGrab = None

try:
    import psutil
except Exception:  # optional dependency
    psutil = None

try:
    import pygetwindow as gw  # type: ignore[import-untyped]
except Exception:  # optional dependency
    gw = None


def on_press(key):
    try:
        print(f"Key pressed: {key.char}")
    except AttributeError:
        print(f"Special key pressed: {key}")


def log_clipboard(stop_event: threading.Event | None = None, interval_s: float = 60):
    recent_value = ""
    stop = stop_event or threading.Event()

    if pyperclip is None:
        print("Clipboard monitor unavailable: pyperclip not installed")
        return

    while not stop.is_set():
        stop.wait(max(0.1, interval_s))
        if stop.is_set():
            break
        current_value = pyperclip.paste()
        if current_value != recent_value:
            recent_value = current_value
            print(f"Clipboard content: {recent_value}")


def capture_screen(
    stop_event: threading.Event | None = None,
    interval_s: float = 60,
    screenshot_dir: str = "screenshots",
):
    stop = stop_event or threading.Event()

    if ImageGrab is None:
        print("Screen capture unavailable: pillow not installed")
        return

    os.makedirs(screenshot_dir, exist_ok=True)
    while not stop.is_set():
        stop.wait(max(0.1, interval_s))
        if stop.is_set():
            break
        screenshot = ImageGrab.grab()
        screenshot.save(os.path.join(screenshot_dir, f"screenshot_{int(time.time())}.png"))


def track_activity(stop_event: threading.Event | None = None, interval_s: float = 5):
    previous_window = None
    stop = stop_event or threading.Event()

    while not stop.is_set():
        stop.wait(max(0.1, interval_s))
        if stop.is_set():
            break

        if gw is not None:
            current_window = gw.getActiveWindowTitle()
            if current_window != previous_window:
                previous_window = current_window
                print(f"Active window: {current_window}")

        if psutil is not None:
            for proc in psutil.process_iter(["pid", "name"]):
                print(f"Running process: {proc.info['name']} (PID: {proc.info['pid']})")


def start_monitoring(
    *,
    enable_keylogger: bool = True,
    enable_clipboard: bool = True,
    enable_screen: bool = True,
    enable_activity: bool = True,
):
    """Explicit monitor startup. Nothing runs automatically at import time."""
    stop_event = threading.Event()
    listener = None
    threads: list[threading.Thread] = []

    if enable_keylogger:
        if keyboard is None:
            print("Keylogger unavailable: pynput not installed")
        else:
            listener = keyboard.Listener(on_press=on_press)
            listener.start()

    if enable_clipboard:
        t = threading.Thread(target=log_clipboard, args=(stop_event,), daemon=True)
        t.start()
        threads.append(t)

    if enable_screen:
        t = threading.Thread(target=capture_screen, args=(stop_event,), daemon=True)
        t.start()
        threads.append(t)

    if enable_activity:
        t = threading.Thread(target=track_activity, args=(stop_event,), daemon=True)
        t.start()
        threads.append(t)

    return stop_event, listener, threads


def stop_monitoring(stop_event, listener, threads):
    stop_event.set()
    if listener is not None:
        listener.stop()
    for t in threads:
        t.join(timeout=2)


