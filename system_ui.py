import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import threading
import os
import tempfile
import psutil
import yara
import ttkbootstrap as tb        # NEW
from ttkbootstrap.constants import *


# --- Load YARA Rules ---
try:
    rules = yara.compile(filepath="C:\\Users\\Admin\\Desktop\\Python-systemScanner\\malware_rules.yar")
except:
    print("Failed to load YARA rules!")


# ============================================
#   FUNCTIONS (same as before)
# ============================================

def scan_file_ui(filepath, output_area):
    try:
        matches = rules.match(filepath=filepath)
        if matches:
            for match in matches:
                output_area.insert(END, f"[MATCH FOUND] {filepath} -> {match.rule}\n")
            return True
    except:
        pass
    return False


def scan_directory_ui(path, output_area):
    output_area.insert(END, f"Counting files in: {path}...\n")
    total_files = sum([len(files) for _, _, files in os.walk(path)])

    safe_ui_update(progress_bar, 'maximum', total_files)
    safe_ui_update(file_count_label, 'text', f"Files: 0/{total_files}")

    output_area.insert(END, f"Found {total_files} files. Starting scan...\n")
    threats = 0
    scanned = 0

    for dirpath, _, files in os.walk(path):
        for file in files:
            fp = os.path.join(dirpath, file)
            if scan_file_ui(fp, output_area):
                threats += 1
            scanned += 1

            safe_ui_update(progress_bar, 'value', scanned)
            safe_ui_update(file_count_label, 'text', f"Files: {scanned}/{total_files}")

    output_area.insert(END, f"Scan complete. Found {threats} threats.\n")
    return threats, scanned


def clean_temp_files_ui(output_area):
    temp_dir = tempfile.gettempdir()
    output_area.insert(END, f"Cleaning: {temp_dir}\n")
    deleted = 0

    for f in os.listdir(temp_dir):
        fp = os.path.join(temp_dir, f)
        try:
            if os.path.isfile(fp) or os.path.islink(fp):
                os.unlink(fp)
                deleted += 1
        except:
            pass

    output_area.insert(END, f"Deleted {deleted} temporary files.\n")


def monitor_system_usage_ui(output_area):
    cpu = psutil.cpu_percent(1)
    mem = psutil.virtual_memory()
    output_area.insert(END, f"CPU Usage: {cpu}%\n")
    output_area.insert(END, f"Free Memory: {mem.available / 1024**2:.2f} MB\n")


def safe_ui_update(widget, prop, value):
    root.after(0, lambda: widget.config(**{prop: value}))


def on_scan_complete(path, threats, scanned):
    progress_bar['value'] = progress_bar['maximum']
    status_label.config(text=f"Completed: {scanned} files, {threats} threats.", bootstyle=SUCCESS)

    scan_button.config(state=NORMAL)
    clean_button.config(state=NORMAL)
    monitor_button.config(state=NORMAL)


def run_scan_thread():
    path = filedialog.askdirectory(title="Select Folder to Scan")
    if not path:
        return

    output_area.delete(1.0, END)
    status_label.config(text="Scanning...", bootstyle=INFO)

    scan_button.config(state=DISABLED)
    clean_button.config(state=DISABLED)
    monitor_button.config(state=DISABLED)

    progress_bar['value'] = 0

    def task():
        threats, scanned = scan_directory_ui(path, output_area)
        on_scan_complete(path, threats, scanned)

    threading.Thread(target=task).start()


def run_cleaner_thread():
    output_area.delete(1.0, END)
    status_label.config(text="Cleaning Temporary Files...", bootstyle=INFO)

    scan_button.config(state=DISABLED)
    clean_button.config(state=DISABLED)
    monitor_button.config(state=DISABLED)

    def task():
        clean_temp_files_ui(output_area)
        status_label.config(text="Cleanup Complete!", bootstyle=SUCCESS)

        scan_button.config(state=NORMAL)
        clean_button.config(state=NORMAL)
        monitor_button.config(state=NORMAL)

    threading.Thread(target=task).start()


def run_monitor_thread():
    output_area.delete(1.0, END)
    status_label.config(text="Monitoring...", bootstyle=INFO)

    scan_button.config(state=DISABLED)
    clean_button.config(state=DISABLED)
    monitor_button.config(state=DISABLED)

    def task():
        monitor_system_usage_ui(output_area)
        status_label.config(text="System Stats Ready", bootstyle=SUCCESS)

        scan_button.config(state=NORMAL)
        clean_button.config(state=NORMAL)
        monitor_button.config(state=NORMAL)

    threading.Thread(target=task).start()



# ============================================
#   TKBOOTSTRAP UI
# ============================================

root = tb.Window(themename="superhero")   # MODERN THEME
root.title("Python System Utility")
root.geometry("650x650")

# Progress Bar
progress_bar = tb.Progressbar(root, bootstyle=INFO, mode="determinate")
progress_bar.pack(fill=X, padx=10, pady=10)

# Status Label
status_label = tb.Label(root, text="Ready", bootstyle=INFO, anchor=W)
status_label.pack(fill=X, padx=10)

# Buttons Frame
frame = tb.Frame(root)
frame.pack(pady=15)

scan_button = tb.Button(frame, text="Run Malware Scan", bootstyle=PRIMARY, command=run_scan_thread)
scan_button.grid(row=0, column=0, padx=5)

clean_button = tb.Button(frame, text="System Cleaner", bootstyle=WARNING, command=run_cleaner_thread)
clean_button.grid(row=0, column=1, padx=5)

monitor_button = tb.Button(frame, text="Monitor Usage", bootstyle=INFO, command=run_monitor_thread)
monitor_button.grid(row=0, column=2, padx=5)

exit_button = tb.Button(frame, text="Exit", bootstyle=DANGER, command=root.destroy)
exit_button.grid(row=0, column=3, padx=5)

# Output Console
output_area = scrolledtext.ScrolledText(root, bg="black", fg="lime", font=("Consolas", 10))
output_area.pack(padx=10, pady=10, fill=BOTH, expand=True)

# File counter
file_count_label = tb.Label(root, text="Files: 0/0", bootstyle=SECONDARY)
file_count_label.pack(pady=10)

root.mainloop()
