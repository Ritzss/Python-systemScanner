import tkinter as tk
print("Imported tkinter")
from tkinter import scrolledtext, filedialog, messagebox
import threading
import os
import tempfile
import shutil
import psutil
import yara

print("Imports successful")

# --- Integrate your existing logic functions here ---

# Compile the YARA rules (Ensure malware_rules.yar is in the same directory)
try:
    rules = yara.compile(filepath="malware_rules.yar")
except yara.SyntaxError as e:
    # Handle this in the UI if needed
    pass 

def scan_file_ui(filepath, output_area):
    try:
        matches = rules.match(filepath=filepath)
        if matches:
            for match in matches:
                output_area.insert(tk.END, f"[MATCH FOUND] {filepath} -> Matched rule: {match.rule}\n")
            return True
    except yara.Error:
        pass
    return False

def scan_directory_ui(path, output_area):
    output_area.insert(tk.END, f"Starting scan of: {path}\n")
    threats_found = 0
    files_scanned = 0
    for root, _, files in os.walk(path):
        for file in files:
            filepath = os.path.join(root, file)
            if scan_file_ui(filepath, output_area):
                threats_found += 1
            files_scanned += 1
    output_area.insert(tk.END, f"Scan Summary: Scanned {files_scanned} files. Found {threats_found} threats.\n")
    output_area.insert(tk.END, "Scan finished.\n")

def clean_temp_files_ui(output_area):
    temp_dir = tempfile.gettempdir()
    output_area.insert(tk.END, f"Scanning for temporary files in {temp_dir}...\n")
    cleaned_count = 0
    for filename in os.listdir(temp_dir):
        file_path = os.path.join(temp_dir, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
                cleaned_count += 1
        except Exception as e:
            output_area.insert(tk.END, f"Failed to delete {file_path}. Reason: {e}\n")
    output_area.insert(tk.END, f"System cleanup complete. Deleted {cleaned_count} files.\n")

def monitor_system_usage_ui(output_area):
    cpu_usage = psutil.cpu_percent(interval=1)
    memory_info = psutil.virtual_memory()
    output_area.insert(tk.END, f"CPU Usage: {cpu_usage}%\n")
    output_area.insert(tk.END, f"Available Memory: {memory_info.available / (1024*1024):.2f} MB\n")

# --- UI Functions ---


def set_status(message, color="black"):
    # This requires the status_label widget to exist later in the code
    status_label.config(text=message, fg=color)

def run_scan_thread():
    scan_path = filedialog.askdirectory(title="Select Folder to Scan")
    if scan_path:
        # Clear previous output
        output_area.delete(1.0, tk.END) 
        
        # --- NEW CODE: Update status and disable buttons ---
        set_status(f"Scan started on {scan_path}...", "blue")
        scan_button.config(state=tk.DISABLED)
        clean_button.config(state=tk.DISABLED)
        monitor_button.config(state=tk.DISABLED) # Disable all buttons
        
        # --- NEW CODE: Use lambda within thread target to execute multiple steps sequentially ---
        thread = threading.Thread(target=lambda: (
            scan_directory_ui(scan_path, output_area),
            set_status("Scan complete.", "green"),
            # Re-enable buttons after scan finishes
            scan_button.config(state=tk.NORMAL),
            clean_button.config(state=tk.NORMAL),
            monitor_button.config(state=tk.NORMAL)
        ))
        thread.start()
    else:
        # Update status if the dialog is canceled
        set_status("Folder selection cancelled.", "orange")
        messagebox.showinfo("Scan Cancelled", "Folder selection cancelled.")


def run_cleaner_thread():
    output_area.delete(1.0, tk.END)
    
    # --- NEW CODE ---
    set_status("Cleaning temporary files...", "blue")
    scan_button.config(state=tk.DISABLED) # Disable other buttons too
    clean_button.config(state=tk.DISABLED)
    monitor_button.config(state=tk.DISABLED)

    thread = threading.Thread(target=lambda: (
        clean_temp_files_ui(output_area),
        set_status("Cleanup complete.", "green"),
        # Re-enable buttons after cleanup
        scan_button.config(state=tk.NORMAL),
        clean_button.config(state=tk.NORMAL),
        monitor_button.config(state=tk.NORMAL)
    ))
    thread.start()

def run_monitor_thread():
    output_area.delete(1.0, tk.END)
    
    # --- NEW CODE: Update status and disable buttons ---
    set_status("Monitoring system usage...", "blue")
    scan_button.config(state=tk.DISABLED)
    clean_button.config(state=tk.DISABLED)
    monitor_button.config(state=tk.DISABLED)

    # Use a thread even for the monitor as a best practice, although it runs quickly
    thread = threading.Thread(target=lambda: (
        monitor_system_usage_ui(output_area),
        set_status("System monitoring results displayed.", "green"),
        # Re-enable buttons after monitoring
        scan_button.config(state=tk.NORMAL),
        clean_button.config(state=tk.NORMAL),
        monitor_button.config(state=tk.NORMAL)
    ))
    thread.start()


# --- Main Application Window ---


print("Creating main window")

root = tk.Tk()
root.title("Python System Utility")
root.geometry("600x400") # Set the initial window size


# Create a label for status messages and place it at the bottom
status_label = tk.Label(root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
# Use pack to place it at the bottom, filling horizontally
status_label.pack(side=tk.BOTTOM, fill=tk.X)

# Create a frame for the buttons
button_frame = tk.Frame(root)
button_frame.pack(pady=10)

# Create buttons
scan_button = tk.Button(button_frame, text="Run Malware Scan", command=run_scan_thread)
scan_button.grid(row=0, column=0, padx=5)

clean_button = tk.Button(button_frame, text="Run System Cleaner", command=run_cleaner_thread)
clean_button.grid(row=0, column=1, padx=5)

monitor_button = tk.Button(button_frame, text="Monitor System Usage", command=run_monitor_thread)
monitor_button.grid(row=0, column=2, padx=5)

exit_button = tk.Button(button_frame, text="Exit", command=root.destroy)
exit_button.grid(row=0, column=3, padx=5)

# Create a scrolled text area for output
output_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, bg="black", fg="green")
output_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

# Create a label for status messages
status_label = tk.Label(root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
# Use pack to place it at the bottom, filling horizontally
status_label.pack(side=tk.BOTTOM, fill=tk.X)


print("Window created, starting mainloop")
root.mainloop()
print("Window closed")