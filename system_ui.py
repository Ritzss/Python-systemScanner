import tkinter as tk
print("Imported tkinter")
from tkinter import scrolledtext, filedialog, messagebox ,ttk
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
    output_area.insert(tk.END, f"Counting files in: {path}...\n")
    
    # Count total files first (using a different variable name for 'root' here)
    total_files = sum([len(files) for dirpath, dirs, files in os.walk(path)])
    progress_bar['maximum'] = total_files 

    output_area.insert(tk.END, f"Found {total_files} files. Starting scan...\n")
    threats_found = 0
    files_scanned = 0
    
    # Rename 'root' to 'dirpath' to avoid conflict
    for dirpath, _, files in os.walk(path):
        for file in files:
            filepath = os.path.join(dirpath, file) # Use dirpath here too
            if scan_file_ui(filepath, output_area):
                threats_found += 1
            files_scanned += 1
            
            # Update progress bar value
            # Call update_idletasks() on the actual Tkinter window object 'root'
            safe_ui_update(progress_bar, 'value', files_scanned)

    output_area.insert(tk.END, f"Scan Summary: Scanned {files_scanned} files. Found {threats_found} threats.\n")
    output_area.insert(tk.END, "Scan finished.\n")
    
    return threats_found, files_scanned
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

def safe_ui_update(widget, prop, value):
    # Schedules the update to happen safely on the main thread
    root.after(0, lambda: widget.config(**{prop: value}))


def on_scan_complete(scan_path, threats_found, files_scanned):
    # This runs after scan_directory_ui finishes
    progress_bar['value'] = 100 # Assignment works here
    set_status(f"Scan complete. Scanned {files_scanned} files. Found {threats_found} threats.", "green")
    
    # Re-enable buttons after scan finishes
    scan_button.config(state=tk.NORMAL)
    clean_button.config(state=tk.NORMAL)
    monitor_button.config(state=tk.NORMAL)

    # Optional: Display a final confirmation pop-up
    if threats_found > 0:
        messagebox.showwarning("Scan Results", f"Scan finished. {threats_found} threats found!")
    else:
        messagebox.showinfo("Scan Results", "Scan finished. No threats found.")


def run_scan_thread():
    scan_path = filedialog.askdirectory(title="Select Folder to Scan")
    if scan_path:
        # ... (Disable buttons and set status) ...
        progress_bar['value'] = 0
        progress_bar['maximum'] = 100 # This max is just a placeholder until we count files in scan_directory_ui

        # Define the task that the thread will run
        def thread_task():
            # Run the scan and capture the results (threats, scanned_count)
            threats_found, files_scanned = scan_directory_ui(scan_path, output_area)
            # Call the completion helper function with the results
            on_scan_complete(scan_path, threats_found, files_scanned)

        # Start the thread with the new task function
        thread = threading.Thread(target=thread_task)
        thread.start()

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
root.geometry("1450x850") # Set the initial window size

# Create a progress bar
progress_bar = ttk.Progressbar(root, orient="horizontal", mode="determinate")
progress_bar.pack(padx=10, pady=5, fill=tk.X)

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