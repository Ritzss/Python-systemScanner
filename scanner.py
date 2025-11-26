import yara
import os
import shutil
import psutil # Ensure psutil is installed
import tempfile

# Compile the YARA rules from the file
try:
    rules = yara.compile(filepath="malware_rules.yar")
except yara.SyntaxError as e:
    print(f"YARA Rule Syntax Error: {e}")
    exit()

def scan_file(filepath):
    try:
        matches = rules.match(filepath=filepath)
        if matches:
            # Iterate over the list of matches returned by yara.match()
            for match in matches:
                print(f"[MATCH FOUND] {filepath} -> Matched rule: {match.rule}")
            return True  # Indicates a threat found
    except yara.Error as e:
        # Optional: uncomment to see why a specific file failed to scan
        # print(f"[ERROR] Could not scan {filepath}: {e}")
        pass
    return False 

def scan_directory(path):
    print(f"Scanning directory: {path}")
    threats_found = 0
    files_scanned = 0
    
    for root, _, files in os.walk(path):
        for file in files:
            filepath = os.path.join(root, file)
            # Optional: Add a print statement here to see every file being checked
            # print(f"Checking: {filepath}") 
            if scan_file(filepath):
                threats_found += 1
            files_scanned += 1

    print(f"Scan Summary: Scanned {files_scanned} files. Found {threats_found} threats.")


def clean_temp_files():
    temp_dir = tempfile.gettempdir()
    if not os.path.exists(temp_dir):
        print(f"Temporary directory not found at {temp_dir}")
        return

    print(f"Scanning for temporary files in {temp_dir}...")
    cleaned_count = 0
    for filename in os.listdir(temp_dir):
        file_path = os.path.join(temp_dir, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
                cleaned_count += 1
                # print(f"Deleted: {filename}")
        except Exception as e:
            print(f"Failed to delete {file_path}. Reason: {e}")

    print(f"System cleanup complete. Deleted {cleaned_count} files.")

def monitor_system_usage():
    # Example of using psutil for a 'system health' check
    cpu_usage = psutil.cpu_percent(interval=1)
    memory_info = psutil.virtual_memory()
    print(f"CPU Usage: {cpu_usage}%")
    print(f"Available Memory: {memory_info.available / (1024*1024):.2f} MB")

if __name__ == "__main__":
    
    SCAN_TARGET = "C:\\Users\\Admin\\Documents"
    
    while True:
        print("\nSelect an option:")
        print("1. Run Malware Scan")
        print("2. Run System Cleaner (clears temp files)")
        print("3. Monitor System Usage")
        print("4. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            scan_directory(SCAN_TARGET) # Update path
        elif choice == '2':
            clean_temp_files()
        elif choice == '3':
            monitor_system_usage()
        elif choice == '4':
            break
        else:
            print("Invalid choice. Please try again.")