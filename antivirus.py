import os
from signatures import signatures

LOG_FILE = "scan_results.log"

def scan_file(file_path):
    """Scan a file for known malware signatures using chunked reading."""
    try:
        with open(file_path, 'rb') as file:
            while chunk := file.read(8192):  # Read 8 KB at a time
                for signature_name, signature in signatures.items():
                    if signature in chunk:
                        return signature_name
    except Exception as e:
        print(f"[ERROR] Failed to scan {file_path}: {e}")
    return None

def scan_directory(directory):
    """Recursively scan a directory for infected files."""
    infected_files = []

    with open(LOG_FILE, "w") as log:
        log.write(f"# Malware Scan Results\nDirectory: {directory}\n\n")

        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)

                # Skip symbolic links
                if os.path.islink(file_path):
                    continue

                result = scan_file(file_path)
                if result:
                    infected_files.append((file_path, result))
                    print(f"[ALERT] {file_path}: {result}")
                    log.write(f"{file_path}: {result}\n")

    return infected_files

def main():
    directory_to_scan = input("Enter the directory to scan: ")

    if not os.path.isdir(directory_to_scan):
        print(f"[ERROR] Invalid directory: {directory_to_scan}")
        return

    print(f"Scanning directory: {directory_to_scan}")
    infected_files = scan_directory(directory_to_scan)

    if infected_files:
        print("\nPotential malware detected:")
        for file_path, signature_name in infected_files:
            print(f"{file_path}: {signature_name}")
    else:
        print("\nNo malware detected.")

    print(f"\nResults saved to {LOG_FILE}")

if __name__ == "__main__":
    main()
