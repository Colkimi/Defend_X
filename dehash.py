import subprocess
import re
import os
from hash_modes import HASH_MODES
# Mapping of hash names to hashcat mode numbers
HASH_MODES = {v: str(k) for k, v in HASH_MODES.items()}

def detect_hash_type(hash_value):
    """
    Uses hashid to detect possible hash types.
    """
    try:
        process = subprocess.run(["hashid", hash_value], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = process.stdout

        # Extract hash types from hashid output
        lines = output.splitlines()
        new = '\n'.join(lines[1:])  # Remove the first line (now stripped)

        if len(new.splitlines()) > 1:
            print("\n🔍 Analyzing the hash...\n")
            print("Possible hash types detected:")
            print(new)
            
            hash_modes = []
            for line in new.splitlines():
                # Extract the hash name (e.g., "SHA-256")
                hash_name = line.split(']')[-1].strip()
                # Map the hash name to its hashcat mode
                if hash_name in HASH_MODES:
                    hash_modes.append(HASH_MODES[hash_name])
                else:
                    print(f"⚠️ Hash type '{hash_name}' is not supported or mapped. Skipping...")

            return hash_modes
        else:
            print("\n❌ No hash type detected. Try again with a valid hash.")
            return []
    
    except Exception as e:
        print(f"Error detecting hash type: {e}")
        return []

def crack_hash(hash_value, wordlist, hash_modes):
    """
    Runs Hashcat with each detected hash type until one succeeds.
    """
    for hash_mode in hash_modes:
        print(f"\n🚀 Attempting to crack using mode {hash_mode}...")

        hashcat_cmd = [
            "hashcat", "-m", hash_mode, "-a", "0", "-w", "3", "--force",
            "--potfile-disable", hash_value, wordlist
        ]
        
        # Running hashcat with the user-provided hash
        process = subprocess.run(hashcat_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if process.returncode == 0:
            # If hashcat succeeds, show the cracked hash
            show_cmd = ["hashcat", "-m", hash_mode, "--show", hash_value]
            show_process = subprocess.run(show_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            if show_process.stdout.strip():
                print(f"✅ Success! Cracked Hash: {show_process.stdout.strip()}")
                return
            else:
                print(f"❌ Hash not cracked with mode {hash_mode}. Trying next...")
        else:
            print(f"❌ Failed with mode {hash_mode}. Trying next...")

    print("\n❌ Hash could not be cracked with the given wordlist.")

# User Inputs
wordlist_path = input("📂 Enter path to your wordlist: ").strip()
if not os.path.isfile(wordlist_path):
    print("❌ The specified wordlist file does not exist. Please check the path and try again.")
    exit(1)

user_hash = input("🔐 Enter the hash to crack: ").strip()

# Detect possible hash types
possible_modes = detect_hash_type(user_hash)

# Start cracking process
if possible_modes:
    crack_hash(user_hash, wordlist_path, possible_modes)
else:
    print("❌ No valid hash modes detected. Exiting.")
