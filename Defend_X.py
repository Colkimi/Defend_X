import base64
import os
import time
import nmap
from colorama import Fore, Style, init
from Crypto.Cipher import AES, DES3, Blowfish, PKCS1_OAEP, ARC4
from Crypto.PublicKey import RSA, ECC
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.fernet import Fernet, InvalidToken
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, get_if_list
import subprocess
import threading
from hash_modes import HASH_MODES

# Supported encryption methods
ENCRYPTION_METHODS = {
    "1": "AES",
    "2": "3DES",
    "3": "Blowfish",
    "4": "RSA",
    "5": "RC4",
    "6": "Fernet"
}

HASH_MODES = {v: str(k) for k, v in HASH_MODES.items()}

# Print Welcome Banner
def print_welcome_banner():
    banner = r"""

    ██████╗ ███████╗███████╗███████╗███╗   ██╗██████╗ ██╗  ██╗                             
    ██╔══██╗██╔════╝██╔════╝██╔════╝████╗  ██║██╔══██╗╚██╗██╔╝                             
    ██║  ██║█████╗  █████╗  █████╗  ██╔██╗ ██║██║  ██║ ╚███╔╝                              
    ██║  ██║██╔══╝  ██╔══╝  ██╔══╝  ██║╚██╗██║██║  ██║ ██╔██╗                              
    ██████╔╝███████╗██║     ███████╗██║ ╚████║██████╔╝██╔╝ ██╗                             
    ╚═════╝ ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝

    """
    
    subtitle = "🚀 Scan and Exploit Faster 🚀"
    author = "🔎 By Colkimi 🔎"

    print(Fore.CYAN + banner + Style.RESET_ALL)
    print(Fore.RED + subtitle.center(60) + Style.RESET_ALL)
    print(Fore.YELLOW + author.center(60) + Style.RESET_ALL)

# Function to simulate a loading animation
def loading_animation(message="Loading", duration=2):
    print(f"\n{message}", end="", flush=True)
    for _ in range(duration * 2):
        time.sleep(0.5)
        print(".", end="", flush=True)
    print()


# Function to simulate a loading animation
def loading_animation(message="Loading", duration=2):
    print(f"\n{message}", end="", flush=True)
    for _ in range(duration * 2):
        time.sleep(0.5)
        print(".", end="", flush=True)
    print()

# Encryption function
def encrypt_text(text, key, method):
    try:
        if method == "AES":
            cipher = AES.new(key, AES.MODE_ECB)
            encrypted_text = base64.b64encode(cipher.encrypt(pad(text.encode(), 16))).decode()
        elif method == "3DES":
            cipher = DES3.new(key, DES3.MODE_ECB)
            encrypted_text = base64.b64encode(cipher.encrypt(pad(text.encode(), 16))).decode()
        elif method == "Blowfish":
            cipher = Blowfish.new(key, Blowfish.MODE_ECB)
            encrypted_text = base64.b64encode(cipher.encrypt(pad(text.encode(), 16))).decode()
        elif method == "RSA":
            cipher = PKCS1_OAEP.new(RSA.import_key(key))
            encrypted_text = base64.b64encode(cipher.encrypt(text.encode())).decode()
        elif method == "RC4":
            cipher = ARC4.new(key)
            encrypted_text = base64.b64encode(cipher.encrypt(text.encode())).decode()
        elif method == "Fernet":
            cipher = Fernet(key)
            encrypted_text = cipher.encrypt(text.encode()).decode()
        else:
            encrypted_text = "Encryption method not implemented."
        return encrypted_text
    except Exception as e:
        return f"❌ Encryption failed: {str(e)}"

# Decryption function
def decrypt_text(encrypted_text, key, method):
    try:
        encrypted_text = base64.b64decode(encrypted_text.encode())
        if method == "AES":
            cipher = AES.new(key, AES.MODE_ECB)
            decrypted_text = unpad(cipher.decrypt(encrypted_text), 16).decode()
        elif method == "3DES":
            cipher = DES3.new(key, DES3.MODE_ECB)
            decrypted_text = unpad(cipher.decrypt(encrypted_text), 16).decode()
        elif method == "Blowfish":
            cipher = Blowfish.new(key, Blowfish.MODE_ECB)
            decrypted_text = unpad(cipher.decrypt(encrypted_text), 16).decode()
        elif method == "RSA":
            cipher = PKCS1_OAEP.new(RSA.import_key(key))
            decrypted_text = cipher.decrypt(encrypted_text).decode()
        elif method == "RC4":
            cipher = ARC4.new(key)
            decrypted_text = cipher.decrypt(encrypted_text).decode()
        elif method == "Fernet":
            cipher = Fernet(key)
            decrypted_text = cipher.decrypt(encrypted_text).decode()
        else:
            decrypted_text = "Decryption method not implemented."
        return decrypted_text
    except InvalidToken:
        return "❌ Decryption failed: Invalid key or token."
    except Exception as e:
        return f"❌ Decryption failed: {str(e)}"

# Function to encrypt a file
def encrypt_file(file_path, key, method):
    try:
        if not os.path.isfile(file_path):
            print("❌ Error: File not found!")
            return

        with open(file_path, 'rb') as file:
            file_data = file.read()
        encrypted_data = encrypt_text(file_data.decode('latin1'), key, method)
        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, 'wb') as file:
            file.write(encrypted_data.encode('latin1'))
        print(f"🔐 File encrypted and saved as {encrypted_file_path}")
    except Exception as e:
        print(f"❌ File encryption failed: {str(e)}")

# Function to decrypt a file
def decrypt_file(file_path, key, method):
    try:
        if not os.path.isfile(file_path):
            print("❌ Error: File not found!")
            return

        with open(file_path, 'rb') as file:
            encrypted_data = file.read()
        decrypted_data = decrypt_text(encrypted_data.decode('latin1'), key, method)
        decrypted_file_path = file_path.replace(".enc", "")
        with open(decrypted_file_path, 'wb') as file:
            file.write(decrypted_data.encode('latin1'))
        print(f"🔓 File decrypted and saved as {decrypted_file_path}")
    except Exception as e:
        print(f"❌ File decryption failed: {str(e)}")
# Function to generate and save keys for asymmetric encryption
def generate_asymmetric_keys(method):
    try:
        if method == "RSA":
            key = RSA.generate(2048)
            private_key = key.export_key()
            public_key = key.publickey().export_key()
        else:
            return None, None

        # Save keys to files
        with open("private_key.pem", "wb") as priv_file:
            priv_file.write(private_key)
        with open("public_key.pem", "wb") as pub_file:
            pub_file.write(public_key)

        print("\n🔑 Private key saved as 'private_key.pem'")
        print("🔑 Public key saved as 'public_key.pem'")
        return public_key, private_key
    except Exception as e:
        print(f"❌ Error generating asymmetric keys: {str(e)}")
        return None, None

# Generate and save symmetric keys
def generate_symmetric_key(method):
    try:
        if method == "AES":
            key = os.urandom(16)  # 16-byte key
        elif method == "3DES":
            key = os.urandom(24)  # 24-byte key
        elif method == "Blowfish":
            key = os.urandom(16)  # Blowfish key
        elif method == "RC4":
            key = os.urandom(16)  # RC4 key
        elif method == "Fernet":
            key = Fernet.generate_key()
        else:
            return None

        # Save key to a file
        with open("symmetric_key.key", "wb") as key_file:
            key_file.write(key)

        print("\n🔑 Symmetric key saved as 'symmetric_key.key'.")
        return key
    except Exception as e:
        print(f"❌ Error generating symmetric key: {str(e)}")
        return None

# Function to load a key from a file
def load_key(key_type):
    while True:
        key_path = input(f"\nEnter the path to the {key_type} key file: ").strip()
        if not os.path.isfile(key_path):
            print("❌ Error: File not found! Please enter a valid file path.")
            continue
        try:
            with open(key_path, "rb") as key_file:
                key = key_file.read()
            print(f"🔑 {key_type.capitalize()} key loaded successfully.")
            return key
        except Exception as e:
            print(f"❌ Error loading key: {str(e)}")
            return None

# Encryption/Decryption Functions
def encryption_decryption_menu():
    while True:
        print("\n🔒 Encryption/Decryption Menu:")
        print("1. Encrypt Text")
        print("2. Decrypt Text")
        print("3. Encrypt File")
        print("4. Decrypt File")
        print("5. Back to Main Menu")
        
        choice = input("\nEnter your choice: ").strip()

        if choice == "1":  # Encrypt Text
            text = input("\nEnter the text: ").strip()
            if not text:
                print("❌ Error: Text cannot be empty!")
                continue

            print("\nSelect an encryption method:")
            for key, method in ENCRYPTION_METHODS.items():
                print(f"{key}. {method}")
            method_choice = input("\nEnter method number: ").strip()
            method = ENCRYPTION_METHODS.get(method_choice)

            if not method:
                print("❌ Invalid encryption method selected!")
                continue

            # Generate key for encryption
            loading_animation("Generating key")
            try:
                if method in ["RSA", "ECC"]:
                    public_key, _ = generate_asymmetric_keys(method)
                    if not public_key:
                        continue
                    key = public_key
                else:
                    key = generate_symmetric_key(method)
                    if not key:
                        continue

                # Encrypt the text
                loading_animation("Encrypting")
                encrypted_text = encrypt_text(text, key, method)
                print("\n🔐 Encrypted Text:", encrypted_text)
            except Exception as e:
                print(f"❌ Error during encryption: {e}")

        elif choice == "2":  # Decrypt Text
            encrypted_text = input("\nEnter the encrypted text: ").strip()
            if not encrypted_text:
                print("❌ Error: Encrypted text cannot be empty!")
                continue

            print("\nSelect a decryption method:")
            for key, method in ENCRYPTION_METHODS.items():
                print(f"{key}. {method}")
            method_choice = input("\nEnter method number: ").strip()
            method = ENCRYPTION_METHODS.get(method_choice)

            if not method:
                print("❌ Invalid decryption method selected!")
                continue

            # Load key for decryption
            try:
                if method in ["RSA", "ECC"]:
                    key = load_key("private key")
                    if not key:
                        continue
                else:
                    key = load_key("symmetric key")
                    if not key:
                        continue

                # Decrypt the text
                loading_animation("Decrypting")
                decrypted_text = decrypt_text(encrypted_text, key, method)
                print("\n🔓 Decrypted Text:", decrypted_text)
            except Exception as e:
                print(f"❌ Error during decryption: {e}")

        elif choice == "3":  # Encrypt File
            file_path = input("\nEnter the file path: ").strip()
            if not os.path.isfile(file_path):
                print("❌ Error: File not found!")
                continue

            print("\nSelect an encryption method:")
            for key, method in ENCRYPTION_METHODS.items():
                print(f"{key}. {method}")
            method_choice = input("\nEnter method number: ").strip()
            method = ENCRYPTION_METHODS.get(method_choice)

            if not method:
                print("❌ Invalid encryption method selected!")
                continue

            # Generate key for encryption
            loading_animation("Generating key")
            try:
                if method in ["RSA", "ECC"]:
                    public_key, _ = generate_asymmetric_keys(method)
                    if not public_key:
                        continue
                    key = public_key
                else:
                    key = generate_symmetric_key(method)
                    if not key:
                        continue

                # Encrypt the file
                loading_animation("Encrypting file")
                encrypt_file(file_path, key, method)
            except Exception as e:
                print(f"❌ Error during file encryption: {e}")

        elif choice == "4":  # Decrypt File
            file_path = input("\nEnter the file path: ").strip()
            if not os.path.isfile(file_path):
                print("❌ Error: File not found!")
                continue

            print("\nSelect a decryption method:")
            for key, method in ENCRYPTION_METHODS.items():
                print(f"{key}. {method}")
            method_choice = input("\nEnter method number: ").strip()
            method = ENCRYPTION_METHODS.get(method_choice)

            if not method:
                print("❌ Invalid decryption method selected!")
                continue

            # Load key for decryption
            try:
                if method in ["RSA", "ECC"]:
                    key = load_key("private key")
                    if not key:
                        continue
                else:
                    key = load_key("symmetric key")
                    if not key:
                        continue

                # Decrypt the file
                loading_animation("Decrypting file")
                decrypt_file(file_path, key, method)
            except Exception as e:
                print(f"❌ Error during file decryption: {e}")

        elif choice == "5":
            break

        else:
            print("❌ Invalid choice! Please try again.")

# Hash Cracking Functions
def hash_cracking_menu():
    while True:
        print("\n🔐 Hash Cracking Menu:")
        print("1. Detect Hash Type")
        print("2. Crack Hash")
        print("3. Back to Main Menu")
        
        choice = input("\nEnter your choice: ").strip()

        if choice == "1":  # Detect Hash Type
            user_hash = input("\n🔐 Enter the hash to detect: ").strip()
            if not user_hash:
                print("❌ Error: Hash cannot be empty!")
                continue

            try:
                possible_modes = detect_hash_type(user_hash)
                if possible_modes:
                    print("\n✅ Possible hash types detected:")
                    for mode in possible_modes:
                        print(f"- {mode}")
                else:
                    print("❌ No valid hash modes detected.")
            except Exception as e:
                print(f"❌ Error detecting hash type: {e}")

        elif choice == "2":  # Crack Hash
            wordlist_path = input("\n📂 Enter path to your wordlist: ").strip()
            if not os.path.isfile(wordlist_path):
                print("❌ The specified wordlist file does not exist. Please check the path and try again.")
                continue

            user_hash = input("\n🔐 Enter the hash to crack: ").strip()
            if not user_hash:
                print("❌ Error: Hash cannot be empty!")
                continue

            try:
                possible_modes = detect_hash_type(user_hash)
                if possible_modes:
                    crack_hash(user_hash, wordlist_path, possible_modes)
                else:
                    print("❌ No valid hash modes detected.")
            except Exception as e:
                print(f"❌ Error cracking hash: {e}")

        elif choice == "3":
            break

        else:
            print("❌ Invalid choice! Please try again.")

# Network Scanning Functions
def network_scanning_menu():
    while True:
        print("\n🌐 Network Scanning Menu:")
        print("1. Masscan")
        print("2. Nmap")
        print("3. Back to Main Menu")
        
        choice = input("\nEnter your choice: ").strip()

        if choice == "1":  # Masscan
            target_ip = input("\nEnter target IP: ").strip()
            port_range = input("Enter port range to scan (e.g., 1-1024): ").strip()
            try:
                start_port, end_port = map(int, port_range.split('-'))
                if start_port < 1 or end_port > 65535 or start_port > end_port:
                    raise ValueError("Invalid port range.")
            except ValueError as e:
                print(f"⚠️ Error: {e}")
                continue

            threads = input("Enter number of threads (recommended: 10-50): ").strip()
            try:
                threads = int(threads)
                if threads < 1:
                    raise ValueError("Number of threads must be at least 1.")
            except ValueError as e:
                print(f"⚠️ Error: {e}")
                continue

            try:
                scan_with_masscan(target_ip, range(start_port, end_port + 1), threads * 100)
            except Exception as e:
                print(f"❌ Error during Masscan: {e}")

        elif choice == "2":  # Nmap
            target_ip = input("\nEnter target IP: ").strip()
            port_range = input("Enter port range to scan (e.g., 1-1024): ").strip()
            try:
                start_port, end_port = map(int, port_range.split('-'))
                if start_port < 1 or end_port > 65535 or start_port > end_port:
                    raise ValueError("Invalid port range.")
            except ValueError as e:
                print(f"⚠️ Error: {e}")
                continue

            threads = input("Enter number of threads (recommended: 10-50): ").strip()
            try:
                threads = int(threads)
                if threads < 1:
                    raise ValueError("Number of threads must be at least 1.")
            except ValueError as e:
                print(f"⚠️ Error: {e}")
                continue

            try:
                open_ports = scan_with_nmap(target_ip, range(start_port, end_port + 1), threads)
                print(f"\n✅ Open ports found: {open_ports}\n")
            except Exception as e:
                print(f"❌ Error during Nmap scan: {e}")

        elif choice == "3":
            break

        else:
            print("❌ Invalid choice! Please try again.")

# Packet Sniffing Functions
def packet_sniffing_menu():
    while True:
        print("\n📡 Packet Sniffing Menu:")
        print("1. Sniff Packets (All Protocols)")
        print("2. Sniff TCP Packets")
        print("3. Sniff UDP Packets")
        print("4. Sniff ICMP Packets")
        print("5. Save Captured Packets to File")
        print("6. Back to Main Menu")
        
        choice = input("\nEnter your choice: ").strip()

        if choice == "1":  # Sniff All Protocols
            print("\nAvailable Network Interfaces:", get_if_list())
            interface = input("Enter interface for packet sniffing: ").strip()
            packet_count = input("Enter number of packets to capture (default: 10): ").strip() or "10"
            try:
                packet_count = int(packet_count)
                sniff_packets(interface, packet_count, filter=None)
            except ValueError:
                print("❌ Invalid packet count! Please enter a number.")
            except Exception as e:
                print(f"❌ Error during packet sniffing: {e}")

        elif choice == "2":  # Sniff TCP Packets
            print("\nAvailable Network Interfaces:", get_if_list())
            interface = input("Enter interface for packet sniffing: ").strip()
            packet_count = input("Enter number of packets to capture (default: 10): ").strip() or "10"
            try:
                packet_count = int(packet_count)
                sniff_packets(interface, packet_count, filter="tcp")
            except ValueError:
                print("❌ Invalid packet count! Please enter a number.")
            except Exception as e:
                print(f"❌ Error during packet sniffing: {e}")

        elif choice == "3":  # Sniff UDP Packets
            print("\nAvailable Network Interfaces:", get_if_list())
            interface = input("Enter interface for packet sniffing: ").strip()
            packet_count = input("Enter number of packets to capture (default: 10): ").strip() or "10"
            try:
                packet_count = int(packet_count)
                sniff_packets(interface, packet_count, filter="udp")
            except ValueError:
                print("❌ Invalid packet count! Please enter a number.")
            except Exception as e:
                print(f"❌ Error during packet sniffing: {e}")

        elif choice == "4":  # Sniff ICMP Packets
            print("\nAvailable Network Interfaces:", get_if_list())
            interface = input("Enter interface for packet sniffing: ").strip()
            packet_count = input("Enter number of packets to capture (default: 10): ").strip() or "10"
            try:
                packet_count = int(packet_count)
                sniff_packets(interface, packet_count, filter="icmp")
            except ValueError:
                print("❌ Invalid packet count! Please enter a number.")
            except Exception as e:
                print(f"❌ Error during packet sniffing: {e}")

        elif choice == "5":  # Save Captured Packets to File
            file_path = input("\nEnter file path to save captured packets (e.g., packets.txt): ").strip()
            if not file_path:
                print("❌ Error: File path cannot be empty!")
                continue
            try:
                save_captured_packets(file_path)
                print(f"✅ Captured packets saved to {file_path}")
            except Exception as e:
                print(f"❌ Error saving packets: {e}")

        elif choice == "6":
            break

        else:
            print("❌ Invalid choice! Please try again.")

# Function to sniff packets
def sniff_packets(interface, packet_count, filter=None):
    try:
        print(f"\n📡 Sniffing {packet_count} packets on {interface}...\n")
        packets = sniff(iface=interface, count=packet_count, filter=filter, prn=process_packet)
        print(f"\n✅ Captured {len(packets)} packets.")
    except Exception as e:
        print(f"❌ Error during packet sniffing: {e}")

# Function to process and display packet details
def process_packet(packet):
    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto

            print(f"\n{Fore.CYAN}Packet Details:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Source IP:{Style.RESET_ALL} {src_ip}")
            print(f"{Fore.GREEN}Destination IP:{Style.RESET_ALL} {dst_ip}")
            print(f"{Fore.GREEN}Protocol:{Style.RESET_ALL} {protocol}")

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                print(f"{Fore.YELLOW}Source Port:{Style.RESET_ALL} {src_port}")
                print(f"{Fore.YELLOW}Destination Port:{Style.RESET_ALL} {dst_port}")
                if Raw in packet:
                    payload = packet[Raw].load
                    print(f"{Fore.RED}Payload:{Style.RESET_ALL} {payload}")

            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                print(f"{Fore.YELLOW}Source Port:{Style.RESET_ALL} {src_port}")
                print(f"{Fore.YELLOW}Destination Port:{Style.RESET_ALL} {dst_port}")
                if Raw in packet:
                    payload = packet[Raw].load
                    print(f"{Fore.RED}Payload:{Style.RESET_ALL} {payload}")

            elif ICMP in packet:
                print(f"{Fore.YELLOW}ICMP Type:{Style.RESET_ALL} {packet[ICMP].type}")
                print(f"{Fore.YELLOW}ICMP Code:{Style.RESET_ALL} {packet[ICMP].code}")

            print(f"{Fore.BLUE}Packet Size:{Style.RESET_ALL} {len(packet)} bytes")
            print("-" * 50)
    except Exception as e:
        print(f"❌ Error processing packet: {e}")

# Function to save captured packets to a file
def save_captured_packets(file_path):
    try:
        with open(file_path, "w") as file:
            packets = sniff(count=10, prn=lambda packet: file.write(str(packet) + "\n"))
        print(f"✅ Saved {len(packets)} packets to {file_path}")
    except Exception as e:
        print(f"❌ Error saving packets: {e}")

# Main Function
# Calls all functions
def main():
    init(autoreset=True)
    print_welcome_banner()
    
    while True:
        print("\n🔥 Main Menu:")
        print("1. Encryption/Decryption")
        print("2. Hash Cracking")
        print("3. Network Scanning")
        print("4. Packet Sniffing")
        print("5. Exit")
        
        choice = input("\nEnter your choice: ").strip()

        if choice == "1":
            encryption_decryption_menu()
            #call the encryption function
        elif choice == "2":
            hash_cracking_menu()
            #call the hash function
        elif choice == "3":
            network_scanning_menu()
            #call the network scan function
        elif choice == "4":
            packet_sniffing_menu()
            #call the packet sniffer
        elif choice == "5":
            print("Exiting... 🔚")
            break
        else:
            print("❌ Invalid choice! Please try again.")

if __name__ == "__main__":
    main()

    #Indentation is so important in python ensure you adhere to thhat to avoid errors
