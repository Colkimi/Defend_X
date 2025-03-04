# DEFEND_X

## Defend_X is a powerful cybersecurity tool designed for:

   +  Encryption & Decryption

   +  Hash Cracking

   +  Network Scanning

   +  Packet Sniffing

### 🛠️ Requirements
Before installing, ensure you have the following:

Python 3.x installed (python3 --version)

    "pip (Python package manager) installed (pip --version)"

The following dependencies:

    "Cryptography (for encryption)

    Hashid (for hash identification)

    Hashcat (for hash cracking)

    Nmap (for network scanning)

    Masscan (for high-speed scanning)

    Scapy (for packet sniffing)"

### 📥 Installation
Clone the Repository:

    git clone https://github.com/Colkimi/Defend_X
    cd Defend_X
### 🚀 Usage
#### Make the script executable:

     chmod +x defendx.py
#### Run Defend_X:
Method 1: Using Python

    python3 Defend_X.py
Method 2: Running Directly (Optional)
To run defendx without python3, move it to /usr/local/bin:

    sudo mv defendx.py /usr/local/bin/defendx
Now you can execute it with:

    Defend_X

## FEATURES
### 🔐 Encryption & Decryption

    ✔️ Generates encryption keys and allows loading existing keys for encryption or decryption.
  
    ✔️ Supports encryption and decryption for both text and files.
  
    ✔️ Supported encryption algorithms:
  
       > AES
       > 3DES
       > Blowfish
       > RSA
       > RC4
       > Fernet
       
### 🔓 Hash Cracking

    ✔️ Uses hashid to identify hash types.
    ✔️ Uses Hashcat to crack hashes.
    ✔️ Supports all hash modes available in hash_modes.py.
    
### 🌐 Network Scanning

     ✔️ Integrates Nmap and Masscan for efficient scanning.
     ✔️ Optimized for speed with timeouts to prevent delays.
     
### 📡 Packet Sniffing

    ✔️ Supports all protocol scanning, including TCP, UDP, and more.
    ✔️ Works with lo (loopback) and eth0 (Ethernet) interfaces.
