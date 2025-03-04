import base64
import os
import time
from Crypto.Cipher import AES, DES3, Blowfish, PKCS1_OAEP
from Crypto.PublicKey import RSA, ECC
from Crypto.Util.Padding import pad, unpad
from Cryptodome.Cipher import ARC4
from cryptography.fernet import Fernet, InvalidToken

# Supported encryption methods
ENCRYPTION_METHODS = {
    "1": "AES",
    "2": "3DES",
    "3": "Blowfish",
    "4": "RSA",
    "5": "RC4",
    "6": "Fernet"
}

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

def main():
    while True:
        print("\n🔒 Choose an operation:")
        print("1. Encrypt Text")
        print("2. Decrypt Text")
        print("3. Encrypt File")
        print("4. Decrypt File")
        print("5. Exit")
        
        operation_choice = input("\nEnter operation number: ").strip()

        if operation_choice == "1":  # Encrypt Text
            text = input("\nEnter the text: ").strip()
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

        elif operation_choice == "2":  # Decrypt Text
            encrypted_text = input("\nEnter the encrypted text: ").strip()
            print("\nSelect a decryption method:")
            for key, method in ENCRYPTION_METHODS.items():
                print(f"{key}. {method}")
            method_choice = input("\nEnter method number: ").strip()
            method = ENCRYPTION_METHODS.get(method_choice)

            if not method:
                print("❌ Invalid decryption method selected!")
                continue

            # Load key for decryption
            if method in ["RSA"]:
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

        elif operation_choice == "3":  # Encrypt File
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
            if method in ["RSA"]:
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

        elif operation_choice == "4":  # Decrypt File
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
            if method in ["RSA"]:
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

        elif operation_choice == "5":
            print("Exiting... 🔚")
            break

        else:
            print("❌ Invalid operation choice! Please try again.")

if __name__ == "__main__":
    main()
