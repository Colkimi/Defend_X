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
