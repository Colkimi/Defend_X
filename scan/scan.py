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

            scan_with_masscan(target_ip, range(start_port, end_port + 1), threads * 100)

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

            open_ports = scan_with_nmap(target_ip, range(start_port, end_port + 1), threads)
            print(f"\n✅ Open ports found: {open_ports}\n")

        elif choice == "3":
            break

        else:
            print("❌ Invalid choice! Please try again.")
