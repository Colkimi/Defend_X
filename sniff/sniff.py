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
        
packet_sniffing_menu()
