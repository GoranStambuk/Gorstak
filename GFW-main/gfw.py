import os
import subprocess
import requests
import sys
import time
from scapy.all import *

# Set a custom cache directory
cache_dir = os.path.join(os.getenv("TEMP"), "scapy_cache")
os.makedirs(cache_dir, exist_ok=True)
conf.cache_dir = cache_dir
print(f"Scapy cache directory set to: {cache_dir}")

# Function to check if Npcap is installed
def is_npcap_installed():
    try:
        # Check if Npcap's DLL exists
        npcap_path = os.path.join(os.environ["SystemRoot"], "System32", "npcap")
        return os.path.exists(npcap_path)
    except Exception:
        return False

# Function to download and install Npcap
def install_npcap():
    npcap_url = "https://npcap.com/dist/npcap-oem-1.75.exe"  # Replace with the latest OEM version URL
    npcap_installer = "npcap_installer.exe"

    print("Downloading Npcap OEM...")
    try:
        response = requests.get(npcap_url, stream=True)
        with open(npcap_installer, "wb") as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)
    except Exception as e:
        print(f"Failed to download Npcap: {e}")
        return False

    print("Installing Npcap OEM...")
    try:
        # Run the installer with the WinPcap compatibility switch
        command = [
            npcap_installer,
            "/S",  # Silent mode
            "/winpcap_mode=yes",  # Enable WinPcap compatibility mode
            "/loopback_support=no",  # Disable loopback support (optional)
        ]
        subprocess.run(command, check=True)
        print("Npcap installed successfully.")
        return True
    except Exception as e:
        print(f"Failed to install Npcap: {e}")
        return False
    finally:
        # Clean up the installer
        if os.path.exists(npcap_installer):
            os.remove(npcap_installer)

# Function to implement firewall rules using Scapy
def firewall_rules():
    print("Starting firewall rules...")

    # Rule 1: Deny all incoming connections except DHCP
    def deny_incoming_except_dhcp(packet):
        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            if packet.haslayer(UDP) and packet.getlayer(UDP).dport == 67:  # DHCP uses UDP port 67
                print(f"Allowing DHCP packet: {ip_layer.src} -> {ip_layer.dst}")
                return
            print(f"Blocking incoming packet: {ip_layer.src} -> {ip_layer.dst}")
            return "Block"

    # Rule 2: Deny all outgoing traffic not belonging to the current user
    def deny_outgoing_not_console_logon(packet):
        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            # Simulate checking the process owner (this is a placeholder)
            print(f"Checking outgoing packet: {ip_layer.src} -> {ip_layer.dst}")
            # Add logic to check the process owner here
            return "Block"

    # Sniff network traffic and apply rules
    sniff(prn=lambda x: deny_incoming_except_dhcp(x) or deny_outgoing_not_console_logon(x), store=0)

# Main function
def main():
    if not is_npcap_installed():
        print("Npcap is not installed.")
        if install_npcap():
            print("Npcap installed successfully. Please restart the script.")
            sys.exit(0)
        else:
            print("Failed to install Npcap. Exiting.")
            sys.exit(1)
    else:
        print("Npcap is already installed.")

    # Start the firewall rules
    firewall_rules()

if __name__ == "__main__":
    main()