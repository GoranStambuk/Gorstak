import os
import subprocess
import requests
import sys
import time
import re
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, DNSRR, conf  # Import conf here

# Set a custom cache directory
cache_dir = os.path.join(os.getenv("TEMP"), "scapy_cache")
os.makedirs(cache_dir, exist_ok=True)
conf.cache_dir = cache_dir  # Now conf is defined
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

# URLs to fetch filter lists (EasyList, EasyPrivacy, and uBlock filters)
FILTER_LIST_URLS = [
    "https://easylist.to/easylist/easylist.txt",
    "https://easylist.to/easylist/easyprivacy.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt",
]

# Combined regex pattern to block 99% of ads
AD_REGEX_PATTERN = re.compile(
    r"^(.+[-_.])?(ad[sxv]?|teads?|doubleclick|adservice|adtrack(er|ing)?|advertising|adnxs|admeld|advert|adx(addy|pose|pr[io])?|adform|admulti|adbutler|adblade|adroll|adgr[ao]|adinterax|admarvel|admed(ia|ix)|adperium|adplugg|adserver|adsolut|adtegr(it|ity)|adtraxx|advertising|aff(iliat(es?|ion))|akamaihd|amazon-adsystem|appnexus|appsflyer|audience2media|bingads|bidswitch|brightcove|casalemedia|contextweb|criteo|doubleclick|emxdgt|e-planning|exelator|eyewonder|flashtalking|goog(le(syndication|tagservices))|gunggo|hurra(h|ynet)|imrworldwide|insightexpressai|kontera|lifestreetmedia|lkntracker|mediaplex|ooyala|openx|pixel(e|junky)|popcash|propellerads|pubmatic|quantserve|revcontent|revenuehits|sharethrough|skimresources|taboola|traktrafficx|twitter[.]com|undertone|yieldmo)",
    re.IGNORECASE
)

# YouTube-specific rules from uBlock Origin
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
    """Load filter lists from URLs."""
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
    """Check if a domain is an ad domain."""
    # Check against regex pattern
    if AD_REGEX_PATTERN.search(domain):
        return True
    # Check against YouTube-specific filters
    for rule in YOUTUBE_FILTERS:
        if re.match(rule.replace("*", ".*"), domain):
            return True
    # Check against filter lists
    if domain in blocked_domains:
        return True
    return False

def packet_callback(packet):
    """Callback function to process packets."""
    if IP in packet:
        # Check DNS queries for ad domains
        if DNS in packet and DNSQR in packet:
            domain = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            if is_ad_domain(domain):
                print(f"Blocked DNS query for ad domain: {domain}")
                return  # Drop the packet
        # Check HTTP/HTTPS requests for ad domains
        if TCP in packet and packet[TCP].dport in [80, 443]:
            host = packet[IP].dst
            if is_ad_domain(host):
                print(f"Blocked HTTP/HTTPS request to ad domain: {host}")
                return  # Drop the packet

def run_packet_filter():
    """Start packet filtering."""
    print("Starting packet filtering...")
    sniff(prn=packet_callback, store=False)

def main():
    """Main function to run the ad-blocking packet filter."""
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

    # Load filter lists
    load_filter_lists()

    # Start packet filtering
    run_packet_filter()

if __name__ == "__main__":
    main()