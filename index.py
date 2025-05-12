import os
from datetime import datetime
from scapy.all import sniff, IP, UDP
import requests
import pycountry
from colorama import init, Fore, Style
from ipaddress import ip_address, ip_network

init(autoreset=True)

GTA_PORTS = {6672, 61455, 61456, 61457, 61458, 3022}
FOUND_IPS = set()

PRIVATE_NETS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16")
]

ROCKSTAR_NETS = [
    ip_network("192.81.240.0/22"),
    ip_network("104.255.104.0/22"),
    ip_network("185.43.108.0/22")
]

LOG_DIR = "GTAO_IP_Logs"
os.makedirs(LOG_DIR, exist_ok=True)
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
LOG_FILE = os.path.join(LOG_DIR, f"LOG_{timestamp}.txt")

def is_excluded_ip(ip):
    ip_obj = ip_address(ip)
    return any(ip_obj in net for net in PRIVATE_NETS + ROCKSTAR_NETS)

def get_country_name(code):
    country = pycountry.countries.get(alpha_2=code)
    return country.name if country else code

def get_ip_info(ip):
    def fetch_info(url, country_key, isp_key):
        try:
            res = requests.get(url, timeout=3)
            if res.status_code == 200:
                data = res.json()
                country = data.get(country_key, "Unknown")
                if len(country) == 2:
                    country = get_country_name(country)
                return {
                    "ip": ip,
                    "country": country,
                    "region": data.get("region", "Unknown"),
                    "isp": data.get(isp_key[0], {}).get(isp_key[1], "Unknown") if isinstance(isp_key, tuple)
                          else data.get(isp_key, "Unknown")
                }
        except:
            pass
        return None

    info = fetch_info(f"https://ipwho.is/{ip}", "country", ("connection", "isp")) \
        or fetch_info(f"https://ipinfo.io/{ip}/json", "country", "org")

    if not info:
        print(f"{Fore.RED}[-] Failed to get info for {ip}")
        return {"ip": ip, "country": "Unknown", "region": "Unknown", "isp": "Unknown"}

    return info

def log_ip(ip):
    info = get_ip_info(ip)
    if any(x in info["isp"] for x in ["Microsoft", "Rockstar", "Take Two"]):
        return

    line = (f"IP: {info['ip']} "
            f"Region: {info['region']} "
            f"Country: {info['country']} "
            f"ISP: {info['isp']}")

    print(f"{Fore.GREEN}[{log_ip.counter}] {Fore.LIGHTMAGENTA_EX}IP: {Fore.LIGHTRED_EX}{info['ip']} {Fore.LIGHTMAGENTA_EX}Region: {Fore.LIGHTCYAN_EX}{info['region']} {Fore.LIGHTMAGENTA_EX}Country: {Fore.LIGHTYELLOW_EX}{info['country']} {Fore.LIGHTMAGENTA_EX}ISP: {Fore.WHITE}{info['isp']}")

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")

    log_ip.counter += 1

def packet_callback(packet):
    if IP in packet and UDP in packet:
        for ip in [packet[IP].src, packet[IP].dst]:
            if not is_excluded_ip(ip) and (
                packet[UDP].sport in GTA_PORTS or packet[UDP].dport in GTA_PORTS
            ):
                if ip not in FOUND_IPS:
                    FOUND_IPS.add(ip)
                    log_ip(ip)

log_ip.counter = 1
print(f"{Style.RESET_ALL}Tracing GTA Online player IPs...\nLogs will be saved to: {Fore.LIGHTBLUE_EX}{LOG_FILE}")
sniff(filter="udp", prn=packet_callback, store=0)
