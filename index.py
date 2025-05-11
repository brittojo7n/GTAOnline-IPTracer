from scapy.all import sniff, IP, UDP
import requests
import pycountry
from colorama import init, Fore, Style
from ipaddress import ip_address, ip_network

init(autoreset=True)

gta_ports = {6672, 61455, 61456, 61457, 61458, 3022}
found_ips = set()

private_nets = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16")
]

rockstar_nets = [
    ip_network("192.81.240.0/22"),
    ip_network("104.255.104.0/22"),
    ip_network("185.43.108.0/22")
]

def is_excluded_ip(ip):
    ip_obj = ip_address(ip)
    return any(ip_obj in net for net in private_nets + rockstar_nets)

def get_country_name(code):
    try:
        country = pycountry.countries.get(alpha_2=code)
        return country.name if country else code
    except:
        return code

def get_ip_info(ip):
    ip_info = None

    try:
        res = requests.get(f"https://ipwho.is/{ip}", timeout=3)
        if res.status_code == 200:
            data = res.json()
            if data.get("success", False):
                country = data.get("country_code", "Unknown")
                if len(country) == 2:  
                    country = get_country_name(country)
                ip_info = {
                    "ip": ip,
                    "country": country,
                    "region": data.get("region", "Unknown"),
                    "isp": data.get("connection", {}).get("isp", "Unknown")
                }
    except Exception as e:
        pass  

    if not ip_info:
        try:
            res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
            if res.status_code == 200:
                data = res.json()
                if data.get("status") != "fail":
                    country = data.get("country", "Unknown")
                    if len(country) == 2: 
                        country = get_country_name(country)
                    ip_info = {
                        "ip": ip,
                        "country": country,
                        "region": data.get("regionName", "Unknown"),
                        "isp": data.get("isp", "Unknown")
                    }
        except Exception as e:
            pass 

    if not ip_info:
        try:
            res = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
            if res.status_code == 200:
                data = res.json()
                country = data.get("country", "Unknown")
                if len(country) == 2:
                    country = get_country_name(country)
                ip_info = {
                    "ip": ip,
                    "country": country,
                    "region": data.get("region", "Unknown"),
                    "isp": data.get("org", "Unknown")
                }
        except Exception as e:
            pass 

    if not ip_info:
        print(f"{Fore.RED}[-] Failed to get info for {ip}")
        ip_info = {
            "ip": ip,
            "country": "Unknown",
            "region": "Unknown",
            "isp": "Unknown"
        }

    return ip_info

def log_ip(ip):
    info = get_ip_info(ip)
    if any(keyword in info['isp'] for keyword in ["Microsoft", "Rockstar", "Take Two"]):
        return
    print_ip = f"{Fore.CYAN}{info['ip']}{Fore.YELLOW} {info['region']}, {info['country']} {Fore.MAGENTA}{info['isp']}"
    log_ip.counter += 1
    print(f"{Fore.GREEN}[{log_ip.counter}] {print_ip}{Style.RESET_ALL}")

def packet_callback(packet):
    if IP in packet and UDP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        sport = packet[UDP].sport
        dport = packet[UDP].dport

        for ip in [src, dst]:
            if not is_excluded_ip(ip) and (sport in gta_ports or dport in gta_ports):
                if ip not in found_ips:
                    found_ips.add(ip)
                    log_ip(ip)

log_ip.counter = 0
print(f"{Fore.GREEN}Listening for GTA Online player IPs...")
sniff(filter="udp", prn=packet_callback, store=0)
