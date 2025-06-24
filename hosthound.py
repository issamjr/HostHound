#!/usr/bin/env python3
import socket
import ipaddress
import argparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore
from time import time

init(autoreset=True)

ASCII_BANNER = f"""{Fore.RED}
██╗  ██╗ ██████╗ ███████╗████████╗██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗ 
██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗
███████║██║   ██║███████╗   ██║   ███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║
██╔══██║██║   ██║╚════██║   ██║   ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║
██║  ██║╚██████╔╝███████║   ██║   ██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝
╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ 
{Fore.YELLOW}  🐾 Advanced Shared Host Scanner Tool
{Fore.MAGENTA}  💀 HostHound v1.0 - Unleash the Network Secrets
{Fore.CYAN}  👨‍💻 code by issam junior
"""
def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        print(f"{Fore.RED}[!] Failed to resolve domain: {domain}")
        return None

def reverse_lookup(ip, timeout):
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip)
        if hostname:
            try:
                confirmed_ip = socket.gethostbyname(hostname)
                if ip == confirmed_ip:
                    try:
                        response = requests.head(f"http://{hostname}", timeout=timeout)
                        if response.status_code < 400:
                            return hostname
                    except requests.RequestException:
                        pass
                    return hostname
            except:
                return hostname
    except:
        pass
    return None

def is_port_open(domain, port=80, timeout=2):
    try:
        with socket.create_connection((domain, port), timeout=timeout):
            return True
    except:
        return False

def generate_ip_range(base_ip):
    net = ipaddress.ip_network(f"{base_ip}/24", strict=False)
    return [str(ip) for ip in net.hosts()]

def scan_network(ip_list, timeout, max_threads):
    found_domains = []
    with ThreadPoolExecutor(max_threads) as executor:
        futures = {executor.submit(reverse_lookup, ip, timeout): ip for ip in ip_list}
        for future in as_completed(futures):
            domain = future.result()
            ip = futures[future]  # نحصل على الـ IP المقابل للدومين
            if domain:
                port80 = is_port_open(domain, port=80, timeout=timeout)
                status_msg = f"{Fore.GREEN}[port 80 open]" if port80 else f"{Fore.RED}[port 80 closed]"
                print(f"{Fore.CYAN}[+] Found domain: {Fore.YELLOW}{domain} {status_msg} {Fore.MAGENTA}(IP: {ip})")
                found_domains.append(f"{domain} {status_msg} (IP: {ip})")
    return found_domains

def main():
    parser = argparse.ArgumentParser(description="HostHound: Find shared hosts on a /24 subnet")
    parser.add_argument("domain", help="Target domain name")
    parser.add_argument("--timeout", type=int, default=2, help="Network timeout (seconds)")
    parser.add_argument("--threads", type=int, default=20, help="Max threads for scanning")
    parser.add_argument("--save", action="store_true", help="Save results to results.txt")

    args = parser.parse_args()

    print(ASCII_BANNER)

    ip = resolve_domain(args.domain)
    if not ip:
        return

    print(f"{Fore.GREEN}[INFO] Resolved {args.domain} to {ip}")
    ip_list = generate_ip_range(ip)
    print(f"{Fore.GREEN}[INFO] Scanning {len(ip_list)} hosts in subnet {ip}/24...")

    start = time()
    domains = scan_network(ip_list, args.timeout, args.threads)
    duration = time() - start

    print(f"\n{Fore.YELLOW}[✓] Scan complete: {len(domains)} domain(s) found in {duration:.2f} seconds.")

    if args.save:
        with open("results.txt", "w") as f:
            for d in domains:
                f.write(f"{d}\n")
        print(f"{Fore.GREEN}[+] Results saved to results.txt")

if __name__ == "__main__":
    main()

