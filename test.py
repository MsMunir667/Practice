#!/usr/bin/env python3
import argparse
import asyncio
import aiohttp
import socket
import json
import os
import re
import ssl
import dns.resolver
import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from urllib.parse import quote
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)
ssl._create_default_https_context = ssl._create_unverified_context

BANNER = f"""{Fore.CYAN}
   ____  __  ______     __  __           _       _____ _____
  / __ \\/ / / / __ \\   / / / /___ ______(_)___  / ___// ___/
 / / / / / / / / / /  / /_/ / __ `/ ___/ / __ \\\\__ \\\\ \\__ \\
/ /_/ / /_/ / /_/ /  / __  / /_/ (__  ) / /_/ /__/ /___/ /
\\___\\_\\\\____/\\____/  /_/ /_/\\__,_/____/_/ .___/____/____/
                                      /_/ {Style.RESET_ALL}
{Fore.YELLOW}        ⚡ Origin IP Finder v4 (0xmun1r) ⚡{Style.RESET_ALL}
"""

CONFIG_FILE = "config.json"

# Known CDN IP ranges for filtering - simplified examples
KNOWN_CDN_ASNS = {
    'Cloudflare': [13335],
    'Akamai': [16625],
    'Fastly': [54113],
    'Imperva': [14618, 44351],
    'Amazon CloudFront': [16509],
    'Google': [15169]
}

def load_config():
    if os.path.isfile(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            try:
                return json.load(f)
            except Exception:
                return {}
    return {}

def is_cdn_ip(ip):
    # Quick ASN check using ipinfo.io (public API, no key required but limited)
    try:
        resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            org = data.get("org", "")
            for cdn, asns in KNOWN_CDN_ASNS.items():
                for asn in asns:
                    if f"AS{asn}" in org:
                        return True, cdn
    except:
        return False, None
    return False, None

def print_waf_status(domain, silent):
    if silent:
        return
    try:
        r = requests.get(f"https://{domain}", timeout=10, verify=False)
        server = r.headers.get('Server', '').lower()
        waf = None
        if 'cloudflare' in server:
            waf = "Cloudflare"
        elif 'akamai' in server:
            waf = "Akamai"
        elif 'sucuri' in server:
            waf = "Sucuri"
        elif 'incapsula' in server:
            waf = "Imperva Incapsula"

        if waf:
            print(f"{Fore.RED}[WAF Detected] {waf}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[WAF Detection] No WAF detected{Style.RESET_ALL}")
    except Exception:
        print(f"{Fore.YELLOW}[WAF Detection] Unknown{Style.RESET_ALL}")

async def fetch_json(session, url, headers=None):
    try:
        async with session.get(url, headers=headers, timeout=20) as resp:
            if resp.status == 200:
                return await resp.json(content_type=None)
    except:
        return None

async def fetch_text(session, url, headers=None):
    try:
        async with session.get(url, headers=headers, timeout=20) as resp:
            if resp.status == 200:
                return await resp.text()
    except:
        return None

async def get_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subs = set()
    async with aiohttp.ClientSession() as session:
        data = await fetch_json(session, url)
        if data:
            for entry in data:
                names = entry.get('name_value', '')
                for sub in names.split('\n'):
                    if domain in sub:
                        subs.add(sub.strip().lower())
    return subs

async def get_rapiddns(domain):
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    subs = set()
    async with aiohttp.ClientSession() as session:
        text = await fetch_text(session, url)
        if text:
            matches = re.findall(r'<td>([a-zA-Z0-9\-\._]+)</td>', text)
            for sub in matches:
                if domain in sub:
                    subs.add(sub.lower())
    return subs

async def get_viewdns(domain):
    url = f"https://viewdns.info/subdomains/?domain={domain}"
    subs = set()
    headers = {"User-Agent": "Mozilla/5.0"}
    async with aiohttp.ClientSession(headers=headers) as session:
        text = await fetch_text(session, url)
        if text:
            soup = BeautifulSoup(text, 'html.parser')
            tds = soup.find_all('td')
            for td in tds:
                sub = td.get_text(strip=True).lower()
                if domain in sub:
                    subs.add(sub)
    return subs

async def get_dnsdumpster(domain):
    url = "https://dnsdumpster.com/"
    subs = set()
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Referer": "https://dnsdumpster.com/",
    }
    async with aiohttp.ClientSession(headers=headers) as session:
        # DNSDumpster requires token and csrf validation; this is a simplified version:
        # You may want to extend for real token handling.
        try:
            # Step 1: Get CSRF token
            r = await session.get(url)
            text = await r.text()
            csrf_token = None
            match = re.search(r'name="csrfmiddlewaretoken" value="(.+?)"', text)
            if match:
                csrf_token = match.group(1)
            if not csrf_token:
                return subs
            # Step 2: Post domain query
            data = {
                "csrfmiddlewaretoken": csrf_token,
                "targetip": domain,
            }
            headers_post = headers.copy()
            headers_post["Content-Type"] = "application/x-www-form-urlencoded"
            headers_post["Referer"] = url
            async with session.post(url, data=data, headers=headers_post) as post_resp:
                post_text = await post_resp.text()
                soup = BeautifulSoup(post_text, 'html.parser')
                tables = soup.find_all("table")
                if tables:
                    rows = tables[0].find_all("tr")
                    for row in rows:
                        cols = row.find_all("td")
                        if len(cols) > 0:
                            sub = cols[0].text.strip().lower()
                            if domain in sub:
                                subs.add(sub)
        except:
            pass
    return subs

async def get_hackertarget_reverseip(domain):
    url = f"https://api.hackertarget.com/reverseiplookup/?q={domain}"
    subs = set()
    async with aiohttp.ClientSession() as session:
        text = await fetch_text(session, url)
        if text and "error" not in text.lower():
            for line in text.splitlines():
                if domain in line:
                    subs.add(line.strip().lower())
    return subs

async def alienvault_otx_ips(domain):
    url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/url_list?limit=500&page=1"
    ips = set()
    async with aiohttp.ClientSession() as session:
        try:
            data = await fetch_json(session, url)
            if data:
                for item in data.get('url_list', []):
                    ip = item.get('result', {}).get('urlworker', {}).get('ip')
                    if ip:
                        ips.add(ip)
        except:
            pass
    return ips

async def securitytrails_subdomains(domain, api_key):
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    subs = set()
    headers = {"APIKEY": api_key}
    async with aiohttp.ClientSession() as session:
        data = await fetch_json(session, url, headers=headers)
        if data and 'subdomains' in data:
            for sub in data['subdomains']:
                fqdn = f"{sub}.{domain}".lower()
                subs.add(fqdn)
    return subs

async def securitytrails_historical_ips(domain, api_key):
    url = f"https://api.securitytrails.com/v1/domain/{domain}/history/a"
    ips = set()
    headers = {"APIKEY": api_key}
    async with aiohttp.ClientSession() as session:
        data = await fetch_json(session, url, headers=headers)
        if data and 'records' in data:
            for record in data['records']:
                ip = record.get('ip')
                if ip:
                    ips.add(ip)
    return ips

async def virustotal_passive_dns(domain, api_key):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions"
    headers = {"x-apikey": api_key}
    ips = set()
    async with aiohttp.ClientSession() as session:
        data = await fetch_json(session, url, headers=headers)
        if data and 'data' in data:
            for entry in data['data']:
                ip = entry.get('attributes', {}).get('ip_address')
                if ip:
                    ips.add(ip)
    return ips

async def shodan_reverse(domain, api_key):
    url = f"https://api.shodan.io/dns/resolve?hostnames={domain}"
    ips = set()
    async with aiohttp.ClientSession() as session:
        try:
            r = await session.get(url + f"&key={api_key}", timeout=15)
            if r.status == 200:
                data = await r.json()
                for ip in data.values():
                    if ip:
                        ips.add(ip)
        except:
            pass
    return ips

async def censys_lookup(domain, api_id, api_secret):
    url = "https://search.censys.io/api/v2/hosts/search"
    ips = set()
    query = f"parsed.names: {domain}"
    headers = {
        "Content-Type": "application/json"
    }
    auth = aiohttp.BasicAuth(api_id, api_secret)
    payload = {"q": query}
    async with aiohttp.ClientSession(auth=auth, headers=headers) as session:
        try:
            async with session.post(url, json=payload, timeout=15) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for hit in data.get('result', {}).get('hits', []):
                        ip = hit.get('ip')
                        if ip:
                            ips.add(ip)
        except:
            pass
    return ips

def parse_spf(domain):
    ips = set()
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = str(rdata.to_text()).strip('"')
            if 'v=spf1' in txt:
                ip_matches = re.findall(r'ip[46]:[^\s]+', txt)
                for ip in ip_matches:
                    ips.add(ip.split(':')[1])
    except:
        pass
    return ips

async def resolve_subdomains(subdomains, silent):
    resolved = {}
    loop = asyncio.get_event_loop()

    async def resolve(sub):
        try:
            ip = await loop.run_in_executor(None, socket.gethostbyname, sub)
            resolved[sub] = ip
            if not silent:
                print(f"{Fore.GREEN}[Resolved] {sub} -> {ip}{Style.RESET_ALL}")
        except:
            pass

    await asyncio.gather(*(resolve(sub) for sub in subdomains))
    return resolved

def active_check(ip, domain):
    try:
        headers = {'Host': domain}
        r = requests.head(f"http://{ip}", headers=headers, timeout=5)
        if r.status_code in [200, 301, 302, 403, 401]:
            return True
    except:
        try:
            r = requests.head(f"https://{ip}", headers=headers, timeout=5, verify=False)
            if r.status_code in [200, 301, 302, 403, 401]:
                return True
        except:
            pass
    return False

def save_output(filename, resolved, origins):
    with open(filename, "w") as f:
        f.write("[Resolved Subdomains]\n")
        for sub, ip in resolved.items():
            f.write(f"{sub} -> {ip}\n")
        f.write("\n[Potential Origin IPs]\n")
        for ip in origins:
            f.write(f"{ip}\n")
    print(f"{Fore.CYAN}[+] Results saved to {filename}{Style.RESET_ALL}")

async def gather_all(domain, config, silent):
    all_subdomains = set()
    all_ips = set()

    # crt.sh
    crtsh_subs = await get_crtsh(domain)
    all_subdomains.update(crtsh_subs)

    # rapiddns.io
    rapiddns_subs = await get_rapiddns(domain)
    all_subdomains.update(rapiddns_subs)

    # viewdns.info
    viewdns_subs = await get_viewdns(domain)
    all_subdomains.update(viewdns_subs)

    # dnsdumpster.com
    dnsdumpster_subs = await get_dnsdumpster(domain)
    all_subdomains.update(dnsdumpster_subs)

    # HackerTarget reverse IP (domain is hostname here)
    hackertarget_subs = await get_hackertarget_reverseip(domain)
    all_subdomains.update(hackertarget_subs)

    # SecurityTrails API (subdomains + historical IPs)
    st_key = config.get("securitytrails_api_key")
    if st_key:
        st_subs = await securitytrails_subdomains(domain, st_key)
        st_ips = await securitytrails_historical_ips(domain, st_key)
        all_subdomains.update(st_subs)
        all_ips.update(st_ips)
    else:
        if not silent:
            print(f"{Fore.YELLOW}[SecurityTrails] API key missing, skipping.{Style.RESET_ALL}")

    # VirusTotal API (passive DNS)
    vt_key = config.get("virustotal_api_key")
    if vt_key:
        vt_ips = await virustotal_passive_dns(domain, vt_key)
        all_ips.update(vt_ips)
    else:
        if not silent:
            print(f"{Fore.YELLOW}[VirusTotal] API key missing, skipping.{Style.RESET_ALL}")

    # AlienVault OTX
    av_ips = await alienvault_otx_ips(domain)
    all_ips.update(av_ips)

    # Shodan API
    sh_key = config.get("shodan_api_key")
    if sh_key:
        sh_ips = await shodan_reverse(domain, sh_key)
        all_ips.update(sh_ips)
    else:
        if not silent:
            print(f"{Fore.YELLOW}[Shodan] API key missing, skipping.{Style.RESET_ALL}")

    # Censys API
    c_id = config.get("censys_api_id")
    c_secret = config.get("censys_api_secret")
    if c_id and c_secret:
        c_ips = await censys_lookup(domain, c_id, c_secret)
        all_ips.update(c_ips)
    else:
        if not silent:
            print(f"{Fore.YELLOW}[Censys] API credentials missing, skipping.{Style.RESET_ALL}")

    # SPF record parsing
    spf_ips = parse_spf(domain)
    all_ips.update(spf_ips)

    # Add root domain to subdomains for resolution
    all_subdomains.add(domain)

    return all_subdomains, all_ips

async def main():
    parser = argparse.ArgumentParser(description="0xmun1r Origin IP Finder v4 - Full Recon Tool")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("--active", action="store_true", help="Enable active IP validation (HTTP HEAD checks)")
    parser.add_argument("--passive", action="store_true", help="Passive mode only, skip active checks")
    parser.add_argument("--silent", action="store_true", help="Silent mode (no banner, minimal output)")
    parser.add_argument("--output", help="Save results to output file")
    args = parser.parse_args()

    if not args.silent:
        print(BANNER)

    config = load_config()
    domain = args.domain.lower()

    print_waf_status(domain, args.silent)

    # Gather all subdomains and IPs from all sources
    if not args.silent:
        print(f"{Fore.YELLOW}[*] Gathering subdomains and IPs from multiple sources...{Style.RESET_ALL}")

    all_subdomains, passive_ips = await gather_all(domain, config, args.silent)

    if not args.silent:
        print(f"{Fore.YELLOW}[*] Resolving subdomains...{Style.RESET_ALL}")

    resolved_subs = await resolve_subdomains(all_subdomains, args.silent)

    # Combine IPs from passive sources and DNS resolutions
    combined_ips = set(passive_ips) | set(resolved_subs.values())

    # Filter out CDN IPs if any
    filtered_ips = set()
    for ip in combined_ips:
        cdn_flag, cdn_name = is_cdn_ip(ip)
        if cdn_flag:
            if not args.silent:
                print(f"{Fore.MAGENTA}[Filter] Excluding CDN IP {ip} ({cdn_name}){Style.RESET_ALL}")
        else:
            filtered_ips.add(ip)

    # Active validation unless passive-only mode
    if args.active and not args.passive:
        if not args.silent:
            print(f"{Fore.YELLOW}[*] Starting active HTTP validation of IPs...{Style.RESET_ALL}")

        active_ips = set()
        for ip in filtered_ips:
            if active_check(ip, domain):
                active_ips.add(ip)
                if not args.silent:
                    print(f"{Fore.GREEN}[Active] {ip} is reachable and likely origin IP{Style.RESET_ALL}")
            else:
                if not args.silent:
                    print(f"{Fore.RED}[Active] {ip} not reachable{Style.RESET_ALL}")
    else:
        active_ips = filtered_ips
        if not args.silent:
            print(f"{Fore.YELLOW}[*] Skipping active validation due to passive mode or no --active flag{Style.RESET_ALL}")

    # Output results
    if args.output:
        save_output(args.output, resolved_subs, active_ips)

    if not args.silent:
        print(f"{Fore.CYAN}[+] Scan complete.{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting...")