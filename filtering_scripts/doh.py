import requests
from typing import Optional
from multiple_dns_filtering_check import get_local_dns, resolve_domain

import subprocess


def resolve_doh(domain: str, provider: str = "cloudflare") -> Optional[str]:
    # function to resolve a domain using DNS over HTTPS (DoH)
    # request json response
    headers = {"accept": "application/dns-json"}

    #  // select the url based on the DoH provider, default cloudfare
    if provider == "cloudflare":
        url = f"https://cloudflare-dns.com/dns-query?name={domain}&type=A"
    elif provider == "google":
        url = f"https://dns.google/resolve?name={domain}&type=A"
    else:
        print("Unsupported DoH provider.")
        return None

    try:
        # send get response
        response = requests.get(url, headers=headers, timeout=5)
        result = response.json()
        if "Answer" in result:
            ip = result["Answer"][0]["data"]
            print(f"[DoH-{provider}] {domain} resolved to {ip}")
            return ip
        else:
            print(f"[DoH-{provider}] No answer for {domain}")
            return None
    except Exception as e:
        print(f"Error resolving {domain} via DoH: {e}")
        return None


domains_to_check = [
    "example.com",
    "wikipedia.org",
    "1337x.to",
    "yts.mx",
    "www.4shared.com",
    "yts.mx",
    "katcr.co",
]


def curl_resolve_https(domain: str, ip: str) -> Optional[str]:
    """
    uses curl with --resolve to make a https request to a domain via a specific ip, for instance after using DoH
    """
    cmd = ["curl", "--resolve", f"{domain}:443:{ip}", f"https://{domain}"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return result.stdout
        else:
            print(f"curl error: {result.stderr}")
            return None
    except subprocess.SubprocessError as e:
        print(f"Failed to run curl: {e}")
        return None


for domain in domains_to_check:

    ip = resolve_domain(domain, get_local_dns())
    if ip is None:
        # if the domain cannot be resolved by dns resolution, use DoH to bypass it
        print("\n**************")
        ip = resolve_doh(domain)
        if ip:
            response = curl_resolve_https(domain, ip)
            if response:
                print(response[:500])
        print("**************\n")
