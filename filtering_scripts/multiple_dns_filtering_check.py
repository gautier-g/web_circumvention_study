from typing import Optional
import dns.resolver
from test_sni_filtering import test_sni_filtering

domains_to_check = [
    "example.com",
    "wikipedia.org",
    "1337x.to",
    "yts.mx",
    "www.4shared.com",
    "yts.mx",
    "katcr.co",
]


def get_local_dns() -> Optional[str]:
    """
    Gets the DNS that is used locally, usually the dns provided by the ISP
    """
    try:
        with open("/etc/resolv.conf", "r") as file:
            lines = file.readlines()
            # Look for lines that start with 'nameserver'
            for line in lines:
                if line.startswith("nameserver"):
                    dns_server = line.split()[1]
                    print(f"System DNS server: {dns_server}")
                    return dns_server
    except FileNotFoundError:
        print("Could not find resolv.conf. Is the file present?")
        return None
    except Exception as e:
        print(f"Error reading resolv.conf: {e}")
        return None


local_dns = get_local_dns()
# List of DNS to check
dns_servers = ["8.8.8.8", "1.1.1.1", local_dns]


def resolve_domain(domain, dns_server) -> Optional[str]:
    """
    Attemps to resolve a domain for a specified dns server
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        # Perform the query for the given domain
        # answers = resolver.resolve(domain)
        answer = resolver.resolve(domain, "A")
        ip = str(answer[0])
        print(f"Resolved {domain} using DNS server {dns_server}: for {ip}")
        return ip
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print(f"ERROR: DNS resolution failed for {domain} using {dns_server}.")
        return None
    except Exception as e:
        print(f"Error resolving {domain} with {dns_server}: {e}")
        return None


successfully_resolved_domains = []

# check dns resolution for all domains in domains_to_check
for domain in domains_to_check:
    print(f"-------- {domain} ----------")
    for dns_server in dns_servers:
        ip = resolve_domain(domain, dns_server)

        # if successfully resolved and not already in list
        if ip != None and (domain, ip) not in successfully_resolved_domains:
            successfully_resolved_domains.append((domain, ip))
    print("-------------")


# checks sni filtering for already resolved domains
for domain, ip in successfully_resolved_domains:
    print(f"+++++{domain}+++++")
    test_sni_filtering(domain, ip)
    print("++++++++++++\n")
