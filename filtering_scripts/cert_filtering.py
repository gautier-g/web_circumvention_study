# script.py
from mitmproxy import http
import socket
import ssl

# CN and SAN to block
blocked_cns = ["example.com", "malicious-site.com"]

def get_real_certificate(domain):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                return ssock.getpeercert()
    except Exception as e:
        print(f"[CERT] Erreur récupération certificat pour {domain} : {e}")
        return None

def is_blocked_by_cert(cert):
    try:
        # Vérification CN
        cn = cert["subject"][0][0][1]
        if cn in blocked_cns:
            print(f"[CERT] Bloqué par CN : {cn}")
            return True
        # Check SAN
        san = cert.get("subjectAltName", [])
        for _, name in san:
            if name in blocked_cns:
                print(f"[CERT] Bloqué par SAN : {name}")
                return True
    except Exception as e:
        print(f"[CERT] Erreur parsing certificat : {e}")
    return False

def request(flow: http.HTTPFlow):
    host = flow.request.host
    cert = get_real_certificate(host)
    if cert and is_blocked_by_cert(cert):
        flow.response = http.Response.make(
                403,
                b"Access to this content is blocked : filtered by certificate.",
                {"Content-Type": "text/plain"}
            )



# def filter_sites_by_certificate(domains):
#     """
#     Filters a list of domains based on their SSL/TLS certificates.
#     """
#     for domain in domains:
#         print(f"Checking domain: {domain}")
#         cert = get_certificate(domain)
#         if cert:
#             if is_blocked_by_certificate(cert):
#                 print(f"Access to {domain} is blocked based on its certificate.\n")
#             else:
#                 print(f"Access to {domain} is allowed.\n")
#         else:
#             print(f"Could not retrieve certificate for {domain}.\n")


## List of domains to check
# domains_to_check = [
#     "example.com",
#     "google.com",
#     "malicious-site.com",
#     "wikipedia.org",
# ]

## Run the filtering
# filter_sites_by_certificate(domains_to_check)