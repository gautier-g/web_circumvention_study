import socket
import ssl


def supports_https(ip: str, domain: str) -> bool:
    # checks if it supports https before checking for sni to avoid false positive
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((ip, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                return True
    except Exception:
        return False


def test_sni_filtering(domain, ip):
    "checks if the domain might be filtered by the sni certificate by attempting a TLS handshake, detects whether the server accepts the handshake and returns a valid certificate for the domain"

    ctx = ssl.create_default_context()
    if not supports_https(ip, domain):
        print(f"{domain} does not support https or is unreacheable")
        return
    try:
        # creates TCP connection on port 443 HTTPS
        with socket.create_connection((ip, 443), timeout=5) as raw_sock:
            # wraps the socket in TLS/SSL, sends the SNI field during the TLS handshake
            with ctx.wrap_socket(raw_sock, server_hostname=domain) as ssock:
                # get the certificate if the handshake is successful
                cert = ssock.getpeercert()
                if cert:
                    try:
                        cn = cert["subject"][0][0][1]
                        print(f"[SNI] - TLS handshake succeeded for {domain}. CN: {cn}")
                    except:
                        print("Some error idk, key_error?")
    except Exception as e:
        print(f"[SNI] Likely SNI-filtered or blocked. Error for domain {domain}: {e}\n")
