from dns.query import https
from mitmproxy import http
from mitmproxy import tls, connection

# script used for mitmproxy proxy, start mitmproxy with:
# (env) ➜  pidr mitmproxy --listen-port 8080 -s filtering_scripts/tls_filtering.py

blocked_domains = [
    "example.com",
    "google.com",
]


def request(flow: http.HTTPFlow) -> None:
    domain = flow.request.host

    if domain in blocked_domains:
        flow.response = http.Response.make(
            403,
            b"Access to this domain is blocked.",
            {"Content-Type": "text/plain"}
        )
    else:
        response = ("Access allowed for " + domain).encode()
        flow.response = http.Response.make(
            200,
            # b"Access allowed",
            response,
            {"Content-Type": "text/plain"}
        )
