from mitmproxy import http

# List of keywords or patterns to block in HTTP requests or responses
blocked_keywords = ["malware", "phishing", "blocked-content"]

def request(flow: http.HTTPFlow):
    """
    Inspect HTTP requests and block based on specific criteria.
    """
    # Inspect the URL
    if any(keyword in flow.request.pretty_url for keyword in blocked_keywords):
        flow.response = http.Response.make(
            403,
            b"Access to this content is blocked by DPI.",
            {"Content-Type": "text/plain"}
        )
        return

    # Inspect HTTP headers
    for header, value in flow.request.headers.items():
        if any(keyword in value for keyword in blocked_keywords):
            flow.response = http.Response.make(
                403,
                b"Access to this content is blocked by DPI.",
                {"Content-Type": "text/plain"}
            )
            return

def response(flow: http.HTTPFlow):
    """
    Inspect HTTP responses and block based on specific criteria.
    """
    # Inspect the response body
    if flow.response.content and any(keyword in flow.response.text for keyword in blocked_keywords):
        flow.response = http.Response.make(
            403,
            b"Access to this content is blocked by DPI.",
            {"Content-Type": "text/plain"}
        )