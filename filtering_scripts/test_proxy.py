import requests


def make_request(url, proxy_url):
    "performs a request using a proxy, same as curl -x http://localhost:8080 <url> etc"

    proxies = {
        "http": proxy_url,
        "https": proxy_url,
    }
    # to disable certificate verification:
    # response = requests.get(url, proxies=proxies, verify=False)

    # request using the mitmproxy certificate
    response = requests.get(url, proxies=proxies, verify="/home/ash/.mitmproxy/mitmproxy-ca-cert.pem"
                            )
    print(f"------{url}------")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text[:100]}...")
    # print(f"Response: {response.text}")
    print("---------------------------\n")


proxy = "http://localhost:8080"
target_urls = ["http://example.com",
               "https://google.com", "https://wikipedia.org"]

for url in target_urls:
    make_request(url, proxy)
