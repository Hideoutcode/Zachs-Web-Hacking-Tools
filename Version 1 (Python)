import requests
import socket
from bs4 import BeautifulSoup

# Test payloads
XSS_PAYLOAD = '<script>alert("XSS")</script>'
SQLI_PAYLOAD = "' OR '1'='1' -- "

def get_ip(url):
    """Resolve domain to IP address."""
    try:
        ip = socket.gethostbyname(url)
        return ip
    except socket.gaierror:
        return "Could not resolve IP"

def scan_headers(url):
    """Check security headers including CSP for vulnerabilities."""
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        vulnerabilities = []

        if "X-Frame-Options" not in headers:
            vulnerabilities.append("❌ Missing X-Frame-Options (Clickjacking risk)")
        if "X-XSS-Protection" not in headers:
            vulnerabilities.append("❌ Missing X-XSS-Protection (XSS risk)")
        if "X-Content-Type-Options" not in headers:
            vulnerabilities.append("❌ Missing X-Content-Type-Options (MIME sniffing risk)")

        if "Content-Security-Policy" in headers:
            vulnerabilities += analyze_csp(headers["Content-Security-Policy"])
        else:
            vulnerabilities.append("❌ Missing Content-Security-Policy (CSP) - XSS risk")

        return vulnerabilities
    except requests.RequestException:
        return ["Error: Unable to scan headers"]

def analyze_csp(csp):
    """Analyze CSP directives and check for security misconfigurations."""
    issues = []

    if "'unsafe-inline'" in csp:
        issues.append("⚠️ CSP allows 'unsafe-inline' (XSS risk)")
    if "'unsafe-eval'" in csp:
        issues.append("⚠️ CSP allows 'unsafe-eval' (Potential XSS via JavaScript eval())")
    if "default-src 'self'" not in csp:
        issues.append("⚠️ CSP missing default-src 'self' (Allows loading external scripts)")
    if "frame-ancestors 'none'" not in csp:
        issues.append("⚠️ CSP may allow Clickjacking (frame-ancestors not set to 'none')")

    if not issues:
        return ["✅ CSP is properly configured."]
    return issues

def find_input_fields(url):
    """Scan for input fields that may be vulnerable to XSS/SQL injection."""
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        inputs = soup.find_all("input")
        textareas = soup.find_all("textarea")

        if not inputs and not textareas:
            return []

        fields = []
        for inp in inputs + textareas:
            field_type = inp.get("type", "text")
            field_name = inp.get("name", "Unnamed")
            fields.append((field_name, field_type))

        return fields
    except requests.RequestException:
        return []

def test_vulnerabilities(url, fields):
    """Send payloads to input fields and check for reflection."""
    vulnerable_xss = []
    vulnerable_sqli = []

    for field_name, field_type in fields:
        if field_name == "Unnamed":
            continue  # Skip unnamed fields

        # Test for XSS
        data = {field_name: XSS_PAYLOAD}
        response = requests.post(url, data=data, timeout=5)
        if XSS_PAYLOAD in response.text:
            vulnerable_xss.append(field_name)

        # Test for SQL Injection
        data = {field_name: SQLI_PAYLOAD}
        response = requests.post(url, data=data, timeout=5)
        if "syntax error" in response.text.lower() or "database error" in response.text.lower():
            vulnerable_sqli.append(field_name)

    return vulnerable_xss, vulnerable_sqli

def scan_website(url):
    """Perform a vulnerability scan."""
    url = url.replace("http://", "").replace("https://", "").split("/")[0]
    full_url = f"http://{url}"

    print(f"🔍 Scanning {url}...\n")
    ip_address = get_ip(url)
    print(f"🌍 IP Address: {ip_address}\n")

    print("🔎 Checking security headers...")
    for vuln in scan_headers(full_url):
        print(vuln)

    print("\n📝 Scanning for input fields...")
    input_fields = find_input_fields(full_url)
    if not input_fields:
        print("❌ No input fields found.")
        return

    for field_name, field_type in input_fields:
        print(f"⚠️ Found input field: name='{field_name}', type='{field_type}'")

    print("\n💥 Testing vulnerabilities...")
    xss_vuln, sqli_vuln = test_vulnerabilities(full_url, input_fields)

    if xss_vuln:
        print("\n🚨 XSS Vulnerable Fields Found:")
        for field in xss_vuln:
            print(f"  - {field}")
    else:
        print("\n✅ No XSS vulnerabilities detected.")

    if sqli_vuln:
        print("\n🚨 SQL Injection Vulnerable Fields Found:")
        for field in sqli_vuln:
            print(f"  - {field}")
    else:
        print("\n✅ No SQL Injection vulnerabilities detected.")

if __name__ == "__main__":
    target_url = input("Enter target URL: ")
    scan_website(target_url)



