from flask import Flask, render_template, request
import requests
import socket
import ssl
import os
from dotenv import load_dotenv

# Load API key from .env file
load_dotenv()
API_KEY = os.getenv("API_NINJAS_KEY")

app = Flask(__name__)

# -------- Utility Functions -------- #
def get_ip(domain):
    try:
        return socket.gethostbyname_ex(domain)[2]
    except Exception as e:
        print("IP Error:", e)
        return []

def get_whois(domain, api_key):
    headers = {'X-Api-Key': api_key}
    try:
        resp = requests.get(f'https://api.api-ninjas.com/v1/whois?domain={domain}', headers=headers, timeout=10)
        print("WHOIS status:", resp.status_code)
        print("WHOIS response:", resp.text)
        if resp.status_code == 200:
            return resp.json()
    except requests.RequestException as e:
        print("WHOIS Error:", e)
    return {}

def get_geo(ip):
    try:
        resp = requests.get(f'http://ip-api.com/json/{ip}', timeout=10)
        if resp.status_code == 200:
            return resp.json()
    except requests.RequestException as e:
        print("Geo Error:", e)
    return {}

def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    'issuer': dict(cert.get('issuer', [])),
                    'subject': dict(cert.get('subject', [])),
                    'valid_from': cert.get('notBefore'),
                    'valid_to': cert.get('notAfter')
                }
    except Exception:
        return {}

def get_http_headers(domain):
    try:
        resp = requests.get(f'https://{domain}', timeout=5)
        return dict(resp.headers)
    except requests.RequestException:
        return {}

def lookup(domain, api_key):
    result = {'domain': domain}

    # IP Lookup
    ips = get_ip(domain)
    result['ip_addresses'] = ips

    # Geo Info (from ip-api)
    geo_info = []
    for ip in ips:
        geo = get_geo(ip)
        if geo:
            geo_info.append(geo)
    result['geo_info'] = geo_info

    # WHOIS
    whois = get_whois(domain, api_key)
    result['whois_raw'] = whois  # store raw for hosting detection

    if whois:
        filtered_whois = {
            'Registrar': whois.get('registrar'),
            'Created Date': whois.get('creation_date'),
            'Updated Date': whois.get('updated_date'),
            'Expiry Date': whois.get('expiration_date'),
            'Nameservers': whois.get('name_servers'),
            'Registrant': whois.get('registrant_name'),
            'Emails': whois.get('emails'),
        }
        result['whois'] = {k: v for k, v in filtered_whois.items() if v}

    # Hosting provider detection
    hosting = "Unknown"
    try:
        if whois.get('registrar'):
            hosting = whois.get('registrar')
        elif whois.get('name_servers'):
            ns = whois.get('name_servers')
            if isinstance(ns, list):
                hosting = ns[0]
            else:
                hosting = ns
        elif geo_info and geo_info[0].get('org'):
            hosting = geo_info[0]['org']
    except Exception as e:
        print("Hosting detection error:", e)

    result['hosting'] = hosting

    # SSL Info
    ssl_info = get_ssl_info(domain)
    if ssl_info:
        result['ssl_info'] = ssl_info

    # HTTP Headers
    headers = get_http_headers(domain)
    if headers:
        result['http_headers'] = headers

    return result

# -------- Flask Route -------- #
@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    print("API KEY:", API_KEY)  # Debug API key
    if request.method == 'POST':
        domain_input = request.form.get('domain', '')
        domain = domain_input.replace("https://", "").replace("http://", "").strip().split('/')[0]
        print("Received domain:", domain)  # Debug line
        if domain:
            result = lookup(domain, API_KEY)
        else:
            print("No domain provided.")
    return render_template('index.html', result=result)

if __name__ == "__main__":
    print("\u2699\ufe0f Flask starting on http://127.0.0.1:8000 ...")
    app.run(debug=True, port=8000)
