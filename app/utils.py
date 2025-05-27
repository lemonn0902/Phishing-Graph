import ssl, socket
import whois
import dns.resolver
import dns.exception
import requests
from datetime import datetime
from urllib.parse import urlparse


def fetch_ssl_info(domain):
    ssl_info = {"issuer": None, "expires": None}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                ssl_info["issuer"] = cert.get("issuer", [])[0][-1] if cert.get("issuer") else "Unknown"
                ssl_info["expires"] = cert.get("notAfter")
    except Exception:
        pass
    return ssl_info

def fetch_whois_info(domain):
    whois_info = {"registrar": None, "creation_date": None}
    try:
        w = whois.whois(domain)
        whois_info["registrar"] = w.registrar
        whois_info["creation_date"] = str(w.creation_date[0]) if isinstance(w.creation_date, list) else str(w.creation_date)
    except Exception:
        pass
    return whois_info

def fetch_dns_info(domain):
    """Fetch DNS information for security analysis"""
    dns_info = {
        "mx_records": [],
        "a_records": [],
        "txt_records": [],
        "ns_records": [],
        "has_spf": False,
        "has_dmarc": False,
        "suspicious_patterns": []
    }
    
    try:
        # Get A records (IP addresses)
        try:
            a_answers = dns.resolver.resolve(domain, 'A')
            dns_info["a_records"] = [str(rdata) for rdata in a_answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass

        # Get MX records (mail servers)
        try:
            mx_answers = dns.resolver.resolve(domain, 'MX')
            dns_info["mx_records"] = [str(rdata) for rdata in mx_answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass

        # Get NS records (name servers)
        try:
            ns_answers = dns.resolver.resolve(domain, 'NS')
            dns_info["ns_records"] = [str(rdata) for rdata in ns_answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass

        # Get TXT records and check for SPF/DMARC
        try:
            txt_answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in txt_answers:
                txt_record = str(rdata).strip('"')
                dns_info["txt_records"].append(txt_record)
                
                if txt_record.startswith('v=spf1'):
                    dns_info["has_spf"] = True
                elif txt_record.startswith('v=DMARC1'):
                    dns_info["has_dmarc"] = True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass

        # Check for suspicious patterns
        suspicious_ips = ['0.0.0.0', '127.0.0.1', '255.255.255.255']
        for ip in dns_info["a_records"]:
            if ip in suspicious_ips:
                dns_info["suspicious_patterns"].append(f"Suspicious IP: {ip}")
        
        # Check for suspicious name servers
        suspicious_ns_keywords = ['free', 'parking', 'sedo', 'bodis']
        for ns in dns_info["ns_records"]:
            if any(keyword in ns.lower() for keyword in suspicious_ns_keywords):
                dns_info["suspicious_patterns"].append(f"Suspicious nameserver: {ns}")

    except Exception as e:
        dns_info["error"] = str(e)
    
    return dns_info

def extract_domains(redirect_chain):
    domains = []
    for url in redirect_chain:
        try:
            parsed = urlparse(url)
            domains.append(parsed.netloc)
        except:
            continue
    return domains

def check_redirect_chain(domain):
    redirect_info = {
        "num_redirects": 0,
        "redirect_chain": [],
        "flagged": False,
        "domain_chain": []
    }
    try:
        response = requests.get(f"http://{domain}", allow_redirects=True, timeout=5)
        chain = [resp.url for resp in response.history] + [response.url]
        redirect_info["redirect_chain"] = chain
        redirect_info["num_redirects"] = len(chain) - 1
        redirect_info["domain_chain"] = extract_domains(chain)
        if len(chain) > 1:
            redirect_info["flagged"] = True
    except Exception:
        pass
    return redirect_info



def score_domain_risk(ssl_info, whois_info, dns_info=None, redirect_info=None):
    score = 0
    reasons = []

    # SSL Checks
    if not ssl_info.get("issuer") or "self" in str(ssl_info["issuer"]).lower():
        score += 1
        reasons.append("Self-signed or missing SSL issuer")
    if ssl_info.get("expires"):
        try:
            exp_date = datetime.strptime(ssl_info["expires"], "%b %d %H:%M:%S %Y %Z")
            days_left = (exp_date - datetime.utcnow()).days
            if days_left <= 90:
                score += 1
                reasons.append("SSL expires in ≤ 3 months")
        except Exception:
            pass

    # WHOIS Checks
    creation = whois_info.get("creation_date")
    if creation:
        try:
            creation_date = datetime.strptime(creation[:10], "%Y-%m-%d")
            age_days = (datetime.utcnow() - creation_date).days
            if age_days < 90:
                score += 1
                reasons.append("Domain registered < 3 months ago")
        except Exception:
            pass
    if not whois_info.get("registrar"):
        score += 1
        reasons.append("Missing registrar in WHOIS")

    # DNS Checks
    if dns_info:
        if not dns_info.get("a_records"):
            score += 1
            reasons.append("No A records found")
        
        if not dns_info.get("has_spf"):
            score += 0.5
            reasons.append("No SPF record found")
        
        if not dns_info.get("has_dmarc"):
            score += 0.5
            reasons.append("No DMARC record found")
        
        if dns_info.get("suspicious_patterns"):
            score += len(dns_info["suspicious_patterns"])
            reasons.extend(dns_info["suspicious_patterns"])
        
        if not dns_info.get("ns_records"):
            score += 1
            reasons.append("No nameserver records found")

    # Redirect Chain Check
    if redirect_info and redirect_info.get("flagged"):
        score += 1
        reasons.append("Multiple redirects detected before reaching final destination")

    return score, reasons