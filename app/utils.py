import ssl, socket, whois, dns.resolver, dns.exception, requests, subprocess, re
from datetime import datetime
from urllib.parse import urlparse

def fetch_ssl_info(domain):
    ssl_info = {"issuer": None, "expires": None}
    domains_to_try = [f"www.{domain}", domain]
    
    # Try direct SSL connection
    for test_domain in domains_to_try:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((test_domain, 443), timeout=15) as sock:
                with context.wrap_socket(sock, server_hostname=test_domain) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        issuer = cert.get("issuer", [])
                        if issuer:
                            issuer_dict = {item[0]: item[1] for item in issuer if len(item) >= 2}
                            ssl_info["issuer"] = (issuer_dict.get('organizationName') or issuer_dict.get('commonName') or issuer_dict.get('O') or 'Unknown')
                        ssl_info["expires"] = cert.get("notAfter")
                        if ssl_info["issuer"] != 'Unknown':
                            return ssl_info
        except Exception:
            continue
    
    # Fallback: HTTPS request with disabled verification
    for test_domain in domains_to_try:
        try:
            import urllib3
            urllib3.disable_warnings()
            if requests.get(f"https://{test_domain}", timeout=10, verify=False).ok:
                ssl_info["issuer"] = "Valid SSL Certificate (via HTTPS request)"
                break
        except:
            continue
    
    # Final fallback: openssl command
    if not ssl_info.get("issuer"):
        for test_domain in domains_to_try:
            try:
                result = subprocess.run(['openssl', 's_client', '-connect', f'{test_domain}:443', '-servername', test_domain, '-verify_return_error'], 
                                      input='\n', text=True, capture_output=True, timeout=10)
                if 'issuer=' in result.stdout:
                    issuer_match = re.search(r'issuer=.*?O\s*=\s*([^,/]+)', result.stdout)
                    if issuer_match:
                        ssl_info["issuer"] = issuer_match.group(1).strip()
                        break
                    issuer_line = re.search(r'issuer=(.+)', result.stdout)
                    if issuer_line:
                        for part in issuer_line.group(1).split('/'):
                            if 'O=' in part:
                                ssl_info["issuer"] = part.replace('O=', '').strip()
                                break
                        ssl_info["issuer"] = ssl_info.get("issuer", "Certificate Found")
                        break
            except Exception:
                continue
    
    return ssl_info

def _whois_via_subprocess(domain):
    try:
        result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            return None
        
        output = result.stdout
        info = {"registrar": None, "creation_date": None}
        
        # Find registrar
        for pattern in [r'registrar:\s*(.+)', r'registrar organization:\s*(.+)', r'registrant organization:\s*(.+)', r'sponsoring registrar:\s*(.+)']:
            match = re.search(pattern, output, re.IGNORECASE)
            if match and (registrar := match.group(1).strip()) != 'N/A':
                info["registrar"] = registrar
                break
        
        # Find creation date
        for pattern in [r'creation date:\s*(\d{4}-\d{2}-\d{2})', r'created:\s*(\d{4}-\d{2}-\d{2})', r'registered:\s*(\d{4}-\d{2}-\d{2})', r'domain registered:\s*(\d{4}-\d{2}-\d{2})', r'created on:\s*(\d{4}-\d{2}-\d{2})']:
            if match := re.search(pattern, output, re.IGNORECASE):
                info["creation_date"] = match.group(1)
                break
        
        return info if info["registrar"] or info["creation_date"] else None
    except Exception:
        return None

def _whois_via_requests(domain):
    try:
        response = requests.get(f"https://www.whois.com/whois/{domain}", timeout=10)
        return {"registrar": "Registrar Found (via web lookup)", "creation_date": None} if response.ok and "registrar" in response.text.lower() else None
    except:
        return None

def fetch_whois_info(domain):
    whois_info = {"registrar": None, "creation_date": None}
    methods = [lambda: whois.whois(domain), lambda: _whois_via_subprocess(domain), lambda: _whois_via_requests(domain)]
    
    for method in methods:
        try:
            if (result := method()) and result.get('registrar'):
                whois_info.update(result)
                break
        except Exception:
            continue
    
    return whois_info

def fetch_dns_info(domain):
    dns_info = {"mx_records": [], "a_records": [], "txt_records": [], "ns_records": [], "has_spf": False, "has_dmarc": False, "suspicious_patterns": []}
    
    for resolver_ip in ['8.8.8.8', '1.1.1.1', '208.67.222.222']:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [resolver_ip]
            resolver.timeout = 5
            resolver.lifetime = 10
            
            # Get all record types
            for record_type, key in [('A', 'a_records'), ('MX', 'mx_records'), ('NS', 'ns_records')]:
                if not dns_info[key]:
                    try:
                        dns_info[key] = [str(rdata) for rdata in resolver.resolve(domain, record_type)]
                    except:
                        pass
            
            # Get TXT records and check for SPF/DMARC
            if not dns_info["txt_records"]:
                try:
                    for rdata in resolver.resolve(domain, 'TXT'):
                        txt_record = str(rdata).strip('"')
                        dns_info["txt_records"].append(txt_record)
                        if txt_record.startswith('v=spf1'):
                            dns_info["has_spf"] = True
                        elif txt_record.startswith('v=DMARC1'):
                            dns_info["has_dmarc"] = True
                except:
                    pass
            
            if dns_info["a_records"] or dns_info["ns_records"]:
                break
        except Exception:
            continue
    
    # Check for suspicious patterns
    for ip in dns_info["a_records"]:
        if ip in ['0.0.0.0', '127.0.0.1', '255.255.255.255']:
            dns_info["suspicious_patterns"].append(f"Suspicious IP: {ip}")
    
    for ns in dns_info["ns_records"]:
        if any(keyword in ns.lower() for keyword in ['free', 'parking', 'sedo', 'bodis']):
            dns_info["suspicious_patterns"].append(f"Suspicious nameserver: {ns}")
    
    return dns_info

def extract_domains(redirect_chain):
    domains = []
    for url in redirect_chain:
        try:
            domains.append(urlparse(url).netloc)
        except:
            continue
    return domains

def check_redirect_chain(domain):
    redirect_info = {"num_redirects": 0, "redirect_chain": [], "flagged": False, "domain_chain": []}
    
    for protocol in ['http', 'https']:
        try:
            response = requests.get(f"{protocol}://{domain}", allow_redirects=True, timeout=10, 
                                  headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
            
            chain = [resp.url for resp in response.history] + [response.url]
            if len(chain) > 1:
                redirect_info.update({"redirect_chain": chain, "num_redirects": len(chain) - 1, 
                                    "domain_chain": extract_domains(chain), "flagged": True})
                break
        except Exception:
            continue
    
    return redirect_info

def score_domain_risk(ssl_info, whois_info, dns_info=None, redirect_info=None):
    score, reasons = 0, []

    # SSL Checks
    if ssl_info.get("issuer"):
        if "self" in str(ssl_info["issuer"]).lower():
            score += 1
            reasons.append("Self-signed SSL certificate")
    else:
        score += 0.5
        reasons.append("No SSL certificate found")
    
    if ssl_info.get("expires"):
        try:
            exp_date = datetime.strptime(ssl_info["expires"], "%b %d %H:%M:%S %Y %Z")
            days_left = (exp_date - datetime.utcnow()).days
            if days_left <= 30:
                score += 1
                reasons.append("SSL expires in ≤ 30 days")
            elif days_left <= 90:
                score += 0.5
                reasons.append("SSL expires in ≤ 90 days")
        except Exception:
            pass

    # WHOIS Checks
    if creation := whois_info.get("creation_date"):
        try:
            age_days = (datetime.utcnow() - datetime.strptime(creation[:10], "%Y-%m-%d")).days
            if age_days < 30:
                score += 1
                reasons.append("Domain registered < 30 days ago")
            elif age_days < 90:
                score += 0.5
                reasons.append("Domain registered < 90 days ago")
        except Exception:
            pass
    else:
        score += 0.5
        reasons.append("Domain creation date unavailable")
    
    if not whois_info.get("registrar"):
        score += 0.5
        reasons.append("Registrar information unavailable")

    # DNS Checks
    if dns_info:
        checks = [
            (not dns_info.get("a_records"), 1, "No A records found"),
            (not dns_info.get("has_spf"), 0.3, "No SPF record"),
            (not dns_info.get("has_dmarc"), 0.3, "No DMARC record"),
            (not dns_info.get("ns_records"), 0.5, "No nameserver records found")
        ]
        
        for condition, penalty, reason in checks:
            if condition:
                score += penalty
                reasons.append(reason)
        
        if suspicious := dns_info.get("suspicious_patterns"):
            score += len(suspicious) * 0.5
            reasons.extend(suspicious)

    # Redirect Check
    if redirect_info and redirect_info.get("flagged"):
        score += 0.5
        reasons.append("Multiple redirects detected")

    return round(score, 1), reasons