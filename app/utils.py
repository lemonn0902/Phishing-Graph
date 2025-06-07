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

def score_domain_risk(ssl_info, whois_info, dns_info=None, redirect_info=None, entropy=None, similarity_info=None):
    """
    Calculate domain risk score on a scale of 0-10
    Returns tuple of (normalized_score, reasons)
    
    Parameters:
    - similarity_info: dict containing 'best_match', 'lev_distance', 'jac_score' for domain similarity
    """
    base_score = 0
    max_score = 10
    reasons = []

    # SSL Certificate Checks (20% weight)
    ssl_score = 0
    if ssl_info.get("issuer"):
        if "self" in str(ssl_info["issuer"]).lower():
            ssl_score += 3
            reasons.append("Self-signed SSL certificate (High Risk)")
    else:
        ssl_score += 2
        reasons.append("No SSL certificate found (Medium Risk)")
    
    if ssl_info.get("expires"):
        try:
            exp_date = datetime.strptime(ssl_info["expires"], "%b %d %H:%M:%S %Y %Z")
            days_left = (exp_date - datetime.utcnow()).days
            if days_left <= 30:
                ssl_score += 2
                reasons.append("SSL expires in ≤ 30 days (Medium Risk)")
            elif days_left <= 90:
                ssl_score += 1
                reasons.append("SSL expires in ≤ 90 days (Low Risk)")
        except Exception:
            pass

    # WHOIS Checks (20% weight)
    whois_score = 0
    if creation := whois_info.get("creation_date"):
        try:
            age_days = (datetime.utcnow() - datetime.strptime(creation[:10], "%Y-%m-%d")).days
            if age_days < 30:
                whois_score += 2.5
                reasons.append("Domain registered < 30 days ago (High Risk)")
            elif age_days < 90:
                whois_score += 1.5
                reasons.append("Domain registered < 90 days ago (Medium Risk)")
        except Exception:
            pass
    else:
        whois_score += 1.5
        reasons.append("Domain creation date unavailable (Medium Risk)")
    
    if not whois_info.get("registrar"):
        whois_score += 1
        reasons.append("Registrar information unavailable (Low Risk)")

    # DNS Checks (20% weight)
    dns_score = 0
    if dns_info:
        checks = [
            (not dns_info.get("a_records"), 2.5, "No A records found (High Risk)"),
            (not dns_info.get("has_spf"), 1.5, "No SPF record (Medium Risk)"),
            (not dns_info.get("has_dmarc"), 1.5, "No DMARC record (Medium Risk)"),
            (not dns_info.get("ns_records"), 2, "No nameserver records found (High Risk)")
        ]
        
        for condition, penalty, reason in checks:
            if condition:
                dns_score += penalty
                reasons.append(reason)
        
        if suspicious := dns_info.get("suspicious_patterns"):
            pattern_score = min(2.5, len(suspicious) * 0.8)  # Cap at 2.5
            dns_score += pattern_score
            reasons.extend(f"{pattern} (High Risk)" for pattern in suspicious)

    # Similarity Score (20% weight)
    similarity_score = 0
    if similarity_info and similarity_info.get('best_match'):
        lev_distance = similarity_info.get('lev_distance', 0)
        jac_score = similarity_info.get('jac_score', 0)
        
        # Levenshtein distance scoring (lower is more suspicious)
        if lev_distance <= 1:
            similarity_score += 2.5
            reasons.append(f"Very similar to {similarity_info['best_match']} (High Risk)")
        elif lev_distance <= 2:
            similarity_score += 2.0
            reasons.append(f"Similar to {similarity_info['best_match']} (Medium Risk)")
        
        # Jaccard similarity scoring (higher is more suspicious)
        if jac_score >= 0.8:
            similarity_score += 2.5
            reasons.append("High character pattern similarity (High Risk)")
        elif jac_score >= 0.6:
            similarity_score += 1.5
            reasons.append("Medium character pattern similarity (Medium Risk)")

    # Entropy and Behavior Checks (20% weight)
    behavior_score = 0
    
    # Check redirects
    if redirect_info and redirect_info.get("flagged"):
        behavior_score += 1.5
        reasons.append("Multiple redirects detected (Medium Risk)")
        
        # Additional check for redirect chain length
        if redirect_info.get("num_redirects", 0) > 3:
            behavior_score += 1.5
            reasons.append("Long redirect chain detected (High Risk)")

    # Include entropy in scoring if provided
    if entropy is not None:
        if entropy > 4.5:
            behavior_score += 2.5
            reasons.append("High domain entropy - possible DGA (High Risk)")
        elif entropy > 3.5:
            behavior_score += 1.5
            reasons.append("Medium domain entropy - unusual pattern (Medium Risk)")

    # Calculate weighted scores (all components now 20%)
    weighted_score = (
        (ssl_score / 3) * 2.0 +         # SSL (20%)
        (whois_score / 2.5) * 2.0 +     # WHOIS (20%)
        (dns_score / 2.5) * 2.0 +       # DNS (20%)
        (similarity_score / 2.5) * 2.0 + # Similarity (20%)
        (behavior_score / 2.5) * 2.0     # Behavior & Entropy (20%)
    )

    # Normalize to 0-10 scale
    final_score = min(10, weighted_score)
    
    # Add risk level to reasons
    if final_score >= 6:
        reasons.insert(0, "⚠️ HIGH RISK DOMAIN")
    elif final_score >= 3.5:
        reasons.insert(0, "⚡ MEDIUM RISK DOMAIN")
    else:
        reasons.insert(0, "ℹ️ LOW RISK DOMAIN")

    return round(final_score, 1), reasons