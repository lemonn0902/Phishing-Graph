# app.py (Flask backend with Neo4j integration and entropy-based DGA scoring)
import os
import csv
import math
from flask import Flask, request, render_template, redirect
from Levenshtein import distance as levenshtein_distance
from neo4j_utils import add_phishing_match, driver, get_phishing_history, get_phishing_statistics, test_connection
from flask import jsonify
from utils import fetch_ssl_info, fetch_whois_info, fetch_dns_info, score_domain_risk, check_redirect_chain
from neo4j_utils import add_domain_metadata  


app = Flask(__name__)

# Define paths
DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
LEGIT_FILE = os.path.join(DATA_DIR, 'legit_domains.txt')

# Load legit domains into memory in a list
with open(LEGIT_FILE, 'r', encoding='utf-8') as f:
    legit_domains = [line.strip().lower() for line in f if line.strip()]

# Similarity functions
def jaccard_similarity(str1, str2, n=3):
    def ngrams(s, n):
        return set(s[i:i+n] for i in range(len(s)-n+1))
    set1, set2 = ngrams(str1, n), ngrams(str2, n)
    return len(set1 & set2) / len(set1 | set2) if set1 | set2 else 0

def get_best_match(user_input, legit_domains, lev_thresh=2, jac_thresh=0.6):
    best_match = None
    best_score = float('inf')
    best_lev = None
    best_jac = None
    
    for legit in legit_domains:
        lev = levenshtein_distance(user_input, legit)
        jac = jaccard_similarity(user_input, legit)
        
        # More lenient conditions for finding matches
        if lev <= lev_thresh or jac >= jac_thresh:  # Changed AND to OR
            score = lev - jac  # prioritize smaller edit and higher overlap
            if score < best_score:
                best_score = score
                best_match = legit
                best_lev = lev
                best_jac = jac
    
    return best_match, best_lev, best_jac

# Entropy calculation for DGA detection
def calculate_entropy(domain):
    """Calculate Shannon entropy of a domain name for DGA detection"""
    if not domain:
        return 0
    freq = {}
    for char in domain:
        freq[char] = freq.get(char, 0) + 1
    entropy = -sum((f / len(domain)) * math.log2(f / len(domain)) for f in freq.values())
    return round(entropy, 3)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check():
    user_input = request.form['url'].strip().lower()
    
    # Remove protocol and www if present for cleaner comparison
    clean_input = user_input.replace('http://', '').replace('https://', '').replace('www.', '')
    
    # Calculate entropy for all cases
    entropy_score = calculate_entropy(clean_input)
    
    if clean_input in legit_domains:
        # Domain is in trusted list - still check DNS for completeness
        ssl_info = fetch_ssl_info(clean_input)
        whois_info = fetch_whois_info(clean_input)
        dns_info = fetch_dns_info(clean_input)
        risk_score, reasons = score_domain_risk(ssl_info, whois_info, dns_info, None, entropy_score)
        
        return render_template('result.html',
                              flagged=False,
                              domain=clean_input,
                              safe=True,
                              suggestion=None,
                              ssl=ssl_info,
                              whois=whois_info,
                              dns=dns_info,
                              risk_score=risk_score,
                              reasons=reasons,
                              entropy=entropy_score)
    
    best_match, lev_distance, jac_score = get_best_match(clean_input, legit_domains)
    ssl_info = fetch_ssl_info(clean_input)
    whois_info = fetch_whois_info(clean_input)
    dns_info = fetch_dns_info(clean_input)
    redirect_info = check_redirect_chain(clean_input)
    
    # Create similarity info dictionary
    similarity_info = None
    if best_match:
        similarity_info = {
            'best_match': best_match,
            'lev_distance': lev_distance,
            'jac_score': jac_score
        }
    
    risk_score, reasons = score_domain_risk(
        ssl_info, 
        whois_info, 
        dns_info, 
        redirect_info, 
        entropy_score,
        similarity_info
    )

    is_suspicious = False
    
    # thresholds
    if best_match:
        is_suspicious = True
    elif risk_score >= 3.5:  # Lower threshold from 4 to 3.5
        is_suspicious = True
        # Additional checks for medium-risk domains
        if (entropy_score > 3.5 or  # Suspicious entropy
            not dns_info.get("has_spf") or  # Missing SPF
            not dns_info.get("has_dmarc")):  # Missing DMARC
            is_suspicious = True
    
    if is_suspicious:
        # Log the phishing attempt to Neo4j
        try:
            add_phishing_match(clean_input, best_match, lev_distance, jac_score, ssl_info, whois_info, risk_score, reasons, redirect_info)
            print(f"Logged phishing attempt: {clean_input} -> {best_match}")
        except Exception as e:
            print(f"Error logging to Neo4j: {e}")
        
        return render_template('result.html',
                           flagged=is_suspicious,
                           domain=clean_input,
                           safe=not is_suspicious,
                           suggestion=best_match,
                           ssl=ssl_info,
                           whois=whois_info,
                           dns=dns_info,
                           risk_score=risk_score,
                           reasons=reasons,
                           redirect_info=redirect_info,
                           entropy=entropy_score)
    else:
        # No match found - could be legitimate unknown domain or suspicious
        return render_template('result.html',
                            flagged=is_suspicious,
                            domain=clean_input,
                            safe=not is_suspicious,
                            suggestion=None, 
                            ssl=ssl_info,
                            whois=whois_info,
                            dns=dns_info,
                            risk_score=risk_score,
                            reasons=reasons,
                            entropy=entropy_score)

@app.route('/analytics')
def analytics():
    """Show analytics dashboard with Neo4j data"""
    try:
        # Test connection first
        if not test_connection():
            return render_template('analytics.html', 
                                 phishing_data=[], 
                                 error="Cannot connect to Neo4j database. Please check if Neo4j is running.")
        
        phishing_data = get_phishing_history()
        stats = get_phishing_statistics()
        
        return render_template('analytics.html', 
                              phishing_data=phishing_data,
                              stats=stats,
                              error=None)
    except Exception as e:
        print(f"Error fetching analytics: {e}")
        return render_template('analytics.html', 
                              phishing_data=[], 
                              stats={},
                              error=f"Database error: {str(e)}")

@app.route('/api/phishing-stats')
def phishing_stats():
    """API endpoint for phishing statistics"""
    try:
        if not test_connection():
            return jsonify({"error": "Neo4j connection failed"}), 500
            
        stats = get_phishing_statistics()
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/bulk-check', methods=['POST'])
def bulk_check():
    raw_input = request.form['urls']
    domain_list = [line.strip().lower().replace('http://', '').replace('https://', '').replace('www.', '') 
                   for line in raw_input.splitlines() if line.strip()]
    
    results = []

    for domain in domain_list:
        entropy_score = calculate_entropy(domain)
        ssl_info = fetch_ssl_info(domain)
        whois_info = fetch_whois_info(domain)
        dns_info = fetch_dns_info(domain)
        redirect_info = check_redirect_chain(domain)
        risk_score, reasons = score_domain_risk(ssl_info, whois_info, dns_info, redirect_info, entropy_score)

        best_match, lev, jac = get_best_match(domain, legit_domains)

        flagged = domain not in legit_domains and (risk_score >= 4 or best_match)

        results.append({
            'domain': domain,
            'safe': not flagged,
            'flagged': flagged,
            'suggestion': best_match,
            'ssl': ssl_info,
            'whois': whois_info,
            'dns': dns_info,
            'redirect_info': redirect_info,
            'risk_score': risk_score,
            'reasons': reasons,
            'entropy': entropy_score,
        })

    return render_template('bulk_results.html', results=results)

@app.route('/api/check', methods=['POST'])
def api_check():
    domain = request.form['url'].strip().lower()
    domain = domain.replace('http://', '').replace('https://', '').replace('www.', '')
    
    # Quick legit check
    if domain in legit_domains:
        return jsonify({'flagged': False, 'reason': 'trusted_domain'})
    
    # Run all checks
    best_match, lev, jac = get_best_match(domain, legit_domains, 8, 0.3)
    ssl_info = fetch_ssl_info(domain)
    whois_info = fetch_whois_info(domain)
    dns_info = fetch_dns_info(domain)
    risk_score, reasons = score_domain_risk(ssl_info, whois_info, dns_info)
    entropy = calculate_entropy(domain)
    
    # Flag if any condition met
    is_flagged = bool(best_match or risk_score >= 1.5 or entropy > 3.5)
    
    return jsonify({
        'flagged': is_flagged,
        'domain': domain,
        'similarity_match': best_match,
        'risk_score': risk_score,
        'entropy': entropy,
        'reasons': reasons
    })

# Cleanup Neo4j connection when app shuts down
@app.teardown_appcontext
def close_neo4j(error):
    if driver:
        driver.close()


if __name__ == '__main__':
    app.run(debug=True, port=8000)