from neo4j import GraphDatabase
from datetime import datetime
import os

# Set your Neo4j credentials here - use environment variables for security
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

def test_connection():
    """Test Neo4j connection"""
    try:
        with driver.session() as session:
            result = session.run("RETURN 1 as test")
            return result.single()["test"] == 1
    except Exception as e:
        print(f"Neo4j connection failed: {e}")
        return False

def add_phishing_match(phishing, legit, lev, jac, ssl_info, whois_info, risk_score, reasons, redirect_info):
    try:
        with driver.session() as session:
            session.write_transaction(_create_match, phishing, legit, lev, jac, ssl_info, whois_info, risk_score, reasons, redirect_info)
        return True
    except Exception as e:
        print(f"Error adding phishing match to Neo4j: {e}")
        return False

def _create_match(tx, phishing, legit, lev, jac, ssl_info, whois_info, risk_score, reasons, redirect_info):
    # Always create or update the Phishing node
    tx.run("""
        MERGE (p:Phishing {domain: $phishing})
        ON CREATE SET p.first_seen = datetime(), p.count = 1
        ON MATCH SET p.count = p.count + 1, p.last_seen = datetime()

        SET p.ssl_issuer = $ssl_issuer,
            p.ssl_expiry = $ssl_expiry,
            p.whois_registrar = $whois_registrar,
            p.whois_creation_date = $whois_creation_date,
            p.risk_score = $risk_score,
            p.risk_reasons = $risk_reasons,
            p.num_redirects = $num_redirects
    """, phishing=phishing,
         ssl_issuer=ssl_info.get("issuer"),
         ssl_expiry=ssl_info.get("expires"),
         whois_registrar=whois_info.get("registrar"),
         whois_creation_date=whois_info.get("creation_date"),
         risk_score=risk_score,
         risk_reasons=", ".join(reasons),
         num_redirects=redirect_info["num_redirects"])

    # Only add Legit node and SIMILAR_TO relationship if legit is not None
    if legit:
        tx.run("""
            MERGE (l:Legit {domain: $legit})
            ON CREATE SET l.created = datetime()

            MERGE (p:Phishing {domain: $phishing})
            MERGE (p)-[r:SIMILAR_TO {
                levenshtein: $lev,
                jaccard: $jac,
                created: datetime()
            }]->(l)
        """, phishing=phishing, legit=legit, lev=lev, jac=jac)

    # Always add redirect nodes
    for domain in redirect_info["domain_chain"]:
        tx.run("""
            MERGE (r:Redirect {domain: $rdomain})
            MERGE (p:Phishing {domain: $phishing})
            MERGE (p)-[:REDIRECTS_TO]->(r)
        """, rdomain=domain, phishing=phishing)

def get_phishing_history(limit=50):
    """Get recent phishing attempts"""
    with driver.session() as session:
        result = session.read_transaction(_get_phishing_history, limit)
        return result

def _get_phishing_history(tx, limit):
    """Transaction function to get phishing history"""
    result = tx.run("""
        MATCH (p:Phishing)-[r:SIMILAR_TO]->(l:Legit)
        RETURN p.domain as phishing_domain,
               l.domain as legit_domain,
               r.levenshtein as levenshtein_distance,
               r.jaccard as jaccard_similarity,
               p.count as attempt_count,
               p.first_seen as first_seen,
               p.last_seen as last_seen
        ORDER BY p.last_seen DESC
        LIMIT $limit
    """, limit=limit)
    
    return [dict(record) for record in result]

def get_phishing_statistics():
    """Get overall phishing statistics"""
    with driver.session() as session:
        return session.read_transaction(_get_phishing_statistics)

def _get_phishing_statistics(tx):
    """Transaction function to get phishing statistics"""
    try:
        # Total unique phishing domains
        total_phishing_result = tx.run("MATCH (p:Phishing) RETURN count(p) as count").single()
        total_phishing = total_phishing_result["count"] if total_phishing_result else 0
        
        # Total phishing attempts - handle null values
        total_attempts_result = tx.run("""
            MATCH (p:Phishing) 
            RETURN sum(CASE WHEN p.count IS NULL THEN 1 ELSE p.count END) as total
        """).single()
        total_attempts = total_attempts_result["total"] if total_attempts_result else 0
        
        # Most targeted legitimate domains
        top_targets = tx.run("""
            MATCH (p:Phishing)-[:SIMILAR_TO]->(l:Legit)
            RETURN l.domain as domain, count(p) as phishing_count
            ORDER BY phishing_count DESC
            LIMIT 10
        """).data()
        
        # Most common phishing domains - handle null counts
        top_phishing = tx.run("""
            MATCH (p:Phishing)
            RETURN p.domain as domain, 
                   CASE WHEN p.count IS NULL THEN 1 ELSE p.count END as attempt_count
            ORDER BY attempt_count DESC
            LIMIT 10
        """).data()
        
        # Recent activity (last 24 hours)
        recent_activity_result = tx.run("""
            MATCH (p:Phishing)
            WHERE p.last_seen IS NOT NULL 
            AND p.last_seen >= datetime() - duration('P1D')
            RETURN count(p) as recent_count
        """).single()
        recent_activity = recent_activity_result["recent_count"] if recent_activity_result else 0
        
        return {
            "total_phishing_domains": total_phishing or 0,
            "total_attempts": total_attempts or 0,
            "recent_activity_24h": recent_activity or 0,
            "top_targeted_domains": top_targets or [],
            "top_phishing_domains": top_phishing or []
        }
    except Exception as e:
        print(f"Error in _get_phishing_statistics: {e}")
        return {
            "total_phishing_domains": 0,
            "total_attempts": 0,
            "recent_activity_24h": 0,
            "top_targeted_domains": [],
            "top_phishing_domains": []
        }

def get_domain_relationships(domain, limit=20):
    """Get all domains similar to a specific domain"""
    with driver.session() as session:
        return session.read_transaction(_get_domain_relationships, domain, limit)

def _get_domain_relationships(tx, domain, limit):
    """Transaction function to get domain relationships"""
    # Find domains similar to the input domain
    result = tx.run("""
        MATCH (source)-[r:SIMILAR_TO]-(target)
        WHERE source.domain = $domain OR target.domain = $domain
        RETURN source.domain as source_domain,
               target.domain as target_domain,
               r.levenshtein as levenshtein_distance,
               r.jaccard as jaccard_similarity,
               labels(source) as source_labels,
               labels(target) as target_labels
        ORDER BY r.jaccard DESC, r.levenshtein ASC
        LIMIT $limit
    """, domain=domain, limit=limit)
    
    return [dict(record) for record in result]

def delete_old_records(days=30):
    """Delete phishing records older than specified days"""
    with driver.session() as session:
        return session.write_transaction(_delete_old_records, days)

def _delete_old_records(tx, days):
    """Transaction function to delete old records"""
    result = tx.run("""
        MATCH (p:Phishing)
        WHERE p.last_seen < datetime() - duration($duration)
        DETACH DELETE p
        RETURN count(p) as deleted_count
    """, duration=f"P{days}D")
    
    return result.single()["deleted_count"]

def close_connection():
    """Close Neo4j driver connection"""
    if driver:
        driver.close()

# Initialize connection test
if __name__ == "__main__":
    if test_connection():
        print("✅ Neo4j connection successful!")
        # Test basic functionality
        stats = get_phishing_statistics()
        print(f"Current stats: {stats}")
    else:
        print("❌ Neo4j connection failed!")

def add_domain_metadata(domain, ssl_data, whois_data):
    with driver.session() as session:
        return session.write_transaction(_add_domain_metadata, domain, ssl_data, whois_data)

def _add_domain_metadata(tx, domain, ssl_data, whois_data):
    tx.run("""
        MERGE (d:Domain {domain: $domain})
        SET d.ssl_issuer = $ssl_issuer,
            d.ssl_subject = $ssl_subject,
            d.ssl_notBefore = $ssl_notBefore,
            d.ssl_notAfter = $ssl_notAfter,
            d.ssl_serialNumber = $ssl_serialNumber,
            d.whois_registrar = $whois_registrar,
            d.whois_creation_date = $whois_creation_date,
            d.whois_expiration_date = $whois_expiration_date,
            d.whois_name_servers = $whois_name_servers,
            d.whois_status = $whois_status,
            d.last_updated = datetime()
    """, domain=domain,
         ssl_issuer=str(ssl_data.get('issuer')),
         ssl_subject=str(ssl_data.get('subject')),
         ssl_notBefore=ssl_data.get('notBefore'),
         ssl_notAfter=ssl_data.get('notAfter'),
         ssl_serialNumber=ssl_data.get('serialNumber'),
         whois_registrar=whois_data.get('registrar'),
         whois_creation_date=whois_data.get('creation_date'),
         whois_expiration_date=whois_data.get('expiration_date'),
         whois_name_servers=str(whois_data.get('name_servers')),
         whois_status=str(whois_data.get('status')))


def get_domain_reputation_score(domain):
    """Check if domain is connected to known phishing domains"""
    try:
        with driver.session() as session:
            result = session.run("""
                MATCH (p:Phishing)
                WHERE p.domain CONTAINS $domain_part OR $domain_part CONTAINS p.domain
                RETURN count(p) as phishing_connections
            """, domain_part=domain)
            
            record = result.single()
            if record:
                connections = record["phishing_connections"]
                return min(connections * 0.5, 2.0)  # Add up to 2 points to risk score
            return 0.0
    except Exception as e:
        print(f"Error getting domain reputation: {e}")
        return 0.0

def check_campaign_pattern(domain):
    """Check if domain is part of a larger phishing campaign"""
    try:
        with driver.session() as session:
            # Look for domains registered around the same time with similar patterns
            result = session.run("""
                MATCH (p:Phishing)
                WHERE p.domain <> $domain
                AND (
                    p.domain CONTAINS $domain_part OR 
                    $domain_part CONTAINS p.domain OR
                    p.whois_creation_date = $creation_date
                )
                AND p.first_seen >= datetime() - duration('P7D')
                RETURN count(p) as similar_recent_domains, 
                       collect(p.domain)[0..5] as example_domains
            """, domain=domain, 
                 domain_part=domain[:5] if len(domain) > 5 else domain,
                 creation_date=datetime.now().strftime('%Y-%m-%d'))
            
            record = result.single()
            if record and record["similar_recent_domains"] >= 2:
                return True, f"Part of campaign with {record['similar_recent_domains']} similar domains"
            return False, None
    except Exception as e:
        print(f"Error checking campaign pattern: {e}")
        return False, None

def get_redirect_network_risk(domain):
    """Check if domain redirects to known malicious endpoints"""
    try:
        with driver.session() as session:
            result = session.run("""
                MATCH (p:Phishing {domain: $domain})-[:REDIRECTS_TO]->(r:Redirect)
                MATCH (other:Phishing)-[:REDIRECTS_TO]->(r)
                WHERE other.domain <> $domain
                RETURN count(other) as shared_redirects,
                       collect(other.domain)[0..3] as other_domains
            """, domain=domain)
            
            record = result.single()
            if record and record["shared_redirects"] > 0:
                return record["shared_redirects"] * 0.5, f"Redirects shared with {record['shared_redirects']} other suspicious domains"
            return 0.0, None
    except Exception as e:
        print(f"Error checking redirect network: {e}")
        return 0.0, None

def get_network_enhanced_risk_score(domain, base_risk_score, reasons):
    """Enhance risk score using graph network analysis"""
    try:
        network_score = 0.0
        network_reasons = []
        
        # Check domain reputation
        reputation_score = get_domain_reputation_score(domain)
        if reputation_score > 0:
            network_score += reputation_score
            network_reasons.append(f"Connected to known phishing patterns (+{reputation_score})")
        
        # Check campaign patterns
        is_campaign, campaign_info = check_campaign_pattern(domain)
        if is_campaign:
            network_score += 1.5
            network_reasons.append(f"Campaign pattern detected: {campaign_info}")
        
        # Check redirect network
        redirect_score, redirect_info = get_redirect_network_risk(domain)
        if redirect_score > 0:
            network_score += redirect_score
            network_reasons.append(f"Redirect network risk: {redirect_info}")
        
        # Combine scores
        enhanced_score = min(10.0, base_risk_score + network_score)
        enhanced_reasons = reasons + network_reasons
        
        if network_score > 0:
            enhanced_reasons.insert(0, f"🕸️ NETWORK ANALYSIS: +{network_score} risk points")
        
        return enhanced_score, enhanced_reasons
        
    except Exception as e:
        print(f"Error in network analysis: {e}")
        return base_risk_score, reasons