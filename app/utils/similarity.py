from Levenshtein import distance as levenshtein_distance
from functools import lru_cache

def jaccard_similarity(a: str, b: str) -> float:
    """Calculate Jaccard similarity between two strings"""
    set_a = set(a.lower())
    set_b = set(b.lower())
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union > 0 else 0

@lru_cache(maxsize=1000)
def find_closest_match(domain: str, legit_domains: tuple) -> dict:
    """
    Find the most similar legitimate domain with caching
    Args:
        domain: User-submitted domain
        legit_domains: Tuple of legitimate domains (must be hashable for cache)
    Returns:
        {'domain': str, 'jaccard': float, 'levenshtein': int}
    """
    best_match = ""
    best_jaccard = 0.0
    best_levenshtein = float('inf')
    
    for legit_domain in legit_domains:
        jac = jaccard_similarity(domain, legit_domain)
        lev = levenshtein_distance(domain, legit_domain)
        
        # Prioritize high Jaccard OR low Levenshtein
        if jac > best_jaccard or (jac == best_jaccard and lev < best_levenshtein):
            best_jaccard = jac
            best_levenshtein = lev
            best_match = legit_domain
    
    return {
        'domain': best_match,
        'jaccard': best_jaccard,
        'levenshtein': best_levenshtein
    }