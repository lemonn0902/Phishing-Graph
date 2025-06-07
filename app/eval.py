# performance_evaluation.py - Complete evaluator
import requests
import json
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

def load_phishing_samples(limit=10):
    """Load phishing domains from PhishTank API"""
    
    url = "http://data.phishtank.com/data/online-valid.json"
    response = requests.get(url, timeout=30)
    data = response.json()
    domains = []
    for item in data[:limit]:
        url_clean = item['url'].replace('http://', '').replace('https://', '').split('/')[0]
        if '.' in url_clean and len(url_clean) < 50:  # Basic filtering
            domains.append(url_clean)
    return domains[:limit]

def load_legit_samples():
    """Load legitimate domains"""
    return ['google.com', 'facebook.com', 'amazon.com', 'microsoft.com', 
            'apple.com', 'wikipedia.org', 'reddit.com', 'twitter.com']

class PhishingEvaluator:
    def __init__(self, app_url="http://localhost:8000"):
        self.app_url = app_url
    
    def test_domains(self, domains, labels):
        """Test domains using API endpoint"""
        predictions = []
        for i, domain in enumerate(domains):
            try:
                response = requests.post(f"{self.app_url}/api/check", 
                                       data={'url': domain}, timeout=15)
                result = response.json()
                flagged = result.get('flagged', False)
                predictions.append(1 if flagged else 0)
                
                label_text = "PHISHING" if labels[i] == 1 else "LEGIT"
                pred_text = "FLAGGED" if flagged else "SAFE"
                print(f"{domain:25} | Actual: {label_text:8} | Predicted: {pred_text}")
                
            except Exception as e:
                print(f"{domain:25} | ERROR: {e}")
                predictions.append(0)
        return predictions
    
    def evaluate(self, test_data):
        """Evaluate performance"""
        domains = [d[0] for d in test_data]
        true_labels = [d[1] for d in test_data]
        
        print(f"Testing {len(domains)} domains...")
        print("-" * 50)
        predictions = self.test_domains(domains, true_labels)
        print("-" * 50)
        
        # Calculate metrics
        acc = accuracy_score(true_labels, predictions)
        prec = precision_score(true_labels, predictions, zero_division=0)
        rec = recall_score(true_labels, predictions, zero_division=0)
        f1 = f1_score(true_labels, predictions, zero_division=0)
        
        print(f"Accuracy:  {acc:.3f}")
        print(f"Precision: {prec:.3f}")
        print(f"Recall:    {rec:.3f}")
        print(f"F1-Score:  {f1:.3f}")
        
        return {'accuracy': acc, 'precision': prec, 'recall': rec, 'f1': f1}

# Usage
if __name__ == "__main__":
    evaluator = PhishingEvaluator()
    
    print("Loading test datasets...")
    phishing_domains = load_phishing_samples(10)
    legit_domains = load_legit_samples()
    
    test_data = [(d, 1) for d in phishing_domains] + [(d, 0) for d in legit_domains]
    
    results = evaluator.evaluate(test_data)
    
    baseline_acc = len(legit_domains) / len(test_data)
    print(f"\nBaseline (always safe): {baseline_acc:.3f}")
    print(f"Your improvement: {results['accuracy'] - baseline_acc:+.3f}")