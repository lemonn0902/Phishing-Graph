import Levenshtein
import csv

def jaccard_similarity(str1, str2, n=3):
    def ngrams(string, n):
        return set([string[i:i+n] for i in range(len(string)-n+1)])
    
    ngrams1 = ngrams(str1, n)
    ngrams2 = ngrams(str2, n)
    intersection = ngrams1 & ngrams2
    union = ngrams1 | ngrams2
    return len(intersection) / len(union) if union else 0

def compute_similarity(phishing_domains, legit_domains):
    results = []
    for phish in phishing_domains:
        for legit in legit_domains:
            lev = Levenshtein.distance(phish, legit)
            jac = jaccard_similarity(phish, legit)
            results.append([phish, legit, lev, jac])
    return results

def load_domains(filename):
    with open(filename, 'r') as file:
        return [line.strip() for line in file.readlines()]

def write_to_csv(results, output_path):
    with open(output_path, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Phishing Domain', 'Legit Domain', 'Levenshtein', 'Jaccard'])
        writer.writerows(results)

if __name__ == '__main__':
    phishing = load_domains('data/phishing_domains.txt')
    legit = load_domains('data/legit_domains.txt')
    sim_scores = compute_similarity(phishing, legit)
    write_to_csv(sim_scores, 'data/similarity_scores.csv')