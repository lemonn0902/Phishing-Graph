import csv
from collections import defaultdict

LEV_THRESHOLD = 6
JACCARD_THRESHOLD = 0.5
TOP_N = 3

def read_similarity_csv(filepath):
    results = []
    with open(filepath, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            results.append({
                'phishing': row['Phishing Domain'],
                'legit': row['Legit Domain'],
                'lev': int(row['Levenshtein']),
                'jac': float(row['Jaccard']),
            })
    return results

def get_top_matches(similarity_data, top_n=3):
    phish_to_matches = defaultdict(list)

    for row in similarity_data:
        # Skip unrelated domains: low Jaccard AND high Levenshtein
        if row['jac'] < 1 and row['lev'] > 6:
            continue
        phish_to_matches[row['phishing']].append(row)

    filtered_results = []

    for phish, matches in phish_to_matches.items():
        # Sort by Levenshtein ascending, Jaccard descending
        matches.sort(key=lambda x: (x['lev'], -x['jac']))
        
        count = 0
        for match in matches:
            if match['lev'] <= LEV_THRESHOLD or match['jac'] >= JACCARD_THRESHOLD:
                filtered_results.append(match)
                count += 1
            if count == top_n:
                break

    return filtered_results

def write_filtered_csv(filtered_data, output_path):
    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['Phishing Domain', 'Legit Domain', 'Levenshtein', 'Jaccard'])
        writer.writeheader()
        for row in filtered_data:
            writer.writerow({
                'Phishing Domain': row['phishing'],
                'Legit Domain': row['legit'],
                'Levenshtein': row['lev'],
                'Jaccard': row['jac'],
            })

if __name__ == "__main__":
    data = read_similarity_csv('data/similarity_scores.csv')
    top_matches = get_top_matches(data, TOP_N)
    write_filtered_csv(top_matches, 'data/filtered_matches.csv')
    print(f"Filtered top matches saved to data/filtered_matches.csv")