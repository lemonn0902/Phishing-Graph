# Phishing Domain Detector Chrome Extension

A Chrome extension that helps detect potential phishing domains using advanced risk scoring algorithms. The extension analyzes various aspects of a domain including entropy, SSL certificates, and similarity to legitimate domains to determine its risk level.

## Features

- Real-time domain risk analysis
- Risk scoring on a scale of 0-10
- Visual indicators for different risk levels (Low, Medium, High)
- Detailed explanations for risk factors
- Domain similarity checking against known legitimate domains
- Entropy-based analysis for detecting DGA (Domain Generation Algorithm) domains

## Installation

1. Clone this repository or download it as a ZIP file
2. Open Chrome and go to `chrome://extensions/`
3. Enable "Developer mode" in the top right corner
4. Click "Load unpacked" and select the extension directory

## Usage

1. Click the extension icon in your Chrome toolbar while on any website
2. The extension will automatically analyze the current domain
3. View the risk score and detailed explanations
4. Pay attention to any warnings or suspicious patterns detected

## Risk Levels

- 0-3.9: Low Risk (Green)
- 4-6.9: Medium Risk (Yellow)
- 7-10: High Risk (Red)

## Technical Details

The extension uses several methods to analyze domains:

- Levenshtein distance for string similarity
- Jaccard similarity for n-gram comparison
- Shannon entropy calculation
- SSL certificate verification
- Known legitimate domain comparison

## Files

- `manifest.json`: Extension configuration
- `popup.html`: Extension UI
- `popup.js`: UI logic
- `background.js`: Core analysis logic
- `data/legit_domains.txt`: List of known legitimate domains

## Development

To modify the extension:

1. Make your changes to the relevant files
2. Go to `chrome://extensions/`
3. Click the refresh icon on the extension card
4. Test your changes

## Contributing

Feel free to submit issues and enhancement requests!
