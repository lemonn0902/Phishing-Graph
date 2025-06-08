// Load legitimate domains list
let legitDomains = [];
fetch(chrome.runtime.getURL('data/legit3.txt'))
  .then(response => response.text())
  .then(text => {
    legitDomains = text.split('\n').map(d => d.trim().toLowerCase()).filter(Boolean);
  });

// Utility functions from utils.py converted to JavaScript
function calculateEntropy(domain) {
  if (!domain) return 0;
  const freq = {};
  for (const char of domain) {
    freq[char] = (freq[char] || 0) + 1;
  }
  const entropy = -Object.values(freq).reduce((sum, f) => {
    const p = f / domain.length;
    return sum + p * Math.log2(p);
  }, 0);
  return Math.round(entropy * 1000) / 1000;
}

function levenshteinDistance(str1, str2) {
  const m = str1.length;
  const n = str2.length;
  const dp = Array(m + 1).fill().map(() => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (str1[i - 1] === str2[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(
          dp[i - 1][j],
          dp[i][j - 1],
          dp[i - 1][j - 1]
        );
      }
    }
  }
  return dp[m][n];
}

function jaccardSimilarity(str1, str2, n = 3) {
  function getNGrams(s, n) {
    const ngrams = new Set();
    for (let i = 0; i <= s.length - n; i++) {
      ngrams.add(s.slice(i, i + n));
    }
    return ngrams;
  }
  
  const set1 = getNGrams(str1, n);
  const set2 = getNGrams(str2, n);
  
  const intersection = new Set([...set1].filter(x => set2.has(x)));
  const union = new Set([...set1, ...set2]);
  
  return union.size ? intersection.size / union.size : 0;
}

function getBestMatch(userInput, legitDomains, levThresh = 3, jacThresh = 0.6) {
  // Pre-filter by length and first character
  const inputLen = userInput.length;
  const firstChar = userInput[0] || '';
  
  // Only check domains with similar length (±2) and same first character
  let candidates = legitDomains.filter(d => 
    Math.abs(d.length - inputLen) <= 2 && 
    d[0] === firstChar
  );
  
  // If too few candidates, expand search
  if (candidates.length < 100) {
    candidates = legitDomains.filter(d => 
      Math.abs(d.length - inputLen) <= 3
    );
  }
  
  let bestMatch = null;
  let bestScore = Infinity;
  let bestLev = null;
  let bestJac = null;
  
  for (const legit of candidates) {
    const lev = levenshteinDistance(userInput, legit);
    if (lev > levThresh) {  // Early exit if too different
      continue;
    }
    
    const jac = jaccardSimilarity(userInput, legit);
    
    if (lev <= levThresh || jac >= jacThresh) {
      const score = lev - jac;
      if (score < bestScore) {
        bestScore = score;
        bestMatch = legit;
        bestLev = lev;
        bestJac = jac;
      }
    }
  }
  
  return { bestMatch, bestLev, bestJac };
}

async function checkDNSRecords(domain) {
  const dnsInfo = {
    hasSpf: false,
    hasDmarc: false,
    hasNS: false,
    hasA: false
  };

  try {
    // Check A record
    const aResponse = await fetch(`https://dns.google/resolve?name=${domain}&type=A`);
    const aData = await aResponse.json();
    dnsInfo.hasA = aData.Answer && aData.Answer.length > 0;

    // Check NS records
    const nsResponse = await fetch(`https://dns.google/resolve?name=${domain}&type=NS`);
    const nsData = await nsResponse.json();
    dnsInfo.hasNS = nsData.Answer && nsData.Answer.length > 0;

    // Check TXT records for SPF and DMARC
    const txtResponse = await fetch(`https://dns.google/resolve?name=${domain}&type=TXT`);
    const txtData = await txtResponse.json();
    if (txtData.Answer) {
      for (const record of txtData.Answer) {
        const txt = record.data.toLowerCase();
        if (txt.includes('v=spf1')) {
          dnsInfo.hasSpf = true;
        }
      }
    }

    // Check DMARC record
    const dmarcResponse = await fetch(`https://dns.google/resolve?name=_dmarc.${domain}&type=TXT`);
    const dmarcData = await dmarcResponse.json();
    if (dmarcData.Answer) {
      for (const record of dmarcData.Answer) {
        const txt = record.data.toLowerCase();
        if (txt.includes('v=dmarc1')) {
          dnsInfo.hasDmarc = true;
        }
      }
    }
  } catch (error) {
    console.error('DNS check error:', error);
  }

  return dnsInfo;
}

// Store redirect information
const redirectTracker = new Map();

// Listen for redirect events
chrome.webRequest.onBeforeRedirect.addListener(
  (details) => {
    if (details.type === 'main_frame') {
      const originalUrl = new URL(details.url);
      const redirectUrl = new URL(details.redirectUrl);
      const domain = originalUrl.hostname.replace('www.', '');
      
      if (!redirectTracker.has(domain)) {
        redirectTracker.set(domain, {
          numRedirects: 1,
          redirectChain: [domain],
          flagged: true,
          timestamp: Date.now()
        });
      } else {
        const info = redirectTracker.get(domain);
        info.numRedirects++;
        info.redirectChain.push(redirectUrl.hostname);
        info.timestamp = Date.now();
      }
    }
  },
  { urls: ["<all_urls>"] }
);

// Clean up old redirect data every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [domain, info] of redirectTracker.entries()) {
    if (now - info.timestamp > 5 * 60 * 1000) { // 5 minutes
      redirectTracker.delete(domain);
    }
  }
}, 5 * 60 * 1000);

async function checkRedirects(domain) {
  // Get stored redirect information
  const redirectInfo = redirectTracker.get(domain) || {
    numRedirects: 0,
    redirectChain: [],
    flagged: false
  };

  return redirectInfo;
}

async function checkDomain(domain) {
  const cleanDomain = domain.toLowerCase();
  
  // First check exact match in legit domains
  if (legitDomains.includes(cleanDomain)) {
    return { riskScore: 0, reasons: ["Domain is in trusted list"] };
  }

  // Then check for similar domains with optimized thresholds
  const { bestMatch } = getBestMatch(cleanDomain, legitDomains, 3, 0.6);
  
  // Rest of the function remains the same...
  const entropyScore = calculateEntropy(cleanDomain);
  let sslScore = 0;
  let dnsScore = 0;
  let behaviorScore = 0;
  const reasons = [];
  
  if (bestMatch) {
    behaviorScore += 2.5;
    reasons.push(`Similar to legitimate domain: ${bestMatch}`);
  }

  // DNS Checks (25% weight)
  const dnsInfo = await checkDNSRecords(cleanDomain);
  if (!dnsInfo.hasSpf) {
    dnsScore += 1.5;
    reasons.push("No SPF record (Medium Risk)");
  }
  if (!dnsInfo.hasDmarc) {
    dnsScore += 1.5;
    reasons.push("No DMARC record (Medium Risk)");
  }
  if (!dnsInfo.hasNS) {
    dnsScore += 2.5;
    reasons.push("No nameserver records found (High Risk)");
  }
  if (!dnsInfo.hasA) {
    dnsScore += 2.5;
    reasons.push("No A records found (High Risk)");
  }
  
  // Check SSL certificate (25% weight)
  try {
    const response = await fetch(`https://${cleanDomain}`);
    const cert = response.headers.get('server-timing');
    if (!cert) {
      sslScore += 2;
      reasons.push("No SSL certificate found (Medium Risk)");
    }
  } catch {
    sslScore += 3;
    reasons.push("SSL verification failed (High Risk)");
  }
  
  // Check domain entropy and redirects (25% weight)
  if (entropyScore > 4.5) {
    behaviorScore += 2.5;
    reasons.push("High domain entropy - possible DGA (High Risk)");
  } else if (entropyScore > 3.5) {
    behaviorScore += 1.5;
    reasons.push("Medium domain entropy - unusual pattern (Medium Risk)");
  }

  // Check redirects
  const redirectInfo = await checkRedirects(cleanDomain);
  if (redirectInfo.flagged) {
    behaviorScore += 1.5;
    reasons.push("Multiple redirects detected (Medium Risk)");
    if (redirectInfo.numRedirects > 3) {
      behaviorScore += 1.5;
      reasons.push("Long redirect chain detected (High Risk)");
    }
  }

  // Calculate final weighted score
  const riskScore = Math.min(10, (
    (sslScore / 3) * 2.5 +      // SSL (25%)
    (dnsScore / 2.5) * 2.5 +    // DNS (25%)
    (behaviorScore / 2.5) * 2.5  // Behavior & Entropy (25%)
  ));
  
  // Add risk level to reasons without emoji (will be added in popup)
  if (riskScore >= 7) {
    reasons.unshift("HIGH RISK DOMAIN");
  } else if (riskScore >= 4) {
    reasons.unshift("MEDIUM RISK DOMAIN");
  } else {
    reasons.unshift("LOW RISK DOMAIN");
  }
  
  return {
    riskScore: Math.round(riskScore * 10) / 10,
    reasons
  };
}

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'checkDomain') {
    checkDomain(request.domain)
      .then(result => sendResponse(result));
    return true; // Will respond asynchronously
  }
});

// Replace webNavigation listener with a more robust implementation
chrome.webNavigation.onCommitted.addListener(
  async (details) => {
    // Only check main frame navigations
    if (details.frameId !== 0) return;
    
    try {
      const url = new URL(details.url);
      const domain = url.hostname.replace('www.', '');

      if (legitDomains.includes(domain)) {
        return;
      }
      
      // Check the domain
      const result = await checkDomain(domain);
      
      // Show warning for medium (>= 4) and high risk (>= 7) sites
      if (result.riskScore >= 4) {
        // Ensure the tab is still valid
        const tab = await chrome.tabs.get(details.tabId);
        if (!tab) {
          console.error('Tab no longer exists:', details.tabId);
          return;
        }

        // Wait for a moment to ensure content script is ready
        await new Promise(resolve => setTimeout(resolve, 100));

        // Try to send message to content script
        try {
          await chrome.tabs.sendMessage(details.tabId, {
            action: 'showWarning',
            riskScore: result.riskScore,
            reasons: result.reasons
          });
          console.log('Warning message sent successfully to tab:', details.tabId);
        } catch (error) {
          console.error('Failed to send message to content script, injecting script manually:', error);
          
          // If message fails, try to inject the content script manually
          try {
            await chrome.scripting.executeScript({
              target: { tabId: details.tabId },
              files: ['content.js']
            });
            
            // Try sending the message again after manual injection
            await chrome.tabs.sendMessage(details.tabId, {
              action: 'showWarning',
              riskScore: result.riskScore,
              reasons: result.reasons
            });
            console.log('Warning message sent after manual script injection');
          } catch (injectionError) {
            console.error('Failed to inject content script:', injectionError);
          }
        }
      }
    } catch (error) {
      console.error('Error checking domain:', error);
    }
  },
  { url: [{ schemes: ['http', 'https'] }] }
); 