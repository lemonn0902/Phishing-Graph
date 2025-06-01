document.addEventListener('DOMContentLoaded', function() {
  const ICONS = {
    HIGH_RISK: '\u26A0\uFE0F',    // ⚠️
    MEDIUM_RISK: '\u26A1',        // ⚡
    LOW_RISK: '\u2139\uFE0F'      // ℹ️
  };

  // Get the current tab's URL
  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    const url = new URL(tabs[0].url);
    const domain = url.hostname.replace('www.', '');
    
    // Update domain display
    document.getElementById('domain').textContent = domain;
    
    // Send message to background script to check domain
    chrome.runtime.sendMessage(
      { action: 'checkDomain', domain: domain },
      function(response) {
        document.getElementById('loading').style.display = 'none';
        document.getElementById('domainInfo').style.display = 'block';
        
        const riskScore = response.riskScore;
        const reasons = response.reasons;
        
        // Update risk score with appropriate color
        const scoreElement = document.getElementById('riskScore').parentElement.parentElement;
        document.getElementById('riskScore').textContent = riskScore;
        
        if (riskScore >= 7) {
          scoreElement.classList.add('high-risk');
        } else if (riskScore >= 4) {
          scoreElement.classList.add('medium-risk');
        } else {
          scoreElement.classList.add('low-risk');
        }
        
        // Display reasons with icons
        const reasonsContainer = document.getElementById('reasons');
        reasonsContainer.innerHTML = '';
        
        reasons.forEach((reason, index) => {
          const reasonElement = document.createElement('div');
          reasonElement.className = 'reason-item';
          
          const iconSpan = document.createElement('span');
          iconSpan.className = 'reason-icon';
          
          // First reason is always the risk level
          if (index === 0) {
            if (reason.includes('HIGH RISK')) {
              iconSpan.textContent = ICONS.HIGH_RISK;
            } else if (reason.includes('MEDIUM RISK')) {
              iconSpan.textContent = ICONS.MEDIUM_RISK;
            } else {
              iconSpan.textContent = ICONS.LOW_RISK;
            }
          } else {
            // For other reasons, check the risk level in the text
            if (reason.includes('High Risk')) {
              iconSpan.textContent = ICONS.HIGH_RISK;
            } else if (reason.includes('Medium Risk')) {
              iconSpan.textContent = ICONS.MEDIUM_RISK;
            } else {
              iconSpan.textContent = ICONS.LOW_RISK;
            }
          }
          
          reasonElement.appendChild(iconSpan);
          
          const textSpan = document.createElement('span');
          textSpan.textContent = ' ' + reason; // Add space after icon
          reasonElement.appendChild(textSpan);
          
          reasonsContainer.appendChild(reasonElement);
        });
      }
    );
  });
}); 