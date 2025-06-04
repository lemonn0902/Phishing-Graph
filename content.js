// Create and inject warning UI
class WarningBanner {
  constructor(riskScore, reasons) {
    this.riskScore = riskScore;
    this.reasons = reasons;
    this.element = null;
    
    // Determine color scheme based on risk score
    const colors = this.getColorScheme();
    
    this.styles = {
      banner: `
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        background: linear-gradient(to right, ${colors.gradientStart}, ${colors.gradientEnd});
        color: white;
        padding: 20px;
        z-index: 999999;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
      `,
      container: `
        max-width: 1200px;
        margin: 0 auto;
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        gap: 24px;
      `,
      warningText: `
        flex-grow: 1;
      `,
      title: `
        display: flex;
        align-items: center;
        gap: 8px;
        font-size: 18px;
        font-weight: 600;
        margin-bottom: 8px;
        color: #ffffff;
      `,
      warningIcon: `
        display: flex;
        align-items: center;
        justify-content: center;
        background-color: rgba(255, 255, 255, 0.2);
        border-radius: 50%;
        width: 24px;
        height: 24px;
        font-size: 14px;
      `,
      riskScore: `
        display: inline-block;
        background-color: rgba(0, 0, 0, 0.2);
        padding: 2px 8px;
        border-radius: 4px;
        margin-left: 8px;
        font-size: 14px;
      `,
      reasonsList: `
        font-size: 14px;
        line-height: 1.5;
        opacity: 0.95;
        margin-top: 4px;
      `,
      buttonsContainer: `
        display: flex;
        gap: 12px;
        align-items: flex-start;
        margin-top: 4px;
      `,
      button: {
        base: `
          display: inline-flex;
          align-items: center;
          justify-content: center;
          padding: 10px 20px;
          border: none;
          border-radius: 6px;
          font-weight: 500;
          cursor: pointer;
          font-size: 14px;
          transition: all 0.2s ease;
          white-space: nowrap;
        `,
        primary: `
          background-color: white;
          color: ${colors.buttonColor};
          box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        `,
        secondary: `
          background-color: rgba(255, 255, 255, 0.1);
          color: white;
        `
      },
      reasonItem: `
        display: inline-block;
        background-color: rgba(0, 0, 0, 0.1);
        padding: 4px 8px;
        border-radius: 4px;
        margin: 2px 4px 2px 0;
      `
    };
  }

  getColorScheme() {
    if (this.riskScore >= 7) {
      return {
        gradientStart: '#ef4444',
        gradientEnd: '#dc2626',
        buttonColor: '#dc2626',
        icon: '⚠️'
      };
    } else {
      return {
        gradientStart: '#f97316',
        gradientEnd: '#ea580c',
        buttonColor: '#ea580c',
        icon: '⚡'
      };
    }
  }

  createButton(text, style, onClick) {
    const button = document.createElement('button');
    button.style.cssText = style;
    button.textContent = text;
    button.onclick = onClick;
    return button;
  }

  createTextElement(tag, text, style) {
    const element = document.createElement(tag);
    element.style.cssText = style;
    element.textContent = text;
    return element;
  }

  formatReasons(reasons) {
    // Filter out the first reason which is usually just the risk level
    const detailedReasons = reasons.slice(1);
    return detailedReasons.map(reason => {
      const span = document.createElement('span');
      span.style.cssText = this.styles.reasonItem;
      span.textContent = reason;
      return span;
    });
  }

  createWarningText() {
    const container = document.createElement('div');
    container.style.cssText = this.styles.warningText;

    const titleContainer = document.createElement('div');
    titleContainer.style.cssText = this.styles.title;

    const warningIcon = document.createElement('span');
    warningIcon.style.cssText = this.styles.warningIcon;
    warningIcon.textContent = this.getColorScheme().icon;
    titleContainer.appendChild(warningIcon);

    const titleText = document.createElement('span');
    titleText.textContent = this.riskScore >= 7 ? 
      'Warning: This site may be unsafe' : 
      'Caution: This site has some risk factors';
    titleContainer.appendChild(titleText);

    const riskScore = document.createElement('span');
    riskScore.style.cssText = this.styles.riskScore;
    riskScore.textContent = `Risk Score: ${this.riskScore}/10`;
    titleContainer.appendChild(riskScore);

    const reasonsList = document.createElement('div');
    reasonsList.style.cssText = this.styles.reasonsList;
    
    const formattedReasons = this.formatReasons(this.reasons);
    formattedReasons.forEach(reason => reasonsList.appendChild(reason));

    container.appendChild(titleContainer);
    container.appendChild(reasonsList);
    return container;
  }

  createButtons() {
    const container = document.createElement('div');
    container.style.cssText = this.styles.buttonsContainer;

    const redirectButton = this.createButton(
      'Go to Google',
      this.styles.button.base + this.styles.button.primary,
      () => { window.location.href = 'https://www.google.com'; }
    );

    const dismissButton = this.createButton(
      'Proceed Anyway',
      this.styles.button.base + this.styles.button.secondary,
      () => { this.remove(); }
    );

    container.appendChild(redirectButton);
    container.appendChild(dismissButton);
    return container;
  }

  render() {
    const banner = document.createElement('div');
    banner.style.cssText = this.styles.banner;

    const container = document.createElement('div');
    container.style.cssText = this.styles.container;

    container.appendChild(this.createWarningText());
    container.appendChild(this.createButtons());

    banner.appendChild(container);
    this.element = banner;
    return banner;
  }

  mount() {
    if (!this.element) {
      this.render();
    }
    document.body.prepend(this.element);

    // Add hover effects for buttons
    const buttons = this.element.getElementsByTagName('button');
    Array.from(buttons).forEach(button => {
      button.addEventListener('mouseover', () => {
        if (button.textContent === 'Go to Google') {
          button.style.backgroundColor = '#f8f8f8';
          button.style.transform = 'translateY(-1px)';
        } else {
          button.style.backgroundColor = 'rgba(255, 255, 255, 0.15)';
        }
      });
      button.addEventListener('mouseout', () => {
        if (button.textContent === 'Go to Google') {
          button.style.backgroundColor = 'white';
          button.style.transform = 'translateY(0)';
        } else {
          button.style.backgroundColor = 'rgba(255, 255, 255, 0.1)';
        }
      });
    });
  }

  remove() {
    if (this.element) {
      this.element.remove();
      this.element = null;
    }
  }
}

// Initialize message listener
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('Content script received message:', message);
  if (message.action === 'showWarning') {
    console.log('Creating warning banner with:', message.riskScore, message.reasons);
    const banner = new WarningBanner(message.riskScore, message.reasons);
    banner.mount();
  }
  sendResponse({ received: true });
  return true;
}); 