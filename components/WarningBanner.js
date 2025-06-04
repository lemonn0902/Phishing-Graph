// Styles for the warning banner
const styles = {
  banner: `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    background-color: #ef4444;
    color: white;
    padding: 16px;
    z-index: 999999;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 2px 8px rgba(0,0,0,0.2);
  `,
  warningText: `
    flex-grow: 1;
    margin-right: 16px;
  `,
  title: `
    font-size: 16px;
    font-weight: 600;
    margin-bottom: 4px;
  `,
  reasonsList: `
    font-size: 14px;
    opacity: 0.9;
  `,
  buttonsContainer: `
    display: flex;
    gap: 8px;
  `,
  button: {
    base: `
      padding: 8px 16px;
      border: none;
      border-radius: 4px;
      font-weight: 600;
      cursor: pointer;
      font-size: 14px;
    `,
    primary: `
      background-color: white;
      color: #ef4444;
    `,
    secondary: `
      background-color: rgba(255, 255, 255, 0.2);
      color: white;
    `
  }
};

// Component creation functions
function createButton(text, style, onClick) {
  const button = document.createElement('button');
  button.style.cssText = style;
  button.textContent = text;
  button.onclick = onClick;
  return button;
}

function createTextElement(tag, text, style) {
  const element = document.createElement(tag);
  element.style.cssText = style;
  element.textContent = text;
  return element;
}

// Main warning banner component
class WarningBanner {
  constructor(riskScore, reasons) {
    this.riskScore = riskScore;
    this.reasons = reasons;
    this.element = null;
  }

  createWarningText() {
    const container = document.createElement('div');
    container.style.cssText = styles.warningText;

    const title = createTextElement(
      'div',
      `⚠️ Warning: This site may be unsafe (Risk Score: ${this.riskScore}/10)`,
      styles.title
    );

    const reasonsList = createTextElement(
      'div',
      this.reasons.join(' | '),
      styles.reasonsList
    );

    container.appendChild(title);
    container.appendChild(reasonsList);
    return container;
  }

  createButtons() {
    const container = document.createElement('div');
    container.style.cssText = styles.buttonsContainer;

    const redirectButton = createButton(
      'Go to Google',
      styles.button.base + styles.button.primary,
      () => { window.location.href = 'https://www.google.com'; }
    );

    const dismissButton = createButton(
      'Proceed Anyway',
      styles.button.base + styles.button.secondary,
      () => { this.remove(); }
    );

    container.appendChild(redirectButton);
    container.appendChild(dismissButton);
    return container;
  }

  render() {
    const banner = document.createElement('div');
    banner.style.cssText = styles.banner;

    banner.appendChild(this.createWarningText());
    banner.appendChild(this.createButtons());

    this.element = banner;
    return banner;
  }

  mount() {
    if (!this.element) {
      this.render();
    }
    document.body.prepend(this.element);
  }

  remove() {
    if (this.element) {
      this.element.remove();
      this.element = null;
    }
  }
}

export { WarningBanner }; 