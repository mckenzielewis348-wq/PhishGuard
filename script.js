document.getElementById('analyze-btn').addEventListener('click', analyzeURL);

// Phase 2: Top target brands and suspicious TLD lists
const TARGETED_BRANDS = ['paypal', 'google', 'microsoft', 'apple', 'chase', 'netflix', 'amazon', 'wellsfargo', 'facebook'];
const SUSPICIOUS_TLDS = ['.zip', '.mov', '.top', '.tk', '.xyz', '.work', '.click', '.gq', '.cf'];

function analyzeURL() {
  const input = document.getElementById('url-input').value.trim();
  if (!input) return;

  let url;
  try {
    url = new URL(input.startsWith('http') ? input : `http://${input}`);
  } catch (e) {
    alert('Please enter a valid URL.');
    return;
  }

  const results = runHeuristics(url);
  displayResults(results);
}

function runHeuristics(url) {
  let score = 0;
  const flags = [];
  const hostname = url.hostname.toLowerCase();
  const href = url.href.toLowerCase();

  // 1. IP Address Detection
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    score += 35;
    flags.push('Uses direct IP address instead of a domain name.');
  }

  // 2. Suspicious Keywords
  const keywords = ['login', 'verify', 'update', 'secure', 'account', 'banking', 'signin', 'password'];
  const foundKeywords = keywords.filter(kw => href.includes(kw));
  if (foundKeywords.length > 0) {
    score += 15 * Math.min(foundKeywords.length, 2);
    flags.push(`Contains sensitive keywords: ${foundKeywords.join(', ')}`);
  }

  // 3. Subdomain & Structure Anomaly
  if ((hostname.match(/\./g) || []).length > 2) {
    score += 15;
    flags.push('Excessive subdomains detected.');
  }
  if ((hostname.match(/-/g) || []).length > 1) {
    score += 10;
    flags.push('Multiple hyphens found in domain name.');
  }

  // 4. Protocol Check
  if (url.protocol !== 'https:') {
    score += 20;
    flags.push('Does not use secure HTTPS protocol.');
  }

  // 5. Brand Impersonation Check (Phase 2)
  TARGETED_BRANDS.forEach(brand => {
    if (hostname.includes(brand) && !hostname.endsWith(`${brand}.com`)) {
      score += 30;
      flags.push(`Possible brand impersonation targeting: ${brand}`);
    }
  });

  // 6. High-Risk TLD Check (Phase 2)
  if (SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld))) {
    score += 25;
    flags.push('Uses a top-level domain (TLD) frequently associated with phishing.');
  }

  // 7. Hidden Redirect / User Info Symbol Check (Phase 2)
  if (inputContainsAtSymbol(url)) {
    score += 25;
    flags.push('Contains "@" character in URL structure (potential credential/redirect trick).');
  }

  score = Math.min(score, 100);
  return { score, flags };
}

function inputContainsAtSymbol(url) {
  return url.username !== '' || url.href.includes('@');
}

function displayResults({ score, flags }) {
  const resultsCard = document.getElementById('results-card');
  const badge = document.getElementById('risk-badge');
  const scoreText = document.getElementById('risk-score-text');
  const list = document.getElementById('heuristics-list');

  resultsCard.classList.remove('hidden');
  scoreText.textContent = `Risk Score: ${score}/100`;

  list.innerHTML = '';
  if (flags.length === 0) {
    list.innerHTML = '<li>No obvious phishing indicators detected.</li>';
  } else {
    flags.forEach(flag => {
      const li = document.createElement('li');
      li.textContent = flag;
      list.appendChild(li);
    });
  }

  badge.className = 'badge';
  if (score < 30) {
    badge.classList.add('low');
    badge.textContent = 'Low Risk';
  } else if (score < 65) {
    badge.classList.add('medium');
    badge.textContent = 'Medium Risk';
  } else {
    badge.classList.add('high');
    badge.textContent = 'High Risk';
  }
}
