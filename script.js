document.getElementById('analyze-btn').addEventListener('click', analyzeURL);

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

  // Check 1: IP address used instead of domain name
  const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipPattern.test(url.hostname)) {
    score += 35;
    flags.push('Uses IP address instead of domain name.');
  }

  // Check 2: Suspicious keywords in hostname or path
  const keywords = ['login', 'verify', 'update', 'secure', 'account', 'banking', 'signin', 'password'];
  const foundKeywords = keywords.filter(kw => url.href.toLowerCase().includes(kw));
  if (foundKeywords.length > 0) {
    score += 20 * Math.min(foundKeywords.length, 2);
    flags.push(`Contains sensitive keywords: ${foundKeywords.join(', ')}`);
  }

  // Check 3: Excessive subdomains or hyphens
  if ((url.hostname.match(/\./g) || []).length > 2) {
    score += 15;
    flags.push('Excessive subdomains detected.');
  }
  if ((url.hostname.match(/-/g) || []).length > 1) {
    score += 10;
    flags.push('Multiple hyphens found in domain.');
  }

  // Check 4: Non-HTTPS scheme
  if (url.protocol !== 'https:') {
    score += 20;
    flags.push('Does not use secure HTTPS protocol.');
  }

  // Cap score at 100
  score = Math.min(score, 100);

  return { score, flags };
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
