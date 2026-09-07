const TARGETED_BRANDS = ['paypal', 'google', 'microsoft', 'apple', 'chase', 'netflix', 'amazon', 'wellsfargo', 'facebook'];
const SUSPICIOUS_TLDS = ['.zip', '.mov', '.top', '.tk', '.xyz', '.work', '.click', '.gq', '.cf'];

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('analyze-btn').addEventListener('click', analyzeURL);
  document.getElementById('copy-btn').addEventListener('click', copySummary);
  document.getElementById('clear-history-btn').addEventListener('click', clearHistory);
  loadHistory();
});

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

  const results = runHeuristics(url, input);
  displayResults(results);
  saveToHistory(results);
}

function runHeuristics(url, rawInput) {
  let score = 0;
  const flags = [];
  const recommendations = [];
  const hostname = url.hostname.toLowerCase();
  const href = url.href.toLowerCase();

  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    score += 35;
    flags.push('Uses direct IP address instead of a domain name.');
    recommendations.push('Legitimate services use domain names. IP addresses often bypass web filters.');
  }

  const keywords = ['login', 'verify', 'update', 'secure', 'account', 'banking', 'signin', 'password'];
  const foundKeywords = keywords.filter(kw => href.includes(kw));
  if (foundKeywords.length > 0) {
    score += 15 * Math.min(foundKeywords.length, 2);
    flags.push(`Contains sensitive keywords: ${foundKeywords.join(', ')}`);
    recommendations.push('Verify the main domain matches the official service before entering credentials.');
  }

  if ((hostname.match(/\./g) || []).length > 2) {
    score += 15;
    flags.push('Excessive subdomains detected.');
    recommendations.push('Attackers create complex subdomains to mimic legitimate company structures.');
  }

  if (url.protocol !== 'https:') {
    score += 20;
    flags.push('Does not use secure HTTPS protocol.');
    recommendations.push('Never enter password or personal data on HTTP pages.');
  }

  TARGETED_BRANDS.forEach(brand => {
    if (hostname.includes(brand) && !hostname.endsWith(`${brand}.com`)) {
      score += 30;
      flags.push(`Possible brand impersonation targeting: ${brand}`);
      recommendations.push(`Access ${brand} directly via bookmarked links rather than clicking external links.`);
    }
  });

  if (SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld))) {
    score += 25;
    flags.push('Uses a high-risk top-level domain (TLD).');
    recommendations.push('Be cautious with unfamiliar domain extensions frequently used in spam.');
  }

  if (url.username !== '' || rawInput.includes('@')) {
    score += 25;
    flags.push('Contains "@" character in URL structure.');
    recommendations.push('The "@" character in a URL can trick browsers into hiding the real target host.');
  }

  score = Math.min(score, 100);
  if (recommendations.length === 0) {
    recommendations.push('Always check the SSL certificate and address bar to ensure safety.');
  }

  return { url: url.href, hostname, score, flags, recommendations, date: new Date().toLocaleTimeString() };
}

function displayResults(data) {
  const resultsCard = document.getElementById('results-card');
  const badge = document.getElementById('risk-badge');
  const scoreText = document.getElementById('risk-score-text');
  const list = document.getElementById('heuristics-list');
  const eduList = document.getElementById('education-list');

  resultsCard.classList.remove('hidden');
  scoreText.textContent = `Risk Score: ${data.score}/100`;

  list.innerHTML = data.flags.length === 0 
    ? '<li>No obvious phishing indicators detected.</li>' 
    : data.flags.map(f => `<li>${f}</li>`).join('');

  eduList.innerHTML = data.recommendations.map(r => `<li>${r}</li>`).join('');

  badge.className = 'badge';
  if (data.score < 30) {
    badge.classList.add('low');
    badge.textContent = 'Low Risk';
  } else if (data.score < 65) {
    badge.classList.add('medium');
    badge.textContent = 'Medium Risk';
  } else {
    badge.classList.add('high');
    badge.textContent = 'High Risk';
  }
}

function saveToHistory(entry) {
  let history = JSON.parse(localStorage.getItem('phishguard_history') || '[]');
  history.unshift(entry);
  if (history.length > 10) history = history.slice(0, 10);
  localStorage.setItem('phishguard_history', JSON.stringify(history));
  loadHistory();
}

function loadHistory() {
  const historyList = document.getElementById('history-list');
  const history = JSON.parse(localStorage.getItem('phishguard_history') || '[]');
  
  if (history.length === 0) {
    historyList.innerHTML = '<li>No previous scans found.</li>';
    return;
  }

  historyList.innerHTML = history.map(item => `
    <li class="history-item">
      <span class="history-url" title="${item.url}">${item.hostname}</span>
      <span><strong>${item.score}/100</strong> (${item.date})</span>
    </li>
  `).join('');
}

function clearHistory() {
  localStorage.removeItem('phishguard_history');
  loadHistory();
}

function copySummary() {
  const score = document.getElementById('risk-score-text').textContent;
  const badge = document.getElementById('risk-badge').textContent;
  const url = document.getElementById('url-input').value;
  const summary = `PhishGuard Analysis Report\nURL: ${url}\nResult: ${badge} (${score})\nScanned locally via PhishGuard.`;

  navigator.clipboard.writeText(summary).then(() => {
    alert('Analysis report copied to clipboard!');
  });
}
