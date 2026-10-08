const emailInput = document.getElementById('emailInput');
const charCount = document.getElementById('charCount');
const analyzeBtn = document.getElementById('analyzeBtn');
const clearBtn = document.getElementById('clearBtn');
const sampleBtn = document.getElementById('sampleBtn');
const errorBox = document.getElementById('errorBox');
const placeholder = document.getElementById('placeholder');
const resultContent = document.getElementById('resultContent');
const resultCard = document.getElementById('resultCard');
const systemStatus = document.getElementById('systemStatus');

const phishingSample = `Dear Customer,

URGENT: Your bank account has been suspended due to suspicious activity.

Please click here to verify your account immediately:
https://fake-bank.example/verify

Failure to verify your password within 24 hours will result in permanent account closure.

Congratulations, you may also be eligible for a free reward.

Security Team`;

function updateCount() {
  const n = emailInput.value.length;
  charCount.textContent = `${n.toLocaleString()} characters`;
}

function showError(message) {
  errorBox.textContent = message;
  errorBox.style.display = 'block';
}

function hideError() {
  errorBox.textContent = '';
  errorBox.style.display = 'none';
}

function renderResult(data) {
  placeholder.classList.add('hidden');
  resultContent.classList.remove('hidden');
  resultCard.classList.toggle('phishing', data.is_phishing);

  document.getElementById('predictionText').textContent = data.prediction;
  document.getElementById('predictionText').style.color = data.is_phishing ? 'var(--danger)' : 'var(--accent)';
  document.getElementById('verdictIcon').textContent = data.is_phishing ? '!' : '✓';
  document.getElementById('phishingProbability').textContent = `${data.phishing_probability}%`;
  document.getElementById('phishingProbability2').textContent = `${data.phishing_probability}%`;
  document.getElementById('safeProbability').textContent = `${data.safe_probability}%`;
  document.getElementById('threshold').textContent = `${data.threshold}%`;
  document.getElementById('progressBar').style.width = `${data.phishing_probability}%`;

  const signalList = document.getElementById('signalList');
  signalList.innerHTML = '';
  const signals = data.features?.suspicious_patterns || [];
  if (!signals.length) {
    signalList.innerHTML = '<span class="no-signal">No obvious suspicious pattern was detected by the rule-based signal layer.</span>';
  } else {
    signals.forEach(signal => {
      const el = document.createElement('span');
      el.className = 'signal';
      el.textContent = signal;
      signalList.appendChild(el);
    });
  }

  const keywords = document.getElementById('keywords');
  keywords.innerHTML = '';
  const matched = data.features?.matched_keywords || [];
  if (!matched.length) {
    keywords.innerHTML = '<span class="no-signal">No configured phishing keywords matched.</span>';
  } else {
    matched.forEach(word => {
      const el = document.createElement('span');
      el.className = 'keyword';
      el.textContent = word;
      keywords.appendChild(el);
    });
  }
}

async function checkHealth() {
  try {
    const response = await fetch('/api/health');
    const data = await response.json();
    const dot = systemStatus.querySelector('span');
    if (data.model_loaded && data.preprocessor_loaded) {
      systemStatus.lastChild.textContent = ' Model ready';
      dot.style.background = 'var(--accent)';
    } else {
      systemStatus.lastChild.textContent = ' Model error';
      dot.style.background = 'var(--danger)';
    }
  } catch (error) {
    systemStatus.lastChild.textContent = ' API offline';
    systemStatus.querySelector('span').style.background = 'var(--danger)';
  }
}

async function analyzeEmail() {
  hideError();
  const email = emailInput.value.trim();
  if (!email) {
    showError('Please paste an email message first.');
    emailInput.focus();
    return;
  }

  analyzeBtn.disabled = true;
  analyzeBtn.querySelector('span:first-child').textContent = 'Analyzing...';

  try {
    const response = await fetch('/api/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });
    const data = await response.json();
    if (!response.ok || !data.success) {
      throw new Error(data.error || 'Prediction failed.');
    }
    renderResult(data);
  } catch (error) {
    showError(error.message || 'Could not connect to the Flask API.');
  } finally {
    analyzeBtn.disabled = false;
    analyzeBtn.querySelector('span:first-child').textContent = 'Analyze Email';
  }
}

emailInput.addEventListener('input', updateCount);
emailInput.addEventListener('keydown', (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') analyzeEmail();
});
analyzeBtn.addEventListener('click', analyzeEmail);
clearBtn.addEventListener('click', () => {
  emailInput.value = '';
  updateCount();
  hideError();
  placeholder.classList.remove('hidden');
  resultContent.classList.add('hidden');
  resultCard.classList.remove('phishing');
});
sampleBtn.addEventListener('click', () => {
  emailInput.value = phishingSample;
  updateCount();
  hideError();
  emailInput.focus();
});

updateCount();
checkHealth();
