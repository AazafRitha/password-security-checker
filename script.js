// =============================
// Password Checker Script (script.js)
// =============================

// Strength colors for score 0-4
const strengthColors = ['#ff4d4d', '#ff944d', '#ffe44d', '#9fff4d', '#4dff88'];
const strengthTexts = ['Very Weak', 'Weak', 'Okay', 'Good', 'Strong'];

// Element references
const passwordInput = document.getElementById('passwordInput');
const strengthMeter = document.getElementById('strengthMeter');
const feedbackText = document.getElementById('feedbackText');
const toggleBtn = document.getElementById('toggleBtn');
const spinner = document.getElementById('loadingSpinner');
const copyBtn = document.getElementById('copyBtn');
const generateBtn = document.getElementById('generateBtn');
const downloadBtn = document.getElementById('downloadBtn');
const policyLink = document.getElementById('policyLink');
const policyModal = document.getElementById('policyModal');
const closeModal = document.getElementById('closeModal');

// Show/hide password
toggleBtn.addEventListener('click', () => {
  const type = passwordInput.type === 'password' ? 'text' : 'password';
  passwordInput.type = type;
  toggleBtn.textContent = type === 'password' ? '👁️' : '🙈';
});

// Regex rules for password validation
function validateWithRegex(password) {
  const errors = [];
  if (password.length < 12) errors.push("🔸 Minimum 12 characters required.");
  if (!/[a-z]/.test(password)) errors.push("🔸 Include at least one lowercase letter.");
  if (!/[A-Z]/.test(password)) errors.push("🔸 Include at least one uppercase letter.");
  if (!/[0-9]/.test(password)) errors.push("🔸 Include at least one number.");
  if (!/[^A-Za-z0-9]/.test(password)) errors.push("🔸 Include at least one special character.");
  return errors;
}

// SHA-1 hashing for HaveIBeenPwned check
async function sha1(str) {
  const buffer = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest("SHA-1", buffer);
  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('').toUpperCase();
}

// Breach check from HaveIBeenPwned
async function checkPasswordBreach(password) {
  const hash = await sha1(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
  const data = await res.text();
  const match = data.split('\n').find(line => line.startsWith(suffix));
  return match ? parseInt(match.split(':')[1]) : 0;
}

// Strength check and feedback on input
passwordInput.addEventListener('input', async () => {
  const password = passwordInput.value;
  spinner.classList.remove('hidden');

  const result = zxcvbn(password);
  strengthMeter.style.width = (result.score + 1) * 20 + '%';
  strengthMeter.style.backgroundColor = strengthColors[result.score];

  const regexErrors = validateWithRegex(password);
  let breachCount = 0;

  if (password && regexErrors.length === 0) {
    try {
      breachCount = await checkPasswordBreach(password);
    } catch (err) {
      feedbackText.textContent = '⚠️ Error checking breach database.';
      spinner.classList.add('hidden');
      return;
    }
  }

  passwordInput.classList.remove('input-alert');
  if (breachCount > 0) passwordInput.classList.add('input-alert');

  spinner.classList.add('hidden');

  // Final feedback output
  if (regexErrors.length > 0) {
    feedbackText.innerHTML = regexErrors.join('<br>');
  } else if (breachCount > 0) {
    feedbackText.innerHTML = `⚠️ Found in <strong>${breachCount.toLocaleString()}</strong> data breaches.`;
  } else if (password) {
    feedbackText.innerHTML = result.feedback.warning || '✅ Strong and unique password!';
  } else {
    feedbackText.textContent = '';
  }
});

// Copy password to clipboard
copyBtn.addEventListener('click', () => {
  if (passwordInput.value.length > 0) {
    navigator.clipboard.writeText(passwordInput.value);
    copyBtn.textContent = "✅ Copied!";
    setTimeout(() => (copyBtn.textContent = "📋 Copy Password"), 1500);
  }
});

// Generate a strong random password
function generatePassword(length = 14) {
  const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_-+=<>?";
  const array = new Uint32Array(length);
  crypto.getRandomValues(array);
  return Array.from(array, x => charset[x % charset.length]).join('');
}

generateBtn.addEventListener('click', () => {
  const newPass = generatePassword();
  passwordInput.value = newPass;
  passwordInput.dispatchEvent(new Event('input'));
});

// Policy popup modal
policyLink.addEventListener('click', e => {
  e.preventDefault();
  policyModal.classList.remove('hidden');
});

closeModal.addEventListener('click', () => {
  policyModal.classList.add('hidden');
});

// Download password report as PDF using jsPDF
downloadBtn.addEventListener('click', () => {
  const password = passwordInput.value;
  const result = zxcvbn(password);
  const doc = new jspdf.jsPDF();

  const text = [
    'Password Security Report',
    '-------------------------',
    `Password: ${password}`,
    `Strength Score: ${result.score} (${strengthTexts[result.score]})`,
    `Feedback: ${result.feedback.warning || 'Looks good!'}`,
    `Hints: ${result.feedback.suggestions.join('; ') || 'None'}`,
    '',
    'Generated by Aazaf Ritha — github.com/AazafRitha'
  ];

  doc.setFont('Courier', 'Normal');
  doc.setFontSize(12);
  doc.text(text, 10, 20);
  doc.save("password_report.pdf");
});
