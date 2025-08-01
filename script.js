// =============================
// Password Checker Script (script.js)
// =============================

const strengthColors = ['#ff4d4d', '#ff944d', '#ffe44d', '#9fff4d', '#4dff88'];
const strengthTexts = ['Very Weak', 'Weak', 'Okay', 'Good', 'Strong'];

const passwordInput = document.getElementById('passwordInput');
const strengthMeter = document.getElementById('strengthBar');
const feedbackText = document.getElementById('feedbackText');
const downloadBtn = document.getElementById('downloadBtn');
const spinner = document.getElementById('loadingSpinner');
const toggleBtn = document.getElementById('toggleBtn');
const generateBtn = document.getElementById('generateBtn');
const copyBtn = document.getElementById('copyBtn');
const policyLink = document.getElementById('policyLink');
const policyModal = document.getElementById('policyModal');
const closeModal = document.getElementById('closeModal');

let lastBreachCount = null;

// Function to update the visibility of the toggle button
function updateToggleBtnVisibility() {
  if (passwordInput.value.length > 0) {
    toggleBtn.classList.remove('hidden');
  } else {
    toggleBtn.classList.add('hidden');
    passwordInput.type = 'password'; // reset to hidden if empty
    toggleBtn.innerHTML = '<i class="fas fa-eye"></i>'; // reset icon
  }
}

// Regex-based validation function
function validateWithRegex(password) {
  const errors = [];
  if (password.length < 12) errors.push("Minimum 12 characters required");
  if (!/[A-Z]/.test(password)) errors.push("Include at least one uppercase letter");
  if (!/[a-z]/.test(password)) errors.push("Include at least one lowercase letter");
  if (!/[0-9]/.test(password)) errors.push("Include at least one digit");
  if (!/[!@#$%^&*(),.?\":{}|<>]/.test(password)) errors.push("Include at least one special character");
  return errors;
}

// Check password breach using k-anonymity with HaveIBeenPwned API
async function checkPasswordBreach(password) {
  const sha1 = new TextEncoder().encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-1', sha1);
  const hashHex = Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();

  const prefix = hashHex.substring(0, 5);
  const suffix = hashHex.substring(5);

  const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
  const text = await response.text();
  const lines = text.split('\n');

  for (const line of lines) {
    const [hashSuffix, count] = line.trim().split(':');
    if (hashSuffix === suffix) return parseInt(count);
  }
  return 0;
}

// Handle password input event
passwordInput.addEventListener('input', async () => {
  updateToggleBtnVisibility();

  const password = passwordInput.value;
  const result = zxcvbn(password);

  // Update strength meter visuals
  const strength = result.score;
  strengthMeter.style.width = `${(strength + 1) * 20}%`;
  strengthMeter.style.backgroundColor = strengthColors[strength];

  const regexErrors = validateWithRegex(password);

  if (password.length === 0) {
    feedbackText.textContent = 'Enter a password to check';
    return;
  }

  if (regexErrors.length > 0) {
    feedbackText.textContent = 'Issues: ' + regexErrors.join(', ');
    return;
  }

  feedbackText.textContent = result.feedback.warning || 'Looks good!';

  spinner.classList.remove('hidden');

  // Small delay to ensure spinner shows before async operation
  await new Promise(resolve => setTimeout(resolve, 100));

  try {
    const breachCount = await checkPasswordBreach(password);
    lastBreachCount = breachCount;
    feedbackText.textContent = "Checked!\nPassword Looks good!\nNow you can download the report.";
  } catch (err) {
    feedbackText.textContent = 'Error checking breach database.';
  }

  spinner.classList.add('hidden');
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

// Generate button event handler
generateBtn.addEventListener('click', () => {
  const newPass = generatePassword();
  passwordInput.value = newPass;
  passwordInput.dispatchEvent(new Event('input'));
  updateToggleBtnVisibility();
});

// Toggle password visibility button handler
toggleBtn.addEventListener('click', () => {
  if (passwordInput.type === 'password') {
    passwordInput.type = 'text';
    toggleBtn.innerHTML = '<i class="fas fa-eye-slash"></i>';
  } else {
    passwordInput.type = 'password';
    toggleBtn.innerHTML = '<i class="fas fa-eye"></i>';
  }
});

// Policy modal open
policyLink.addEventListener('click', e => {
  e.preventDefault();
  policyModal.classList.remove('hidden');
});

// Policy modal close
closeModal.addEventListener('click', () => {
  policyModal.classList.add('hidden');
});

// Download password report as PDF using jsPDF
downloadBtn.addEventListener('click', () => {
  const password = passwordInput.value;
  const result = zxcvbn(password);

  const doc = new jspdf.jsPDF();
  doc.setFont('Courier', 'Normal');
  doc.setFontSize(12);

  const breachLine = (lastBreachCount === null)
    ? 'Breach Count: Not Checked'
    : (lastBreachCount === 0)
      ? 'Breach Count: No breach found'
      : `Breach Count: Found in ${lastBreachCount.toLocaleString()} breaches`;

  const text = [
    'Password Security Report',
    '-------------------------',
    `Password: ${password}`,
    `Strength Score: ${result.score} (${strengthTexts[result.score]})`,
    `Feedback: ${result.feedback.warning || 'Looks good!'}`,
    `Hints: ${result.feedback.suggestions.join('; ') || 'None'}`,
    '',
    'Password Breach Status:',
    breachLine,
    'Check manually: https://haveibeenpwned.com/Passwords',
    '',
    'Password Policy & Rules:',
    '- At least 12 characters long',
    '- Includes uppercase and lowercase letters',
    '- Contains at least one number',
    '- Includes special characters (!@#$%^&*)',
    '- Avoid common words or sequences (e.g., 1234, qwerty)',
    '- Do not reuse passwords across multiple accounts',
    '',
    'Password Scoring Explained:',
    'Score 0 - Very Weak: Easy to guess (e.g., 123456)',
    'Score 1 - Weak: Still guessable, common patterns',
    'Score 2 - Okay: Some strength, but improvements needed',
    'Score 3 - Good: Reasonably strong and less predictable',
    'Score 4 - Strong: Very secure, long and complex',
    '',
    '--------------------------------------------------------',
    'BSc (Hons) in Information Technology — Cyber Security',
    'SLIIT Uni, Sri Lanka',
    'Generated by Aazaf Ritha — github.com/AazafRitha',
    '',
    'Thank you for using this Password Security Checker!',
    'Stay safe and secure online.'
  ];

  doc.text(text, 10, 20);
  doc.save("password_report.pdf");
});
