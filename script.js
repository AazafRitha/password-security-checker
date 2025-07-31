// Color scheme for strength meter (score 0 to 4)
const strengthColors = ['#ff4d4d', '#ff944d', '#ffe44d', '#9fff4d', '#4dff88'];

// Grab DOM elements
const passwordInput = document.getElementById('passwordInput');
const strengthMeter = document.getElementById('strengthMeter');
const feedbackText = document.getElementById('feedbackText');
const toggleBtn = document.getElementById('toggleBtn');
const spinner = document.getElementById('loadingSpinner');

// Show/hide password toggle button event
toggleBtn.addEventListener('click', () => {
  const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
  passwordInput.setAttribute('type', type);
  toggleBtn.textContent = type === 'password' ? '👁️' : '🙈';
});

// Validate password with custom regex rules
function validateWithRegex(password) {
  const errors = [];
  if (password.length < 12) errors.push("🔸 Minimum 12 characters required.");
  if (!/[a-z]/.test(password)) errors.push("🔸 Include at least one lowercase letter.");
  if (!/[A-Z]/.test(password)) errors.push("🔸 Include at least one uppercase letter.");
  if (!/[0-9]/.test(password)) errors.push("🔸 Include at least one number.");
  if (!/[^A-Za-z0-9]/.test(password)) errors.push("🔸 Include at least one special character.");
  return errors;
}

// Generate SHA-1 hash of the password (for breach check)
async function sha1(str) {
  const buffer = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest("SHA-1", buffer);
  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

// Check password against Have I Been Pwned API breach database
async function checkPasswordBreach(password) {
  const hash = await sha1(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
  const data = await response.text();

  const lines = data.split('\n');
  const match = lines.find(line => line.startsWith(suffix));
  
  return match ? parseInt(match.split(':')[1]) : 0;
}

// Main event: on user typing in password input
passwordInput.addEventListener('input', async () => {
  const password = passwordInput.value;

  // Show loading spinner
  spinner.classList.remove('hidden');

  // Check strength using zxcvbn (make sure zxcvbn library is loaded in your page)
  const result = zxcvbn(password);
  strengthMeter.style.width = (result.score + 1) * 20 + '%';
  strengthMeter.style.backgroundColor = strengthColors[result.score];

  // Validate against regex rules
  const regexErrors = validateWithRegex(password);

  let breachCount = 0;

  // Only check for breaches if password is not empty and passes regex validation
  if (password.length > 0 && regexErrors.length === 0) {
    try {
      breachCount = await checkPasswordBreach(password);
    } catch (error) {
      console.error('Error checking password breach:', error);
      feedbackText.textContent = '⚠️ Error checking password breach. Please try again later.';
      spinner.classList.add('hidden');
      return;
    }
  }

  // Toggle alert class based on breach count
  passwordInput.classList.remove('input-alert');
  if (breachCount > 0) {
    passwordInput.classList.add('input-alert');
  }

  // Hide spinner after async tasks done
  spinner.classList.add('hidden');

  // Show feedback messages accordingly
  if (regexErrors.length > 0) {
    feedbackText.innerHTML = regexErrors.join('<br>');
  } else if (breachCount > 0) {
    feedbackText.innerHTML = `⚠️ This password has been found in <strong>${breachCount.toLocaleString()}</strong> data breaches. Choose a different password.`;
  } else if (password.length > 0) {
    feedbackText.textContent = '✅ Strong and unique password!';
  } else {
    feedbackText.textContent = '';
  }
});
