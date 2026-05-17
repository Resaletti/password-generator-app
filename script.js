// ============================================
//  PASSFORGE — Password Generator
//  script.js
//
//  Uses the Web Crypto API (crypto.getRandomValues)
//  for cryptographically secure random generation.
//  Zero external dependencies. Zero data sent anywhere.
// ============================================

'use strict';

// --- CHARACTER SETS ---
const CHARS = {
  uppercase:  'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lowercase:  'abcdefghijklmnopqrstuvwxyz',
  numbers:    '0123456789',
  symbols:    '!@#$%^&*()-_=+[]{}|;:,.<>?',
  ambiguous:  'O0lI1',
};

// --- DOM REFERENCES ---
const passwordText    = document.getElementById('passwordText');
const copyBtn         = document.getElementById('copyBtn');
const refreshBtn      = document.getElementById('refreshBtn');
const copyToast       = document.getElementById('copyToast');
const generateBtn     = document.getElementById('generateBtn');

const lengthSlider    = document.getElementById('lengthSlider');
const lengthValue     = document.getElementById('lengthValue');

const quantitySlider  = document.getElementById('quantitySlider');
const quantityValue   = document.getElementById('quantityValue');

const useUppercase    = document.getElementById('useUppercase');
const useLowercase    = document.getElementById('useLowercase');
const useNumbers      = document.getElementById('useNumbers');
const useSymbols      = document.getElementById('useSymbols');

const excludeAmbiguous = document.getElementById('excludeAmbiguous');
const noRepeat         = document.getElementById('noRepeat');

const strengthFill    = document.getElementById('strengthFill');
const strengthLabel   = document.getElementById('strengthLabel');

const batchSection    = document.getElementById('batchSection');
const batchList       = document.getElementById('batchList');
const copyAllBtn      = document.getElementById('copyAllBtn');

const entropySection  = document.getElementById('entropySection');
const entropyBits     = document.getElementById('entropyBits');
const poolSize        = document.getElementById('poolSize');
const crackTime       = document.getElementById('crackTime');

// Toggle card elements
const toggleCards = {
  upper:   document.getElementById('toggleUpper'),
  lower:   document.getElementById('toggleLower'),
  numbers: document.getElementById('toggleNumbers'),
  symbols: document.getElementById('toggleSymbols'),
};

// Tracks the last generated batch
let lastBatch = [];

// ============================================
//  CORE — Cryptographically Secure Generator
// ============================================

/**
 * Generates a single password using crypto.getRandomValues().
 * This is the Web Crypto API — far more secure than Math.random().
 *
 * @param {number} length    - Desired password length
 * @param {string} charset   - Pool of characters to use
 * @param {boolean} noRepeat - Disallow repeating characters
 * @returns {string}
 */
function generatePassword(length, charset, noRepeat) {
  if (charset.length === 0) return '';

  // Enforce max length when noRepeat is set
  const maxLen = noRepeat ? Math.min(length, charset.length) : length;

  let result    = '';
  let available = charset.split('');

  // We use a typed array for crypto API
  const randomValues = new Uint32Array(maxLen * 3); // extra buffer for rejection sampling
  crypto.getRandomValues(randomValues);

  let idx = 0;

  for (let i = 0; i < maxLen; i++) {
    if (noRepeat && available.length === 0) break;

    const pool = noRepeat ? available : charset.split('');

    // Rejection sampling: avoid modulo bias
    const limit = Math.floor(0x100000000 / pool.length) * pool.length;
    let pick;

    do {
      if (idx >= randomValues.length) {
        // Refill if we ran out of buffer
        crypto.getRandomValues(randomValues);
        idx = 0;
      }
      pick = randomValues[idx++];
    } while (pick >= limit);

    const charIdx = pick % pool.length;
    result += pool[charIdx];

    if (noRepeat) {
      available.splice(charIdx, 1);
    }
  }

  return result;
}

// ============================================
//  CHARSET BUILDER
// ============================================

/**
 * Builds the character pool based on current settings.
 * Ensures at least one character from each selected set
 * by injecting a guaranteed character at a random position.
 */
function buildCharset() {
  let pool    = '';
  const sets  = [];

  if (useUppercase.checked) { sets.push(CHARS.uppercase); pool += CHARS.uppercase; }
  if (useLowercase.checked) { sets.push(CHARS.lowercase); pool += CHARS.lowercase; }
  if (useNumbers.checked)   { sets.push(CHARS.numbers);   pool += CHARS.numbers;   }
  if (useSymbols.checked)   { sets.push(CHARS.symbols);   pool += CHARS.symbols;   }

  if (excludeAmbiguous.checked) {
    pool = pool.split('').filter(c => !CHARS.ambiguous.includes(c)).join('');
  }

  return { pool, sets };
}

/**
 * Guarantees at least one character from each required set.
 */
function guaranteeCharsets(password, sets, pool, noRepeatMode) {
  const arr = password.split('');
  const len = arr.length;

  sets.forEach(set => {
    let filtered = set.split('').filter(c => pool.includes(c));
    if (noRepeatMode) filtered = filtered.filter(c => !arr.includes(c));
    if (filtered.length === 0) return;

    // Check if the password already contains a char from this set
    const hasChar = arr.some(c => filtered.includes(c));
    if (!hasChar && len > 0) {
      const randArr = new Uint32Array(2);
      crypto.getRandomValues(randArr);
      const replaceIdx = randArr[0] % len;
      const pickIdx    = randArr[1] % filtered.length;
      arr[replaceIdx]  = filtered[pickIdx];
    }
  });

  return arr.join('');
}

// ============================================
//  STRENGTH & ENTROPY
// ============================================

const STRENGTH_LEVELS = [
  { label: 'Very Weak', color: 'var(--red)',    pct: 15  },
  { label: 'Weak',      color: 'var(--orange)', pct: 35  },
  { label: 'Fair',      color: 'var(--yellow)', pct: 55  },
  { label: 'Strong',    color: 'var(--green)',  pct: 78  },
  { label: 'Very Strong',color:'var(--accent)', pct: 100 },
];

/**
 * Calculates Shannon entropy in bits.
 * entropy = length × log2(poolSize)
 */
function calcEntropy(length, poolLen) {
  if (poolLen === 0) return 0;
  return length * Math.log2(poolLen);
}

/**
 * Maps entropy bits to a strength tier.
 */
function getStrengthTier(bits) {
  if (bits < 28)  return 0;
  if (bits < 40)  return 1;
  if (bits < 60)  return 2;
  if (bits < 80)  return 3;
  return 4;
}

/**
 * Estimates crack time assuming 1 trillion guesses/sec (offline attack).
 */
function estimateCrackTime(bits) {
  const GUESSES_PER_SEC = 1e12;
  const combinations    = Math.pow(2, bits);
  const seconds         = combinations / (2 * GUESSES_PER_SEC); // avg = half

  if (seconds < 1)          return '< 1 sec';
  if (seconds < 60)         return `${Math.round(seconds)} sec`;
  if (seconds < 3600)       return `${Math.round(seconds / 60)} min`;
  if (seconds < 86400)      return `${Math.round(seconds / 3600)} hrs`;
  if (seconds < 2592000)    return `${Math.round(seconds / 86400)} days`;
  if (seconds < 31536000)   return `${Math.round(seconds / 2592000)} months`;
  if (seconds < 3.15e9)     return `${Math.round(seconds / 31536000)} years`;
  if (seconds < 3.15e12)    return `${(seconds / 3.15e9).toFixed(1)}K years`;
  if (seconds < 3.15e15)    return `${(seconds / 3.15e12).toFixed(1)}M years`;
  return '∞ years';
}

function updateStrength(password, poolLen) {
  const bits  = calcEntropy(password.length, poolLen);
  const tier  = getStrengthTier(bits);
  const level = STRENGTH_LEVELS[tier];

  strengthFill.style.width      = `${level.pct}%`;
  strengthFill.style.background = level.color;
  strengthLabel.style.color     = level.color;
  strengthLabel.textContent     = level.label;

  // Update entropy panel
  entropyBits.textContent = `${bits.toFixed(1)}`;
  poolSize.textContent    = poolLen;
  crackTime.textContent   = estimateCrackTime(bits);
}

// ============================================
//  UI UPDATES
// ============================================

function updateSliderVisual(slider, valueEl) {
  const min = Number(slider.min);
  const max = Number(slider.max);
  const val = Number(slider.value);
  const pct = ((val - min) / (max - min)) * 100;
  valueEl.textContent = val;
  // Tint the filled portion of the slider track via background
  slider.style.background = `linear-gradient(to right, var(--accent) ${pct}%, var(--surface3) ${pct}%)`;
}

function syncToggleCards() {
  toggleCards.upper.classList.toggle('active',   useUppercase.checked);
  toggleCards.lower.classList.toggle('active',   useLowercase.checked);
  toggleCards.numbers.classList.toggle('active', useNumbers.checked);
  toggleCards.symbols.classList.toggle('active', useSymbols.checked);
}

// ============================================
//  MAIN GENERATE FUNCTION
// ============================================

function generate() {
  const { pool, sets } = buildCharset();
  const length   = Number(lengthSlider.value);
  const quantity = Number(quantitySlider.value);
  const repeat   = !noRepeat.checked;

  if (pool.length === 0) {
    passwordText.textContent = 'Select at least one set';
    passwordText.classList.add('placeholder');
    strengthFill.style.width = '0%';
    strengthLabel.textContent = '—';
    return;
  }

  lastBatch = [];

  for (let i = 0; i < quantity; i++) {
    let pw = generatePassword(length, pool, !repeat);
    pw = guaranteeCharsets(pw, sets, pool, !repeat);
    lastBatch.push(pw);
  }

  // Primary display (first password)
  const primary = lastBatch[0];
  passwordText.textContent = primary;
  passwordText.classList.remove('placeholder');

  // Animate password characters in
  animatePassword();

  // Strength
  updateStrength(primary, pool.length);

  // Show entropy section
  entropySection.style.display = 'block';

  // Batch list
  if (quantity > 1) {
    batchSection.style.display = 'block';
    batchList.innerHTML = '';
    lastBatch.forEach((pw, i) => {
      const li   = document.createElement('li');
      li.className = 'batch-item';
      li.style.animationDelay = `${i * 40}ms`;
      li.innerHTML = `
        <span class="batch-pw">${pw}</span>
        <span class="batch-copy-hint">click to copy</span>
      `;
      li.addEventListener('click', () => copyText(pw, li));
      batchList.appendChild(li);
    });
  } else {
    batchSection.style.display = 'none';
  }
}

// ============================================
//  ANIMATIONS
// ============================================

function animatePassword() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$';
  const final = passwordText.textContent;
  const steps = 6;
  let step    = 0;

  const interval = setInterval(() => {
    if (step >= steps) { passwordText.textContent = final; clearInterval(interval); return; }
    passwordText.textContent = final.split('').map((c, i) => {
      if (i < Math.floor((step / steps) * final.length)) return c;
      return chars[Math.floor(Math.random() * chars.length)];
    }).join('');
    step++;
  }, 40);
}

// ============================================
//  CLIPBOARD
// ============================================

async function copyText(text, sourceEl) {
  try {
    await navigator.clipboard.writeText(text);
    // Show toast near the output section
    copyToast.classList.add('show');
    setTimeout(() => copyToast.classList.remove('show'), 1800);
    // Brief highlight on source element
    if (sourceEl) {
      sourceEl.style.borderColor = 'var(--green)';
      setTimeout(() => sourceEl.style.borderColor = '', 800);
    }
  } catch {
    // Fallback for older browsers
    const el = document.createElement('textarea');
    el.value = text;
    el.style.position = 'fixed';
    el.style.opacity  = '0';
    document.body.appendChild(el);
    el.select();
    document.execCommand('copy');
    document.body.removeChild(el);
    copyToast.classList.add('show');
    setTimeout(() => copyToast.classList.remove('show'), 1800);
  }
}

function copyAll() {
  const allPw = lastBatch.join('\n');
  copyText(allPw, null);
}

// ============================================
//  AT LEAST ONE CHARSET ENFORCER
// ============================================

function enforceAtLeastOne(changedCheckbox) {
  const all = [useUppercase, useLowercase, useNumbers, useSymbols];
  const checked = all.filter(cb => cb.checked);
  if (checked.length === 0) {
    changedCheckbox.checked = true;
    // Sync the card back
    syncToggleCards();
  }
}

// ============================================
//  EVENT LISTENERS
// ============================================

// Sliders
lengthSlider.addEventListener('input', () => {
  updateSliderVisual(lengthSlider, lengthValue);
});

quantitySlider.addEventListener('input', () => {
  updateSliderVisual(quantitySlider, quantityValue);
});

// Toggle cards — clicking the label triggers the checkbox change
[useUppercase, useLowercase, useNumbers, useSymbols].forEach(cb => {
  cb.addEventListener('change', () => {
    enforceAtLeastOne(cb);
    syncToggleCards();
  });
});

// Generate button
generateBtn.addEventListener('click', generate);

// Refresh button (regenerate with same settings)
refreshBtn.addEventListener('click', generate);

// Copy button
copyBtn.addEventListener('click', () => {
  if (lastBatch.length > 0) copyText(lastBatch[0], document.querySelector('.password-display'));
});

// Copy all
copyAllBtn.addEventListener('click', copyAll);

// Keyboard shortcut: Enter to generate
document.addEventListener('keydown', e => {
  if (e.key === 'Enter') generate();
  if ((e.ctrlKey || e.metaKey) && e.key === 'c' && lastBatch.length > 0) {
    e.preventDefault();
    copyText(lastBatch[0], document.querySelector('.password-display'));
  }
});

// ============================================
//  INIT
// ============================================

(function init() {
  updateSliderVisual(lengthSlider, lengthValue);
  updateSliderVisual(quantitySlider, quantityValue);
  syncToggleCards();

  // Set placeholder style
  passwordText.classList.add('placeholder');

  // Auto-generate on first load
  generate();
})();
