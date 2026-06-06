// ─── PASSWORD STRENGTH ───
function checkPasswordStrength(password) {
  const rules = {
    length:    password.length >= 8,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    number:    /[0-9]/.test(password),
    special:   /[!@#$%&*^()_+\-=\[\]{}|;':",.<>?\/\\`~]/.test(password),
  };
  return { rules, passed: Object.values(rules).filter(Boolean).length };
}

function initPasswordStrength(inputId) {
  const input = document.getElementById(inputId);
  if (!input) return;
  const barFill = document.querySelector('.pwd-bar-fill');
  const ruleEls = {
    length:    document.getElementById('rule-length'),
    uppercase: document.getElementById('rule-upper'),
    lowercase: document.getElementById('rule-lower'),
    number:    document.getElementById('rule-number'),
    special:   document.getElementById('rule-special'),
  };
  const colors = ['#ddd','#e74c3c','#e67e22','#f1c40f','#2e9e7a','#2e9e7a'];
  input.addEventListener('input', () => {
    const { rules, passed } = checkPasswordStrength(input.value);
    const pct = input.value.length ? (passed / 5) * 100 : 0;
    if (barFill) { barFill.style.width = pct + '%'; barFill.style.background = colors[passed]; }
    Object.entries(rules).forEach(([key, ok]) => {
      const el = ruleEls[key];
      if (el) { el.classList.toggle('pass', ok); el.querySelector('.check').textContent = ok ? '✓' : '○'; }
    });
  });
}

function initAvatarPreview(inputId, previewId) {
  const input   = document.getElementById(inputId);
  const preview = document.getElementById(previewId);
  if (!input || !preview) return;
  input.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => { preview.innerHTML = '<img src="' + ev.target.result + '" alt="">'; };
    reader.readAsDataURL(file);
  });
}

function initPasswordConfirm(pwdId, confirmId, feedbackId) {
  const pwd      = document.getElementById(pwdId);
  const confirm  = document.getElementById(confirmId);
  const feedback = document.getElementById(feedbackId);
  if (!pwd || !confirm || !feedback) return;
  const check = () => {
    if (!confirm.value) { feedback.textContent = ''; return; }
    if (pwd.value === confirm.value) {
      feedback.textContent = '✓ Passwords match';
      feedback.style.color = '#2e9e7a';
    } else {
      feedback.textContent = '✗ Passwords do not match';
      feedback.style.color = '#d94f43';
    }
  };
  pwd.addEventListener('input', check);
  confirm.addEventListener('input', check);
}

// ─── EMAILJS ───
const EMAILJS_PUBLIC_KEY  = 'tqh97xCyqPdV-Uuu4';
const EMAILJS_SERVICE_ID  = 'service_nxame25';
const EMAILJS_TEMPLATE_ID = 'template_gs2q0y8';

function sendWelcomeEmail(toEmail, toName) {
  if (typeof emailjs === 'undefined') {
    console.warn('EmailJS not loaded yet');
    return;
  }
  emailjs.init(EMAILJS_PUBLIC_KEY);
  const params = {
    email:   toEmail,
    name:    toName,
    title:   '🎉 Welcome to Luxe Market!',
    message: 'Congratulations ' + toName + '!\n\nYour Luxe Market account has been created successfully.\n\nYou can now:\n• Browse thousands of premium products\n• Add items to your cart and place orders\n• Track your orders in real time\n\nThank you for joining Luxe Market — your premium shopping destination!\n\nHappy Shopping! 🛍️'
  };
  emailjs.send(EMAILJS_SERVICE_ID, EMAILJS_TEMPLATE_ID, params)
    .then(() => console.log('✓ Welcome email sent to', toEmail))
    .catch(err => console.error('EmailJS error:', err));
}

function sendOrderEmail(toEmail, toName, orderDetails) {
  if (typeof emailjs === 'undefined') return;
  emailjs.init(EMAILJS_PUBLIC_KEY);
  emailjs.send(EMAILJS_SERVICE_ID, EMAILJS_TEMPLATE_ID, {
    email:   toEmail,
    name:    toName,
    title:   '📦 Order Confirmed — Luxe Market',
    message: 'Hi ' + toName + ',\n\nYour order has been placed successfully!\n\nOrder Details:\n' + orderDetails + '\n\nThe seller will confirm your order shortly. You will be notified when it is confirmed and delivered.\n\nThank you for shopping with Luxe Market!'
  }).then(() => console.log('✓ Order email sent'))
    .catch(err => console.error('EmailJS error:', err));
}

// ─── DOM READY ───
document.addEventListener('DOMContentLoaded', () => {
  initPasswordStrength('password');
  initAvatarPreview('profile_picture',      'avatar-preview');
  initAvatarPreview('profile_picture_edit', 'avatar-preview-edit');
  initPasswordConfirm('password', 'confirm_password', 'confirm-feedback');

  // Check if we just registered — send email from success page
  const regMeta = document.getElementById('reg-success-meta');
  if (regMeta) {
    const email = regMeta.dataset.email;
    const name  = regMeta.dataset.name;
    if (email && name) sendWelcomeEmail(email, name);
  }

  // Auto-dismiss flash messages
  setTimeout(() => {
    document.querySelectorAll('.flash').forEach(f => {
      f.style.transition = 'opacity 0.5s';
      f.style.opacity = '0';
      setTimeout(() => f.remove(), 500);
    });
  }, 5000);
});
