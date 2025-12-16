/**
 * @file Client-side application logic for the FHIR booking system.
 * ...
 */

// --- 1. Reusable API Handler ---

const api = {
  post: async function(endpoint, body) {
    const origin = window.location.origin;
    try {
      const response = await fetch(`${origin}${endpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(body)
      });

      const result = await response.json();
      if (!response.ok) {
        throw new Error(result.error || `Request failed with status ${response.status}`);
      }
      return result;

    } catch (err) {
      console.error(`API POST Error to ${endpoint}:`, err);
      throw err;
    }
  }
};

// --- 2. Shared Utilities ---

const common = {
  initializeI18n: async function() {
    const LANG_KEY = 'app_lang';
    const switcher = document.getElementById('langSwitcher');
    if (!switcher) return;

    const loadLocale = async (lang) => {
      try {
        const res = await fetch(`${window.location.origin}/locales/${lang}.json`);
        if (!res.ok) throw new Error(`Locale file not found for: ${lang}`);
        const dict = await res.json();
        document.querySelectorAll('[data-i18n]').forEach(el => {
          const key = el.dataset.i18n;
          if (dict[key]) el.textContent = dict[key];
        });
        document.documentElement.lang = lang;
      } catch (error) {
        console.error(`Could not load locale: ${lang}`, error);
      }
    };

    const savedLang = localStorage.getItem(LANG_KEY) || 'zh';
    switcher.value = savedLang;
    await loadLocale(savedLang);

    switcher.addEventListener('change', e => {
      const newLang = e.target.value;
      localStorage.setItem(LANG_KEY, newLang);
      loadLocale(newLang);
    });
  },

  showMessage: function(msg, type) {
    const messageDiv = document.getElementById('message');
    if (!messageDiv) return;

    messageDiv.textContent = msg;
    messageDiv.className = `message ${type}`;
    messageDiv.style.display = 'block';
  }
};


function handleLoginPage() {
  const loginForm = document.getElementById('loginForm');
  if (!loginForm) return;

  const params = new URLSearchParams(window.location.search);
  const postRegistrationToken = params.get('postRegistrationToken');

  // 🔵 新增：後端回傳 isPortalAdmin 時的跳轉方式
  const onLoginSuccess = (message, isPortalAdmin) => {
    common.showMessage(message, 'success');
    setTimeout(() => {
      if (isPortalAdmin) {
        // portal 管理員跳這裡
        window.location.href = '/portalAdmin.html';
      } else {
        // 一般使用者跳這裡
        window.location.href = '/patient-register.html';
      }
    }, 1000);
  };

  if (postRegistrationToken) {
    console.log('Post-registration token detected, attempting auto-login...');
    api.post('/api/login', { postRegistrationToken })
      .then(result => {
        onLoginSuccess('註冊後自動登入成功！正在跳轉...', result.isPortalAdmin);
      })
      .catch(err => common.showMessage(err.message, 'error'));

    window.history.replaceState({}, document.title, "/login.html");
  }

  loginForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    try {
      // 🔵 接收後端回傳結果（包含 isPortalAdmin）
      const result = await api.post('/api/login', { email, password });

      sessionStorage.setItem('userEmail', email);

      // 🔵 呼叫新版 onLoginSuccess
      onLoginSuccess('登入成功！正在跳轉...', result.isPortalAdmin);

    } catch (err) {
      common.showMessage(err.message, 'error');
    }
  });
}
function handleRegisterPage() {
  const registerForm = document.getElementById('registerForm');
  if (!registerForm) return;

  registerForm.addEventListener('submit', async e => {
    e.preventDefault();
    const data = {
      name: document.getElementById('name').value,
      email: document.getElementById('email').value,
      password: document.getElementById('password').value
    };
    try {
      const result = await api.post('/api/register', data);

      sessionStorage.setItem('userEmail', data.email);

      common.showMessage('註冊成功！將為您自動登入...', 'success');

      setTimeout(() => {
        window.location.href = `/login.html?postRegistrationToken=${result.postRegistrationToken}`;
      }, 1500);
    } catch (err) {
      common.showMessage(err.message, 'error');
    }
  });
}

function handleForgotPage() {
  const forgotForm = document.getElementById('forgotForm');
  if (!forgotForm) return;

  forgotForm.addEventListener('submit', async e => {
    e.preventDefault();
    const email = document.getElementById('email').value.trim();

    common.showMessage('請求已送出。如果此 Email 已註冊，您將很快收到一封重設密碼的郵件。', 'success');

    try {
      await api.post('/api/request-reset', { email });
    } catch (err) {
      console.error('Request password reset failed:', err);
    }
  });
}

function handleResetPasswordPage() {
  const resetForm = document.getElementById('resetForm');
  if (!resetForm) return;

  const token = new URLSearchParams(window.location.search).get('token');

  if (!token) {
    common.showMessage('錯誤：無效的重設連結，找不到權杖。', 'error');
    resetForm.style.display = 'none';
    return;
  }

  resetForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirm-password').value;

    if (password !== confirmPassword) {
      common.showMessage('密碼不相符。', 'error');
      return;
    }
    if (password.length < 6) {
      common.showMessage('密碼長度至少需要 6 個字元。', 'error');
      return;
    }

    try {
      const result = await api.post('/api/reset-password', { token, password });
      common.showMessage(result.message + ' 您現在可以關閉此頁面並重新登入。', 'success');
      resetForm.style.display = 'none';
    } catch (err) {
      common.showMessage(err.message, 'error');
    }
  });
}

// --- 4. App Controller ---

const main = () => {
  common.initializeI18n();

  const pageHandlers = {
    'login-page': handleLoginPage,
    'register-page': handleRegisterPage,
    'forgot-password-page': handleForgotPage,
    'reset-password-page': handleResetPasswordPage
  };

  const bodyId = document.body.id;
  const handler = pageHandlers[bodyId];

  if (handler) {
    handler();
  } else {
    console.log(`No specific logic for page with body ID: "${bodyId}"`);
  }
};

document.addEventListener('DOMContentLoaded', main);