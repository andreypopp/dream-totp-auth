function flash(category, text) {
  let messages = document.getElementById('messages');
  messages.innerHTML = `<p class="flash-${category}">${category}: ${text}</p>`;
}

function flashClear() {
  let messages = document.getElementById('messages');
  messages.innerHTML = '';
}

function submit(form) {
  let body = new URLSearchParams(new FormData(form));
  return fetch(form.action, { method: form.method, body });
}

function startAuthFlow() {
  let login = document.getElementById('login');
  let register = document.getElementById('register');
  let verifyTotp = document.getElementById('verify-totp');
  let verifyEmail = document.getElementById('verify-email');

  function transitionVerifyTotp(password) {
    flashClear();
    verifyTotp.querySelector('input[name="password"]').value = password;
    login.style.display = 'none';
    register.style.display = 'none';
    verifyTotp.style.display = 'block';
    verifyEmail.style.display = 'none';
  }

  function transitionVerifyEmail() {
    flashClear();
    login.style.display = 'none';
    register.style.display = 'none';
    verifyTotp.style.display = 'none';
    verifyEmail.style.display = 'block';
  }

  function transitionFinal() {
    flashClear();
    window.location.reload();
  }

  login.querySelector('.with-password').onsubmit = (ev) => {
    ev.preventDefault();
    let password = login.querySelector('input[name="password"]').value
    submit(ev.target).then(async resp => {
      if (resp.ok) {
        let status = await resp.text();
        if (status === 'ok') transitionFinal();
        else if (status === 'totp') transitionVerifyTotp(password);
        else if (status === 'email') transitionVerifyEmail();
        else flash('error', `server returned unknown response: ${status}`);
      } else flash('error', await resp.text());
    });
  }

  login.querySelector('.with-email').onsubmit = (ev) => {
    ev.preventDefault();
    submit(ev.target).then(async resp => {
      if (resp.ok) {
        let status = await resp.text();
        if (status === 'email') transitionVerifyEmail();
        else flash('error', `server returned unknown response: ${status}`);
      } else flash('error', await resp.text());
    });
  }

  register.querySelector('form').onsubmit = (ev) => {
    ev.preventDefault();
    submit(ev.target).then(async resp => {
      if (resp.ok) {
        let status = await resp.text();
        if (status === 'email') transitionVerifyEmail();
        else flash('error', `server returned unknown response: ${status}`);
      } else flash('error', await resp.text());
    });
  }

  verifyTotp.querySelector('form').onsubmit = (ev) => {
    ev.preventDefault();
    submit(ev.target).then(async resp => {
      if (resp.ok) transitionFinal();
      else flash('error', await resp.text());
    });
  };

  verifyEmail.querySelector('.verify').onsubmit = (ev) => {
    ev.preventDefault();
    submit(ev.target).then(async resp => {
      if (resp.ok) transitionFinal();
      else flash('error', await resp.text());
    });
  };

  verifyEmail.querySelector('.resend').onsubmit = (ev) => {
    ev.preventDefault();
    submit(ev.target).then(async resp => {
      if (resp.ok) flash('success', 'Check your email');
      else flash('error', await resp.text());
    });
  };
}
