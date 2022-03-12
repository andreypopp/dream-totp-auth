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

  function transitionVerifyTotp(username, password) {
    flashClear();
    verifyTotp.querySelector('input[name="username"]').value = username;
    verifyTotp.querySelector('input[name="password"]').value = password;
    login.style.display = 'none';
    register.style.display = 'none';
    verifyTotp.style.display = 'block';
    verifyEmail.style.display = 'none';
  }

  function transitionVerifyEmail(username, password) {
    flashClear();
    verifyEmail.querySelector('form.verify input[name="username"]').value = username;
    verifyEmail.querySelector('form.resend input[name="username"]').value = username;
    if (password != null) {
      verifyEmail.querySelector('form.verify input[name="password"]').value = password;
      verifyEmail.querySelector('form.resend input[name="password"]').value = password;
    }
    login.style.display = 'none';
    register.style.display = 'none';
    verifyTotp.style.display = 'none';
    verifyEmail.style.display = 'block';
  }

  function transitionFinal() {
    flashClear();
    window.location.reload();
  }

  login.querySelector('form.with-password').onsubmit = (ev) => {
    ev.preventDefault();
    let username = ev.target.querySelector('input[name="username"]').value
    let password = ev.target.querySelector('input[name="password"]').value
    submit(ev.target).then(async resp => {
      if (resp.ok) {
        let status = await resp.text();
        if (status === 'ok') transitionFinal();
        else if (status === 'totp') transitionVerifyTotp(username, password);
        else if (status === 'email') transitionVerifyEmail(username, password);
        else flash('error', `server returned unknown response: ${status}`);
      } else flash('error', await resp.text());
    });
  }

  login.querySelector('form.with-email').onsubmit = (ev) => {
    ev.preventDefault();
    let username = ev.target.querySelector('input[name="username"]').value
    submit(ev.target).then(async resp => {
      if (resp.ok) {
        let status = await resp.text();
        if (status === 'email') transitionVerifyEmail(username);
        else flash('error', `server returned unknown response: ${status}`);
      } else flash('error', await resp.text());
    });
  }

  register.querySelector('form').onsubmit = (ev) => {
    ev.preventDefault();
    let username = ev.target.querySelector('input[name="username"]').value
    let password = ev.target.querySelector('input[name="password"]').value
    submit(ev.target).then(async resp => {
      if (resp.ok) {
        let status = await resp.text();
        if (status === 'email') transitionVerifyEmail(username, password);
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

  verifyEmail.querySelector('form.verify').onsubmit = (ev) => {
    ev.preventDefault();
    submit(ev.target).then(async resp => {
      if (resp.ok) transitionFinal();
      else flash('error', await resp.text());
    });
  };

  verifyEmail.querySelector('form.resend').onsubmit = (ev) => {
    ev.preventDefault();
    submit(ev.target).then(async resp => {
      if (resp.ok) return;
      else flash('error', await resp.text());
    });
  };
}
