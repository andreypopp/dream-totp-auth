# dream-totp-auth

An example [Dream][] app with password + TOTP + email OTP auth:

- [argon2][] is used for password hashing
- [twostep][] is used for TOTP (secret generation and verification)
- [qrc][] is used for generating QR codes out for Authy, Google Authenticator

Few notes:

- The app is a toy example:

  - No real email interactions - the OTP codes are simply printed on terminal.
    It's up to a real application to decide how to send emails.

  - No persistent storage and no proper abstraction for it. I've just
    consolidated the API for persistent storage and expected data types in
    `Data` module but all other code use it directly.

- User registration process asks for username, email and password:

  - After initial registration form user is asked to confirm email by entering an
    OTP (One Time Password) sent to the email (note that just prints OTP on the
    terminal, it doesn't send anything)

  - If the process is interrupted then user will be presented with email
    verification prompt on the next login.

- Once user is registered and confirmed their email it's possible to enable TOTP
  (Time-based One Time password, to be used with Google Authenticator/Authy/...).

  - Enabling TOTP requires user to scan QR code with freshly generated TOTP secret
    and enter password and TOTP.

  - Disabling TOTP requires user to enter password and TOTP.

  - The TOTP secret is stored encrypted with user's password. Therefore it is not
    possible to verify TOTP code without providing user's password.

  - Because of that password requirement the little piece of JS is used (see
    `public/app.js`) to improve the UX: on login the form is submitted with JS
    and based on the response it shows TOTP form with password value pre-filled
    (from the previous step).

- There's also "Login with email" avaialable:

  - Only users with previously confirmed email are allowed to use this flow.

  - After user enters their username an new OTP code generated and sent to the
    user's email (again, in this demo app it's printed on the terminal).

  - Email OTP is bound to the current session (OTP is a Dream's CSRF token), so
    it's not possible to initiate the process on one user agent and complete on
    the other.

  - Note that "Login with email" won't prompt for TOTP even if it's enabled for
    the user. This is because TOTP requires password (rememeber that TOTP secret
    is stored encrypted with user's password) and that requirements will ruin
    "Login with email" flow. Alternatively we can disallow "Login with email"
    for those users with TOTP enabled.

Trying out:

- Make sure [opam][] is installed
- Run `make init` to initialize a new local opam switch and install all
  dependencies
- Run `make start` to start the app

[Dream]: https://aantron.github.io/dream/
[argon2]: https://github.com/Khady/ocaml-argon2
[twostep]: https://github.com/marcoonroad/twostep
[qrc]: https://github.com/dbuenzli/qrc
[opam]: https://opam.ocaml.org
