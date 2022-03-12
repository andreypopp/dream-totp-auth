# dream-totp-auth

An example [Dream][] app with password + TOTP + email OTP auth:

- [argon2][] is used for password hashing
- [twostep][] is used for TOTP (secret generation and verification)
- [qrc][] is used for generating QR codes out for Authy

[Dream]: https://aantron.github.io/dream/
[argon2]: https://github.com/Khady/ocaml-argon2
[twostep]: https://github.com/marcoonroad/twostep
[qrc]: https://github.com/dbuenzli/qrc
