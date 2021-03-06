let make ~username ~email ~password () =
  let password_hash = Password.hash password in
  {
    Data.user_name = username;
    user_password_hash = password_hash;
    user_email = email;
    user_email_verification = Email_unconfirmed;
    user_totp_secret_cipher = None;
  }

let verify_password ~password user =
  Password.verify ~hash:user.Data.user_password_hash password

let verify_email_otp ~otp user =
  match%lwt Data.Email_otp.find user.Data.user_email with
  | None -> Lwt.return false
  | Some { email_otp = None; _ } -> Lwt.return false
  | Some ({ email_otp = Some email_otp; _ } as record) ->
    if String.equal otp email_otp then
      let%lwt () = Data.Email_otp.store { record with Data.email_otp = None } in
      Lwt.return true
    else
      Lwt.return false

let verify_totp ~password ~totp user =
  match user.Data.user_totp_secret_cipher with
  | None ->
    (* The reasoning here is that if user has no TOTP enabled then we cannot
       verify any TOTP code. *)
    Lwt.return false
  | Some secret_cipher -> (
    match
      Dream__cipher.Cipher.AEAD_AES_256_GCM.decrypt ~secret:password
        secret_cipher
    with
    | None -> Lwt.return false
    | Some secret -> Totp.verify secret ~totp ~username:user.Data.user_name)

let set_totp_secret ~password ~secret user =
  let user_totp_secret_cipher =
    Option.map
      (Dream__cipher.Cipher.AEAD_AES_256_GCM.encrypt ~secret:password)
      secret
  in
  { user with Data.user_totp_secret_cipher }
