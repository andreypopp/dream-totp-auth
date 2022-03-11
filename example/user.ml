type t = {
  username : string;
  password_hash : string;
  totp_secret_cipher : string option;
}

let make ~username ~password () =
  let password_hash = Password.hash password in
  { username; password_hash; totp_secret_cipher = None }

let verify_password ~password user =
  Password.verify ~hash:user.password_hash password

let verify_totp ~password ~totp user =
  match user.totp_secret_cipher with
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
    | Some secret -> Totp.verify secret ~totp ~id:user.username)

let set_totp_secret ~password ~secret user =
  let totp_secret_cipher =
    Option.map
      (Dream__cipher.Cipher.AEAD_AES_256_GCM.encrypt ~secret:password)
      secret
  in
  { user with totp_secret_cipher }
