type t = {
  username : string;
  password_hash : string;
  totp : totp;
}

and totp =
  | Totp_disabled
  | Totp_enabled of Totp.secret

let make ~username ~password () =
  let password_hash = Password.hash password in
  { username; password_hash; totp = Totp_disabled }

let verify_password ~password user =
  Password.verify ~hash:user.password_hash password

let verify_totp ~totp user =
  match user.totp with
  | Totp_disabled ->
    (* The reasoning here is that if user has no TOTP enabled then we cannot
       verify any TOTP code. *)
    Lwt.return false
  | Totp_enabled secret -> Totp.verify secret ~totp ~id:user.username
