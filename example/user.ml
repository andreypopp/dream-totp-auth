type t = {
  username : string;
  password_hash : string;
  totp : totp;
}

and totp =
  | Totp_disabled
  | Totp_enabled of { secret : string }

let make ~username ~password () =
  let password_hash =
    match Password.hash password with
    | Ok password_hash -> password_hash
    | Error err -> failwith err
  in
  { username; password_hash; totp = Totp_disabled }

let verify_password ~password user =
  match Password.verify ~hash:user.password_hash password with
  | Ok ok -> ok
  | Error err -> failwith err

let verify_totp ~totp user =
  match user.totp with
  | Totp_disabled ->
    (* The reasoning here is that if user has no TOTP enabled then we cannot
       verify any TOTP code. *)
    false
  | Totp_enabled { secret } -> Twostep.TOTP.verify ~secret ~code:totp ()
