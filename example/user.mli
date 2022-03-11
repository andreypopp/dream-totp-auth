type t = {
  username : string;
  password_hash : string;
  totp : totp;
}

and totp =
  | Totp_disabled
  | Totp_enabled of { secret : string }

val make : username:string -> password:string -> unit -> t
val verify_password : password:string -> t -> bool
val verify_totp : totp:string -> t -> bool
