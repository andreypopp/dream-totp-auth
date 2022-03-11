type t = {
  username : string;
  password_hash : string;
  totp : totp;
}
(** This type represents user accounts. *)

and totp =
  | Totp_disabled
  | Totp_enabled of Totp.secret

val make : username:string -> password:string -> unit -> t
val verify_password : password:string -> t -> bool
val verify_totp : totp:string -> t -> bool Lwt.t
