type t = {
  username : string;
  password_hash : string;
  totp_secret_cipher : string option;
}
(** This type represents user accounts. *)

val make : username:string -> password:string -> unit -> t
val verify_password : password:string -> t -> bool
val verify_totp : password:string -> totp:string -> t -> bool Lwt.t
val set_totp_secret : password:string -> secret:string option -> t -> t
