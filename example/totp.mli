type secret

val secret_to_string : secret -> string
val secret_of_string : string -> secret

val secret_to_svg : appname:string -> username:string -> secret -> string
(** Produce a QR code encoded as svg string. *)

val make_secret : unit -> secret
(** Make new secret. *)

val verify : id:string -> totp:string -> secret -> bool Lwt.t
(** Verify TOTP against secret. *)
