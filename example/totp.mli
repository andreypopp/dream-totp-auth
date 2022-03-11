val secret_to_svg : appname:string -> username:string -> string -> string
(** Produce a QR code encoded as svg string. *)

val make_secret : unit -> string
(** Make new secret. *)

val verify : id:string -> totp:string -> string -> bool Lwt.t
(** Verify TOTP against secret. *)
