(** A repository of user accounts.

    In this example app we store all accounts in memory, but real application
    would want to have this stored in a database or any other persistent
    storage. *)

module type REPO = sig
  type t

  val find : string -> t option Lwt.t
  val store : t -> unit Lwt.t
  val transaction : (unit -> 'a Lwt.t) -> 'a Lwt.t
end

type user = {
  user_name : string;
  user_email : string;
  user_email_verification : email_verification;
  user_password_hash : string;
  user_totp_secret_cipher : string option;
}

and email_verification =
  | Email_confirmed
  | Email_unconfirmed

module Users : REPO with type t = user

type email_otp = {
  email_otp_email : string;
  email_otp_code : string;
}

module Email_otp : REPO with type t = email_otp

type totp = {
  totp_username : string;
  totp_code : (string * float) list;
}

module Totp : REPO with type t = totp
