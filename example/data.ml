module type RECORD = sig
  type t

  val id : t -> string
end

module type REPO = sig
  type t

  val find : string -> t option Lwt.t
  val store : t -> unit Lwt.t
  val transaction : (unit -> 'a Lwt.t) -> 'a Lwt.t
end

module Repo (Record : RECORD) () : REPO with type t = Record.t = struct
  module String_map = Map.Make (String)

  type t = Record.t

  let repo : Record.t String_map.t ref = ref String_map.empty
  let find id = Lwt.return (String_map.find_opt id !repo)

  let store record =
    repo := String_map.add (Record.id record) record !repo;
    Lwt.return ()

  let lock = Lwt_mutex.create ()

  let transaction f =
    Lwt_mutex.with_lock lock (fun () ->
        let snapshot = !repo in
        try%lwt f ()
        with exn ->
          repo := snapshot;
          Lwt.fail exn)
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

module Users =
  Repo
    (struct
      type t = user

      let id user = user.user_name
    end)
    ()

type email_otp = {
  email_otp_email : string;
  email_otp_code : string;
}

module Email_otp =
  Repo
    (struct
      type t = email_otp

      let id otp = otp.email_otp_email
    end)
    ()

type totp = {
  totp_username : string;
  totp_code : (string * float) list;
}

module Totp =
  Repo
    (struct
      type t = totp

      let id v = v.totp_username
    end)
    ()

let () =
  Lwt_main.run
  @@ Users.store
       {
         user_name = "user";
         user_password_hash = Password.hash "password";
         user_totp_secret_cipher = None;
         user_email = "user@example.com";
         user_email_verification = Email_confirmed;
       }
