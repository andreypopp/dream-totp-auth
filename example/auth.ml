module Auth_state : sig
  (** Authentication state stored in session. Note that [Auth_state_ok],
      [Auth_state_awaiting_totp] and [Auth_state_awaiting_email_otp] should be
      validated further for the present of a user account in a repository. *)

  type t = string option

  val get : Dream.request -> t
  val set : Dream.request -> t -> unit Lwt.t
end = struct
  type t = string option

  let t_of_yojson = function
    | `Null -> None
    | `String username -> Some username
    | _ -> failwith "Auth_state.t_of_yojson"

  let yojson_of_t = function
    | None -> `Null
    | Some username -> `String username

  let session_field = "auth"

  let get req =
    match Dream.session_field req session_field with
    | None -> None
    | Some data -> (
      match Yojson.Basic.from_string data with
      | exception Yojson.Json_error _ -> None
      | json -> (
        match t_of_yojson json with
        | auth -> auth
        | exception Failure _ -> None))

  let set req auth =
    let value = Yojson.Basic.to_string (yojson_of_t auth) in
    Dream.set_session_field req session_field value
end

let user req : Data.user option Lwt.t =
  match Auth_state.get req with
  | None -> Lwt.return None
  | Some username -> (
    match%lwt Data.Users.find username with
    | None -> Lwt.return None
    | Some user -> Lwt.return (Some user))

let with_user handler req =
  match%lwt user req with
  | None -> Dream.respond ~status:`Forbidden "access denied"
  | Some user -> handler user req

type registration = {
  registration_user : Data.user;
  registration_email_otp : string;
}

let register ~username ~email ~password req =
  Data.Users.transaction (fun () ->
      match%lwt Data.Users.find username with
      | Some _ -> Lwt.return_error "username is not available"
      | None ->
        let user = User.make ~username ~email ~password () in
        let%lwt () = Data.Users.store user in
        let email_otp = Dream.csrf_token req in
        let%lwt () =
          Data.Email_otp.store
            { email_otp_email = email; email_otp = Some email_otp }
        in
        Lwt.return_ok
          { registration_user = user; registration_email_otp = email_otp })

let authenticate user req =
  let%lwt () = Auth_state.set req (Some user.Data.user_name) in
  Lwt.return_some (`User_authenticated user)

type verify_password_transition =
  [ `User_awaiting_totp of Data.user
  | `User_awaiting_email_otp of Data.user
  | `User_authenticated of Data.user ]

let verify_password ~username ~password req :
    verify_password_transition option Lwt.t =
  match%lwt Data.Users.find username with
  | None -> Lwt.return_none
  | Some user ->
    if User.verify_password user ~password then
      match (user.user_email_verification, user.user_totp_secret_cipher) with
      | Email_unconfirmed, _ -> Lwt.return_some (`User_awaiting_email_otp user)
      | Email_confirmed, Some _ -> Lwt.return_some (`User_awaiting_totp user)
      | Email_confirmed, None -> authenticate user req
    else
      Lwt.return_none

type verify_email_otp_transition = [`User_authenticated of Data.user]

let verify_email_otp ~username ~password ~otp req :
    verify_email_otp_transition option Lwt.t =
  match%lwt Data.Users.find username with
  | Some user -> (
    match%lwt Dream.verify_csrf_token req otp with
    | `Ok -> (
      match (user.Data.user_email_verification, password) with
      | Email_confirmed, _ ->
        if%lwt User.verify_email_otp user ~otp then
          authenticate user req
        else
          Lwt.return_none
      | Email_unconfirmed, None -> Lwt.return_none
      | Email_unconfirmed, Some password ->
        if User.verify_password user ~password then
          if%lwt User.verify_email_otp user ~otp then
            let%lwt user =
              match user.Data.user_email_verification with
              | Email_confirmed -> Lwt.return user
              | Email_unconfirmed ->
                let user =
                  { user with Data.user_email_verification = Email_confirmed }
                in
                let%lwt () = Data.Users.store user in
                Lwt.return user
            in
            authenticate user req
          else
            Lwt.return_none
        else
          Lwt.return_none)
    | `Expired _ | `Wrong_session | `Invalid -> Lwt.return_none)
  | None -> Lwt.return_none

type verify_totp_transition = [`User_authenticated of Data.user]

let verify_totp ~username ~password ~totp req :
    verify_totp_transition option Lwt.t =
  match%lwt verify_password ~username ~password req with
  | Some (`User_authenticated user) | Some (`User_awaiting_totp user) ->
    if%lwt User.verify_totp user ~password ~totp then
      authenticate user req
    else
      Lwt.return_none
  | Some (`User_awaiting_email_otp _) -> Lwt.return_none
  | None -> Lwt.return_none

let totp_enable ~password ~totp ~secret user =
  if User.verify_password user ~password then
    let user = User.set_totp_secret user ~password ~secret:(Some secret) in
    if%lwt User.verify_totp user ~password ~totp then
      let%lwt () = Data.Users.store user in
      Lwt.return_ok ()
    else
      Lwt.return_error "Invalid TOTP"
  else
    Lwt.return_error "Invalid password"

let totp_disable ~password ~totp user =
  if User.verify_password user ~password then
    if%lwt User.verify_totp user ~password ~totp then
      let user = User.set_totp_secret user ~password ~secret:None in
      let%lwt () = Data.Users.store user in
      Lwt.return_ok ()
    else
      Lwt.return_error "Invalid TOTP"
  else
    Lwt.return_error "Invalid password"

let email_otp ~username ~password req =
  match%lwt Data.Users.find username with
  | Some user -> (
    let make_otp () =
      let otp = Dream.csrf_token req in
      let%lwt () =
        Data.Email_otp.store
          { email_otp_email = user.Data.user_email; email_otp = Some otp }
      in
      Lwt.return otp
    in
    match (user.user_email_verification, password) with
    | Email_confirmed, _ ->
      let%lwt otp = make_otp () in
      Lwt.return_some otp
    | Email_unconfirmed, Some password ->
      if User.verify_password user ~password then
        let%lwt otp = make_otp () in
        Lwt.return_some otp
      else
        Lwt.return_none
    | Email_unconfirmed, None -> Lwt.return_none)
  | None -> Lwt.return_none

let logout req = Auth_state.set req None
