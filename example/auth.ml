module Auth_state : sig
  (** Authentication state stored in session. Note that [Auth_state_ok],
      [Auth_state_awaiting_totp] and [Auth_state_awaiting_email_otp] should be
      validated further for the present of a user account in a repository. *)

  type t =
    | Auth_state_none
    | Auth_state_ok of string
    | Auth_state_awaiting_email_otp of string
    | Auth_state_awaiting_totp of string

  val get : Dream.request -> t
  val set : Dream.request -> t -> unit Lwt.t
  val drop : Dream.request -> unit Lwt.t
end = struct
  type t =
    | Auth_state_none
    | Auth_state_ok of string
    | Auth_state_awaiting_email_otp of string
    | Auth_state_awaiting_totp of string

  let t_of_yojson = function
    | `Assoc [("type", `String "Auth_state_none")] -> Auth_state_none
    | `Assoc [("type", `String "Auth_state_ok"); ("user", `String user)] ->
      Auth_state_ok user
    | `Assoc
        [("type", `String "Auth_state_awaiting_totp"); ("user", `String user)]
      -> Auth_state_awaiting_totp user
    | `Assoc
        [
          ("type", `String "Auth_state_awaiting_email_otp");
          ("user", `String user);
        ] -> Auth_state_awaiting_email_otp user
    | _ -> failwith "Auth_state.t_of_yojson"

  let yojson_of_t = function
    | Auth_state_none -> `Assoc [("type", `String "Auth_state_none")]
    | Auth_state_ok user ->
      `Assoc [("type", `String "Auth_state_ok"); ("user", `String user)]
    | Auth_state_awaiting_totp user ->
      `Assoc
        [("type", `String "Auth_state_awaiting_totp"); ("user", `String user)]
    | Auth_state_awaiting_email_otp user ->
      `Assoc
        [
          ("type", `String "Auth_state_awaiting_email_otp");
          ("user", `String user);
        ]

  let session_field = "auth"

  let get req =
    match Dream.session_field req session_field with
    | None -> Auth_state_none
    | Some data -> (
      match Yojson.Basic.from_string data with
      | exception Yojson.Json_error _ -> Auth_state_none
      | json -> (
        match t_of_yojson json with
        | auth -> auth
        | exception Failure _ -> Auth_state_none))

  let set req auth =
    let value = Yojson.Basic.to_string (yojson_of_t auth) in
    Dream.set_session_field req session_field value

  let drop req =
    let value = Yojson.Basic.to_string `Null in
    Dream.set_session_field req session_field value
end

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
        let email_otp_code = Dream.csrf_token req in
        let email_otp = { Data.email_otp_email = email; email_otp_code } in
        let%lwt () = Data.Email_otp.store email_otp in
        let%lwt () =
          Auth_state.set req (Auth_state_awaiting_email_otp username)
        in
        Lwt.return_ok
          { registration_user = user; registration_email_otp = email_otp_code })

type auth_result =
  [ `User_anonymous
  | `User_awaiting_totp of Data.user
  | `User_awaiting_email_otp of Data.user
  | `User_authenticated of Data.user ]

let auth req : auth_result Lwt.t =
  match Auth_state.get req with
  | Auth_state_none -> Lwt.return `User_anonymous
  | Auth_state_ok username -> (
    match%lwt Data.Users.find username with
    | None -> Lwt.return `User_anonymous
    | Some user -> Lwt.return (`User_authenticated user))
  | Auth_state_awaiting_totp username -> (
    match%lwt Data.Users.find username with
    | None -> Lwt.return `User_anonymous
    | Some user -> Lwt.return (`User_awaiting_totp user))
  | Auth_state_awaiting_email_otp username -> (
    match%lwt Data.Users.find username with
    | None -> Lwt.return `User_anonymous
    | Some user -> Lwt.return (`User_awaiting_email_otp user))

let user req =
  match%lwt auth req with
  | `User_authenticated user -> Lwt.return_some user
  | `User_awaiting_totp _ | `User_awaiting_email_otp _ | `User_anonymous ->
    Lwt.return_none

let with_user handler req =
  match%lwt user req with
  | None -> Dream.respond ~status:`Forbidden "access denied"
  | Some user -> handler user req

let login_verification user =
  match (user.Data.user_email_verification, user.user_totp_secret_cipher) with
  | Data.Email_unconfirmed, _ ->
    ( Auth_state.Auth_state_awaiting_email_otp user.user_name,
      `User_awaiting_email_otp user )
  | Data.Email_confirmed, Some _ ->
    ( Auth_state.Auth_state_awaiting_totp user.user_name,
      `User_awaiting_totp user )
  | _, _ -> (Auth_state_ok user.user_name, `User_authenticated user)

let login ~username ~password req =
  match%lwt Data.Users.find username with
  | None -> Lwt.return `User_anonymous
  | Some user -> (
    match User.verify_password user ~password with
    | true ->
      let auth, result = login_verification user in
      let%lwt () = Auth_state.set req auth in
      Lwt.return result
    | false -> Lwt.return `User_anonymous)

let verify_totp ~password ~totp req =
  let%lwt cur_auth = auth req in
  match cur_auth with
  | `User_awaiting_totp user ->
    if%lwt User.verify_totp user ~password ~totp then
      let%lwt () = Auth_state.set req (Auth_state_ok user.Data.user_name) in
      Lwt.return (`User_authenticated user)
    else
      Lwt.return cur_auth
  | `User_awaiting_email_otp _ | `User_anonymous | `User_authenticated _ ->
    Lwt.return cur_auth

let verify_email_otp ~otp req =
  let%lwt cur_auth = auth req in
  match cur_auth with
  | `User_awaiting_email_otp user -> (
    match%lwt Dream.verify_csrf_token req otp with
    | `Ok -> (
      match%lwt Data.Email_otp.find user.Data.user_email with
      | None -> Lwt.return cur_auth
      | Some email_otp ->
        if String.equal email_otp.Data.email_otp_code otp then
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
          let auth, result = login_verification user in
          let%lwt () = Auth_state.set req auth in
          Lwt.return result
        else
          Lwt.return cur_auth)
    | `Expired _ | `Wrong_session | `Invalid -> Lwt.return cur_auth)
  | `User_awaiting_totp _ | `User_anonymous | `User_authenticated _ ->
    Lwt.return cur_auth

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

let refresh_email_otp' user req =
  let email_otp_code = Dream.csrf_token req in
  let%lwt () =
    Data.Email_otp.store
      { email_otp_email = user.Data.user_email; email_otp_code }
  in
  Lwt.return email_otp_code

let login_with_email_otp ~username req =
  match%lwt Data.Users.find username with
  | None -> Lwt.return_none
  | Some user -> (
    match user.Data.user_email_verification with
    | Email_unconfirmed -> Lwt.return_none
    | Email_confirmed ->
      let%lwt otp = refresh_email_otp' user req in
      let%lwt () =
        Auth_state.set req (Auth_state_awaiting_email_otp username)
      in
      Lwt.return_some otp)

let refresh_email_otp req =
  match%lwt user req with
  | Some user ->
    let%lwt otp = refresh_email_otp' user req in
    Lwt.return_some otp
  | None -> Lwt.return_none

let logout req = Auth_state.drop req
