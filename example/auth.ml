module Auth_state : sig
  (** Authentication state stored in session. Note that [Auth_state_ok] and
      [Auth_state_awaiting_totp] should be validated further for the present of
      a user account in a repository. *)

  type t =
    | Auth_state_none
    | Auth_state_ok of string
    | Auth_state_awaiting_totp of string

  val get : Dream.request -> t
  val set : Dream.request -> t -> unit Lwt.t
  val drop : Dream.request -> unit Lwt.t
end = struct
  type t =
    | Auth_state_none
    | Auth_state_ok of string
    | Auth_state_awaiting_totp of string

  let t_of_yojson = function
    | `Assoc [("type", `String "Auth_state_none")] -> Auth_state_none
    | `Assoc [("type", `String "Auth_state_ok"); ("user", `String user)] ->
      Auth_state_ok user
    | `Assoc
        [("type", `String "Auth_state_awaiting_totp"); ("user", `String user)]
      -> Auth_state_awaiting_totp user
    | _ -> failwith "Auth_state.t_of_yojson"

  let yojson_of_t = function
    | Auth_state_none -> `Assoc [("type", `String "Auth_state_none")]
    | Auth_state_ok user ->
      `Assoc [("type", `String "Auth_state_ok"); ("user", `String user)]
    | Auth_state_awaiting_totp user ->
      `Assoc
        [("type", `String "Auth_state_awaiting_totp"); ("user", `String user)]

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

let register ?(login = false) ~username ~password req =
  match%lwt User_repo.find username with
  | Some _ -> Lwt.return_error "username is not available"
  | None ->
    let user = User.make ~username ~password () in
    let%lwt () = User_repo.store user in
    let%lwt () =
      if login then
        Auth_state.set req (Auth_state_ok username)
      else
        Lwt.return ()
    in
    Lwt.return_ok user

type auth_result =
  [ `Auth_awaiting_totp of User.t
  | `Auth_none
  | `Auth_ok of User.t ]

let auth req : auth_result Lwt.t =
  match Auth_state.get req with
  | Auth_state_none -> Lwt.return `Auth_none
  | Auth_state_ok username -> (
    match%lwt User_repo.find username with
    | None -> Lwt.return `Auth_none
    | Some user -> Lwt.return (`Auth_ok user))
  | Auth_state_awaiting_totp username -> (
    match%lwt User_repo.find username with
    | None -> Lwt.return `Auth_none
    | Some user -> Lwt.return (`Auth_awaiting_totp user))

let login ~username ~password req =
  match%lwt User_repo.find username with
  | None -> Lwt.return `Auth_none
  | Some user -> (
    match User.verify_password user ~password with
    | true ->
      let auth, result =
        match user.totp with
        | Totp_enabled _ ->
          ( Auth_state.Auth_state_awaiting_totp username,
            `Auth_awaiting_totp user )
        | Totp_disabled -> (Auth_state_ok username, `Auth_ok user)
      in
      let%lwt () = Auth_state.set req auth in
      Lwt.return result
    | false -> Lwt.return `Auth_none)

let verify_login ~totp req =
  match%lwt auth req with
  | `Auth_awaiting_totp user ->
    if User.verify_totp user ~totp then
      let%lwt () = Auth_state.set req (Auth_state_ok user.User.username) in
      Lwt.return (`Auth_ok user)
    else
      Lwt.return (`Auth_awaiting_totp user)
  | (`Auth_none | `Auth_ok _) as auth -> Lwt.return auth

let logout req = Auth_state.drop req

let user req =
  match%lwt auth req with
  | `Auth_ok user -> Lwt.return_some user
  | `Auth_awaiting_totp _ | `Auth_none -> Lwt.return_none

let with_user handler req =
  match%lwt user req with
  | None -> Dream.respond ~status:`Forbidden "access denied"
  | Some user -> handler user req
