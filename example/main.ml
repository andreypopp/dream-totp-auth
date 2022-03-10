module Auth : sig
  type user = {
    username : string;
    password_hash : string;
    totp : totp;
  }

  and totp =
    | Totp_disabled
    | Totp_enabled of { secret : string }

  val register :
    ?login:bool ->
    username:string ->
    password:string ->
    Dream.request ->
    (user, string) Lwt_result.t

  val logout : Dream.request -> (unit, string) Lwt_result.t
  val verify_totp : user -> string -> bool
  val user : Dream.request -> user option Lwt.t
  val with_user : (user -> Dream.handler) -> Dream.handler
  val update_user : user -> unit Lwt.t

  type auth =
    | Auth_none
    | Auth_awaiting_verification of user
    | Auth_authenticated of user

  val auth : Dream.request -> auth Lwt.t
  val login : username:string -> password:string -> Dream.request -> auth Lwt.t
  val verify_login : Dream.request -> string -> auth Lwt.t
end = struct
  type user = {
    username : string;
    password_hash : string;
    totp : totp;
  }

  and totp =
    | Totp_disabled
    | Totp_enabled of { secret : string }

  type auth =
    | Auth_none
    | Auth_awaiting_verification of user
    | Auth_authenticated of user

  let users =
    let users = Hashtbl.create 10 in
    Hashtbl.add users "user"
      {
        username = "user";
        password_hash =
          "$argon2id$v=19$m=102400,t=2,p=8$cC1Z3vVsyvDjp0PRjW7O7w$1MpRLlSifXJoLGYtkQZywQ";
        totp = Totp_disabled;
      };
    users

  let session_key = "auth"

  let auth req =
    match Dream.session_field req session_key with
    | None | Some "" -> Lwt.return Auth_none
    | Some v ->
      Lwt.return
        (match String.split_on_char '|' v with
        | "Auth_awaiting_verification" :: parts -> (
          let username = String.concat "|" parts in
          match Hashtbl.find_opt users username with
          | None -> Auth_none
          | Some user -> Auth_awaiting_verification user)
        | "Auth_authenticated" :: parts -> (
          let username = String.concat "|" parts in
          match Hashtbl.find_opt users username with
          | None -> Auth_none
          | Some user -> Auth_authenticated user)
        | _ -> Auth_none)

  let set_auth req auth =
    let value =
      match auth with
      | Auth_none -> ""
      | Auth_authenticated user -> "Auth_authenticated|" ^ user.username
      | Auth_awaiting_verification user ->
        "Auth_awaiting_verification|" ^ user.username
    in
    Dream.set_session_field req session_key value

  let register ?(login = false) ~username ~password req =
    match Hashtbl.find_opt users username with
    | Some _ -> Lwt.return_error "username is not available"
    | None -> (
      match Password.hash password with
      | Error _ -> Lwt.return_error "unable to register"
      | Ok password_hash ->
        print_endline password_hash;
        let user = { username; password_hash; totp = Totp_disabled } in
        Hashtbl.add users username user;
        let%lwt () =
          if login then
            Dream.set_session_field req session_key username
          else
            Lwt.return ()
        in
        Lwt.return_ok user)

  let login ~username ~password req =
    match Hashtbl.find_opt users username with
    | None -> Lwt.return Auth_none
    | Some user -> (
      match Password.verify ~hash:user.password_hash password with
      | Error _ -> Lwt.return Auth_none
      | Ok true ->
        let auth =
          match user.totp with
          | Totp_enabled _ -> Auth_awaiting_verification user
          | Totp_disabled -> Auth_authenticated user
        in
        let%lwt () = set_auth req auth in
        Lwt.return auth
      | Ok false -> Lwt.return Auth_none)

  let logout req =
    let%lwt () = Dream.set_session_field req session_key "" in
    Lwt.return_ok ()

  let user req =
    match%lwt auth req with
    | Auth_authenticated user -> Lwt.return_some user
    | Auth_awaiting_verification _ | Auth_none -> Lwt.return_none

  let verify_totp user code =
    match user.totp with
    | Totp_disabled -> true
    | Totp_enabled { secret } -> Twostep.TOTP.verify ~secret ~code ()

  let verify_login req code =
    match%lwt auth req with
    | Auth_none -> Lwt.return Auth_none
    | Auth_authenticated user -> Lwt.return (Auth_authenticated user)
    | Auth_awaiting_verification user ->
      if verify_totp user code then
        let auth = Auth_authenticated user in
        let%lwt () = set_auth req auth in
        Lwt.return auth
      else
        Lwt.return (Auth_awaiting_verification user)

  let with_user handler req =
    match%lwt user req with
    | None -> Dream.respond ~status:`Forbidden "access denied"
    | Some user -> handler user req

  let update_user user = Lwt.return (Hashtbl.replace users user.username user)
end

module Totp_enable = struct
  let session_key = "totp_secret"

  let new_secret req =
    (* TODO: expiration? *)
    let secret = Twostep.TOTP.secret () in
    let%lwt () = Dream.set_session_field req session_key secret in
    Lwt.return secret

  let verify_code ~code req =
    match Dream.session_field req session_key with
    | None -> Lwt.return_error "invalid verification code"
    | Some secret ->
      if Twostep.TOTP.verify ~code ~secret () then
        let%lwt () = Dream.set_session_field req session_key "" in
        Lwt.return_ok secret
      else
        Lwt.return_error "invalid verification code"
end

module Page_template = struct
  let spf = Printf.sprintf

  let make_page req content =
    let messages =
      Dream.flash_messages req
      |> List.map (fun (category, text) ->
             spf {|<p class="flash-%s">%s: %s</p>|} category category text)
      |> String.concat "\n"
    in
    Dream.respond
    @@ spf
         {|
        <style>
          body {
            font-size: 20px;
            font-family: system;
            font-family: -apple-system, Helvetica, sans-serif;
          }
          label { display: block; }
          .flash-error { color: red; }
          .flash-success { color: green; }
        </style>
        <body>
          <div>%s</div>
          <div>%s</div>
        </body>
      |}
         messages content

  let content_anonymous req =
    Lwt.return
    @@ spf
         {|
    <form action="/auth/login" method="POST">
      %s
      <h3>Login</h3>
      <label>Username: <input type="text" name="username" /></label>
      <label>Password: <input type="password" name="password" /></label>
      <button type="submit">Login</button>
    </form>
    <form action="/auth/register" method="POST">
      %s
      <h3>Register</h3>
      <label>Username: <input type="text" name="username" /></label>
      <label>Password: <input type="password" name="password" /></label>
      <label>Confirm password: <input type="password" name="confirm_password" /></label>
      <button type="submit">Register</button>
    </form>
  |}
         (Dream.csrf_tag req) (Dream.csrf_tag req)

  let totp_form user req =
    match user.Auth.totp with
    | Totp_disabled ->
      let%lwt qr =
        let%lwt secret = Totp_enable.new_secret req in
        let uri =
          spf "otpauth://totp/Dream OCaml: %s?secret=%s" user.Auth.username
            secret
        in
        match Qrc.encode uri with
        | Some qr -> Lwt.return qr
        | None -> assert false
      in
      Lwt.return
      @@ spf
           {|
           <h4>Two Factor Authentication: Disabled</h4>
           <form action="/auth/totp/enable" method="POST">
             %s
             %s
             <label>Enter code: <input type="text" name="code" /></label>
             <button type="submit">Enable</button>
           </form>
           |}
           (Dream.csrf_tag req) (Qrc.Matrix.to_svg qr)
    | Totp_enabled _ ->
      Lwt.return
      @@ spf
           {|
           <h4>Two Factor Authentication: Enabled</h4>
           <form action="/auth/totp/disable" method="POST">
             %s
             <label>Enter code: <input type="text" name="code" /></label>
             <button type="submit">Disable</button>
           </form>
           |}
           (Dream.csrf_tag req)

  let content_authenticated user req =
    let%lwt totp_form = totp_form user req in
    Lwt.return
    @@ spf
         {|
          <h3>Welcome, %s!</h3>
          <form action="/auth/logout" method="POST">
            %s
            <button type="submit">Logout</button>
          </form>
          %s
         |}
         user.Auth.username (Dream.csrf_tag req) totp_form

  let content_awaiting_verification user req =
    Lwt.return
    @@ spf
         {|
         <h3>Welcome, %s!</h3>
         <h4>Please verify login with TOTP</h4>
         <form action="/auth/login/verify" method="POST">
           %s
           <label>Enter code: <input type="text" name="code" /></label>
           <button type="submit">Login</button>
         </form>
         |}
         user.Auth.username (Dream.csrf_tag req)

  let main req =
    let%lwt content =
      match%lwt Auth.auth req with
      | Auth_none -> content_anonymous req
      | Auth_awaiting_verification user ->
        content_awaiting_verification user req
      | Auth_authenticated user -> content_authenticated user req
    in
    make_page req content
end

let login req =
  let open Lwt_result.Infix in
  let result =
    (match%lwt Dream.form req with
    | `Ok fields -> (
      match
        (List.assoc_opt "username" fields, List.assoc_opt "password" fields)
      with
      | Some username, Some password -> Lwt.return_ok (username, password)
      | _ -> Lwt.return_error "incorrect form submission")
    | _ -> Lwt.return_error "invalid form submission")
    >>= fun (username, password) ->
    match%lwt Auth.login ~username ~password req with
    | Auth_none -> Lwt.return_error "incorrect username or password"
    | Auth_authenticated _ | Auth_awaiting_verification _ -> Lwt.return_ok ()
  in
  match%lwt result with
  | Ok () -> Dream.redirect req "/"
  | Error error ->
    Dream.add_flash_message req "error" error;
    Dream.redirect req "/"

let register req =
  let open Lwt_result.Infix in
  let result =
    (match%lwt Dream.form req with
    | `Ok fields -> (
      match
        ( List.assoc_opt "username" fields,
          List.assoc_opt "password" fields,
          List.assoc_opt "confirm_password" fields )
      with
      | Some username, Some password, Some confirm_password ->
        if not (String.equal password confirm_password) then
          Lwt.return_error "passwords do not match"
        else
          Lwt.return_ok (username, password)
      | _ -> Lwt.return_error "incorrect form submission")
    | _ -> Lwt.return_error "invalid form submission")
    >>= fun (username, password) -> Auth.register ~username ~password req
  in
  match%lwt result with
  | Ok _user ->
    Dream.add_flash_message req "success" "Success!";
    Dream.redirect req "/"
  | Error error ->
    Dream.add_flash_message req "error" error;
    Dream.redirect req "/"

let totp_code req =
  match%lwt Dream.form req with
  | `Ok fields -> (
    match List.assoc_opt "code" fields with
    | Some code -> Lwt.return_ok code
    | _ -> Lwt.return_error "missing totp")
  | _ -> Lwt.return_error "invalid form submission"

let login_verify req =
  let open Lwt_result.Infix in
  let result =
    totp_code req >>= fun code ->
    match%lwt Auth.verify_login req code with
    | Auth_none -> Lwt.return_error "something gone wrong, please try again"
    | Auth_authenticated _ -> Lwt.return_ok ()
    | Auth_awaiting_verification _ -> Lwt.return_error "invalid TOTP"
  in
  match%lwt result with
  | Ok () -> Dream.redirect req "/"
  | Error error ->
    Dream.add_flash_message req "error" error;
    Dream.redirect req "/"

let totp_enable user req =
  let open Lwt_result.Infix in
  let result =
    totp_code req >>= fun code -> Totp_enable.verify_code ~code req
  in
  match%lwt result with
  | Ok secret ->
    let%lwt () =
      Auth.update_user { user with Auth.totp = Totp_enabled { secret } }
    in
    Dream.add_flash_message req "success" "Two Factor Authentication enabled!";
    Dream.redirect req "/"
  | Error error ->
    Dream.add_flash_message req "error" error;
    Dream.redirect req "/"

let totp_disable user req =
  let open Lwt_result.Infix in
  let result =
    totp_code req >>= fun code ->
    if Auth.verify_totp user code then
      Lwt.return_ok ()
    else
      Lwt.return_error "invalid TOTP"
  in
  match%lwt result with
  | Ok () ->
    let%lwt () = Auth.update_user { user with Auth.totp = Totp_disabled } in
    Dream.add_flash_message req "success" "Two Factor Authentication enabled!";
    Dream.redirect req "/"
  | Error error ->
    Dream.add_flash_message req "error" error;
    Dream.redirect req "/"

let logout req =
  let open Lwt_result.Infix in
  let result =
    (match%lwt Dream.form req with
    | `Ok _ -> Lwt.return_ok ()
    | _ -> Lwt.return_error "invalid form submission")
    >>= fun () -> Auth.logout req
  in
  match%lwt result with
  | Ok () -> Dream.redirect req "/"
  | Error error ->
    Dream.add_flash_message req "error" error;
    Dream.redirect req "/"

let () =
  let () = Dream.initialize_log ~level:`Debug () in
  let interface =
    Option.value (Sys.getenv_opt "INTERFACE") ~default:"127.0.0.1"
  in
  Dream.run ~tls:false ~adjust_terminal:false ~interface
  @@ Dream.logger
  @@ Dream.memory_sessions
  @@ Dream.flash
  @@ Dream.router
       [
         Dream.get "/" Page_template.main;
         Dream.post "/auth/login" login;
         Dream.post "/auth/login/verify" login_verify;
         Dream.post "/auth/register" register;
         Dream.post "/auth/totp/enable" (Auth.with_user totp_enable);
         Dream.post "/auth/totp/disable" (Auth.with_user totp_disable);
         Dream.post "/auth/logout" logout;
       ]
