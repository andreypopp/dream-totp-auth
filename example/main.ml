module Page = struct
  let spf = Printf.sprintf

  let chrome req content =
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
    match user.User.totp with
    | Totp_disabled ->
      let secret = Twostep.TOTP.secret () in
      let qr =
        let appname = "Dream OCaml" in
        let uri =
          spf "otpauth://totp/%s:%s?secret=%s" appname user.User.username secret
        in
        match Qrc.encode uri with
        | Some qr -> qr
        | None -> assert false
      in
      Lwt.return
      @@ spf
           {|
           <h4>Two Factor Authentication: Disabled</h4>
           <form action="/auth/totp/enable" method="POST">
             %s
             <input type="hidden" name="secret" value="%s" />
             %s
             <label>Enter code: <input type="text" name="code" /></label>
             <button type="submit">Enable</button>
           </form>
           |}
           (Dream.csrf_tag req) secret (Qrc.Matrix.to_svg qr)
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
         user.User.username (Dream.csrf_tag req) totp_form

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
         user.User.username (Dream.csrf_tag req)

  let main req =
    let%lwt content =
      match%lwt Auth.auth req with
      | `Auth_none -> content_anonymous req
      | `Auth_awaiting_totp user -> content_awaiting_verification user req
      | `Auth_ok user -> content_authenticated user req
    in
    chrome req content
end

type handler_result = (string option, string) Lwt_result.t
(** Form handlers return either an optional message in case of a success or an
    error message in case of an error. *)

(** We use [response_of_result] to convert [handler_result] into
    [Dream.response]. *)
let response_of_result req result =
  let%lwt () =
    match%lwt result with
    | Ok msg ->
      Option.iter (Dream.add_flash_message req "success") msg;
      Lwt.return ()
    | Error msg ->
      Dream.add_flash_message req "error" msg;
      Lwt.return ()
  in
  Dream.redirect req "/"

(** Register form handlers creates a new user account. *)
let register req =
  let open Lwt_result.Infix in
  let form =
    Form.(
      let+ username = field "username"
      and+ password = field "password"
      and+ confirm_password = field "confirm_password" in
      if String.equal password confirm_password then
        Ok (username, password)
      else
        Error "passwords do not match")
  in
  response_of_result req
    ( Form.validate form req >>= fun (username, password) ->
      Auth.register ~username ~password req >>= fun _user ->
      Lwt.return_ok (Some "Registered!") )

(** Login form handler checks user's password and transition authentication
    state. *)
let login req =
  let open Lwt_result.Infix in
  let form =
    Form.(
      let+ username = field "username"
      and+ password = field "password" in
      Ok (username, password))
  in
  response_of_result req
    ( Form.validate form req >>= fun (username, password) ->
      match%lwt Auth.login ~username ~password req with
      | `Auth_none -> Lwt.return_error "incorrect username or password"
      | `Auth_awaiting_totp _ | `Auth_ok _ -> Lwt.return_ok None )

let login_verify req =
  let open Lwt_result.Infix in
  response_of_result req
    ( Form.validate (Form.field "code") req >>= fun totp ->
      match%lwt Auth.verify_login req ~totp with
      | `Auth_ok _ -> Lwt.return_ok None
      | `Auth_none -> Lwt.return_error "something gone wrong, please try again"
      | `Auth_awaiting_totp _ -> Lwt.return_error "invalid TOTP" )

let totp_enable user req =
  let open Lwt_result.Infix in
  let form =
    Form.(
      let+ code = field "code"
      and+ secret = field "secret" in
      Ok (code, secret))
  in
  response_of_result req
    ( Form.validate form req >>= fun (totp, secret) ->
      let user = { user with User.totp = Totp_enabled { secret } } in
      if User.verify_totp user ~totp then
        let%lwt () = User_repo.store user in
        Lwt.return_ok (Some "Two Factor Authentication enabled!")
      else
        Lwt.return_error "Invalid TOTP" )

let totp_disable user req =
  let open Lwt_result.Infix in
  response_of_result req
    ( Form.validate (Form.field "code") req >>= fun totp ->
      if User.verify_totp user ~totp then
        let%lwt () = User_repo.store { user with User.totp = Totp_disabled } in
        Lwt.return_ok (Some "Two Factor Authentication disabled!")
      else
        Lwt.return_error "invalid TOTP" )

let logout _user req =
  let open Lwt_result.Infix in
  response_of_result req
    ( Form.validate Form.empty req >>= fun () ->
      let%lwt () = Auth.logout req in
      Lwt.return_ok None )

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
         Dream.get "/" Page.main;
         Dream.post "/auth/login" login;
         Dream.post "/auth/login/verify" login_verify;
         Dream.post "/auth/register" register;
         Dream.post "/auth/totp/enable" (Auth.with_user totp_enable);
         Dream.post "/auth/totp/disable" (Auth.with_user totp_disable);
         Dream.post "/auth/logout" (Auth.with_user logout);
       ]
