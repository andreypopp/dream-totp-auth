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
        <script src="/public/app.js"></script>
        <body>
          <div id="messages">%s</div>
          <div>%s</div>
        </body>
      |}
         messages content

  let content_anonymous req =
    Lwt.return
    @@ spf
         {|
          <div id="login">
            <h3 id="title">Login</h3>
            <form class="with-password" action="/auth/login" method="POST">
              %s
              <label>Username: <input type="text" name="username" /></label>
              <label>Password: <input type="password" name="password" /></label>
              <button type="submit">Login</button>
            </form>
            <h3 id="title">Login with email</h3>
            <form class="with-email" action="/auth/login-with-email" method="POST">
              %s
              <label>Username: <input type="text" name="username" /></label>
              <button type="submit">Login with email</button>
            </form>
          </div>
          <div id="verify-totp" style="display: none">
            <h3>Verify one time password</h3>
            <form action="/auth/verify/totp" method="POST">
              %s
              <input type="hidden" name="password" value="" />
              <label>Enter code: <input type="text" name="code" /></label>
              <button type="submit">Login</button>
            </form>
          </div>
          <div id="verify-email" style="display: none">
            <h3>Verify email</h3>
            <form class="verify" action="/auth/verify/email" method="POST">
              %s
              <label>Enter code: <input type="text" name="code" /></label>
              <button type="submit">Login</button>
            </form>
            <form class="resend" action="/auth/verify/email-resend" method="POST">
              %s
              <button type="submit">Resend verification code</button>
            </form>
          </div>
          <hr />
          <div id="register">
            <h3>Register</h3>
            <form action="/auth/register" method="POST">
              %s
              <label>Username: <input type="text" name="username" /></label>
              <label>Email: <input type="text" name="email" /></label>
              <label>Password: <input type="password" name="password" /></label>
              <label>Confirm password: <input type="password" name="confirm_password" /></label>
              <button type="submit">Register</button>
            </form>
          </div>
          <script>
            window.addEventListener('DOMContentLoaded', startAuthFlow);
          </script>
        |}
         (Dream.csrf_tag req) (Dream.csrf_tag req) (Dream.csrf_tag req)
         (Dream.csrf_tag req) (Dream.csrf_tag req) (Dream.csrf_tag req)

  let totp_form user req =
    match user.Data.user_totp_secret_cipher with
    | None ->
      let secret = Totp.make_secret () in
      let qr =
        Totp.secret_to_svg secret ~appname:"Dream OCaml"
          ~username:user.Data.user_name
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
             <label>Password: <input type="password" name="password" /></label>
             <button type="submit">Enable</button>
           </form>
           |}
           (Dream.csrf_tag req) secret qr
    | Some _ ->
      Lwt.return
      @@ spf
           {|
           <h4>Two Factor Authentication: Enabled</h4>
           <form action="/auth/totp/disable" method="POST">
             %s
             <label>Enter code: <input type="text" name="code" /></label>
             <label>Password: <input type="password" name="password" /></label>
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
         user.Data.user_name (Dream.csrf_tag req) totp_form

  let main req =
    let%lwt content =
      match%lwt Auth.user req with
      | None -> content_anonymous req
      | Some user -> content_authenticated user req
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

let api_response_of_result result =
  match%lwt result with
  | Ok body -> Dream.respond ~status:`OK body
  | Error msg -> Dream.respond ~status:`Bad_Request msg

(** Register form handlers creates a new user account. *)
let register req =
  let open Lwt_result.Infix in
  let form =
    Form.(
      let+ username = field "username"
      and+ email = field "email"
      and+ password = field "password"
      and+ confirm_password = field "confirm_password" in
      if String.equal password confirm_password then
        Ok (username, email, password)
      else
        Error "passwords do not match")
  in
  api_response_of_result
    ( Form.validate form req >>= fun (username, email, password) ->
      Auth.register ~username ~email ~password req >>= fun registration ->
      Dream.log "EMAIL OTP CODE: %s\n" registration.Auth.registration_email_otp;
      Lwt.return_ok "email" )

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
  api_response_of_result
    ( Form.validate form req >>= fun (username, password) ->
      match%lwt Auth.login ~username ~password req with
      | `User_anonymous -> Lwt.return_error "incorrect username or password"
      | `User_awaiting_email_otp _ -> Lwt.return_ok "email"
      | `User_awaiting_totp _ -> Lwt.return_ok "totp"
      | `User_authenticated _ -> Lwt.return_ok "ok" )

let verify_totp req =
  let open Lwt_result.Infix in
  let form =
    Form.(
      let+ code = field "code"
      and+ password = field "password" in
      Ok (code, password))
  in
  api_response_of_result
    ( Form.validate form req >>= fun (totp, password) ->
      match%lwt Auth.verify_totp req ~totp ~password with
      | `User_authenticated _ -> Lwt.return_ok "ok"
      | `User_anonymous ->
        Lwt.return_error "something went wrong, please try again"
      | `User_awaiting_totp _ | `User_awaiting_email_otp _ ->
        Lwt.return_error "invalid TOTP" )

let verify_email req =
  let open Lwt_result.Infix in
  let form = Form.(field "code") in
  api_response_of_result
    ( Form.validate form req >>= fun otp ->
      match%lwt Auth.verify_email_otp req ~otp with
      | `User_authenticated _ -> Lwt.return_ok "ok"
      | `User_anonymous ->
        Lwt.return_error "something went wrong, please try again"
      | `User_awaiting_email_otp _ | `User_awaiting_totp _ ->
        Lwt.return_error "invalid OTP" )

let login_with_email req =
  let open Lwt_result.Infix in
  api_response_of_result
    ( Form.validate (Form.field "username") req >>= fun username ->
      match%lwt Auth.login_with_email_otp ~username req with
      | Some otp ->
        Dream.log "EMAIL OTP CODE: %s\n" otp;
        Lwt.return_ok "email"
      | None -> Lwt.return_error "something went wrong, please try again" )

let verify_email_resend req =
  let open Lwt_result.Infix in
  api_response_of_result
    ( Form.validate Form.empty req >>= fun () ->
      match%lwt Auth.refresh_email_otp req with
      | None -> Lwt.return_error "something went wrong, please try again"
      | Some otp ->
        Dream.log "EMAIL OTP CODE: %s\n" otp;
        Lwt.return_ok "ok" )

let totp_enable user req =
  let open Lwt_result.Infix in
  let form =
    Form.(
      let+ code = field "code"
      and+ secret = field "secret"
      and+ password = field "password" in
      Ok (code, secret, password))
  in
  response_of_result req
    ( Form.validate form req >>= fun (totp, secret, password) ->
      Auth.totp_enable user ~totp ~secret ~password >>= fun () ->
      Lwt.return_ok (Some "Two Factor Authentication enabled!") )

let totp_disable user req =
  let open Lwt_result.Infix in
  let form =
    Form.(
      let+ code = field "code"
      and+ password = field "password" in
      Ok (code, password))
  in
  response_of_result req
    ( Form.validate form req >>= fun (totp, password) ->
      Auth.totp_disable user ~totp ~password >>= fun () ->
      Lwt.return_ok (Some "Two Factor Authentication disabled!") )

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
         Dream.post "/auth/login-with-email" login_with_email;
         Dream.post "/auth/verify/totp" verify_totp;
         Dream.post "/auth/verify/email" verify_email;
         Dream.post "/auth/verify/email-resend" verify_email_resend;
         Dream.post "/auth/register" register;
         Dream.post "/auth/totp/enable" (Auth.with_user totp_enable);
         Dream.post "/auth/totp/disable" (Auth.with_user totp_disable);
         Dream.post "/auth/logout" (Auth.with_user logout);
         Dream.get "/public/**" @@ Dream.static "public";
       ]
