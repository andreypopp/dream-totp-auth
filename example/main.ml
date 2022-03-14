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
      match%lwt Auth.verify_password ~username ~password req with
      | None -> Lwt.return_error "incorrect username or password"
      | Some (`User_awaiting_email_otp _) -> Lwt.return_ok "email"
      | Some (`User_awaiting_totp _) -> Lwt.return_ok "totp"
      | Some (`User_authenticated _) -> Lwt.return_ok "ok" )

let verify_totp req =
  let open Lwt_result.Infix in
  let form =
    Form.(
      let+ username = field "username"
      and+ password = field "password"
      and+ totp = field "totp" in
      Ok (username, password, totp))
  in
  api_response_of_result
    ( Form.validate form req >>= fun (username, password, totp) ->
      match%lwt Auth.verify_totp req ~username ~password ~totp with
      | Some (`User_authenticated _) -> Lwt.return_ok "ok"
      | None -> Lwt.return_error "something went wrong, please try again" )

let verify_email_otp req =
  let open Lwt_result.Infix in
  let form =
    Form.(
      let+ username = field "username"
      and+ password = field_opt "password"
      and+ otp = field "otp" in
      Ok (username, password, otp))
  in
  api_response_of_result
    ( Form.validate form req >>= fun (username, password, otp) ->
      match%lwt Auth.verify_email_otp req ~username ~password ~otp with
      | Some (`User_authenticated _) -> Lwt.return_ok "ok"
      | None -> Lwt.return_error "invalid OTP" )

let login_with_email req =
  let open Lwt_result.Infix in
  api_response_of_result
    ( Form.validate
        Form.(
          let+ username = field "username"
          and+ password = field_opt "password" in
          Ok (username, password))
        req
    >>= fun (username, password) ->
      match%lwt Auth.email_otp ~username ~password req with
      | Some otp ->
        Dream.log "EMAIL OTP CODE: %s\n" otp;
        Lwt.return_ok "email"
      | None -> Lwt.return_error "login via email is not available" )

let totp_enable user req =
  let open Lwt_result.Infix in
  let form =
    Form.(
      let+ totp = field "totp"
      and+ secret = field "secret"
      and+ password = field "password" in
      Ok (totp, secret, password))
  in
  response_of_result req
    ( Form.validate form req >>= fun (totp, secret, password) ->
      Auth.totp_enable user ~totp ~secret ~password >>= fun () ->
      Lwt.return_ok (Some "Two Factor Authentication enabled!") )

let totp_disable user req =
  let open Lwt_result.Infix in
  let form =
    Form.(
      let+ totp = field "totp"
      and+ password = field "password" in
      Ok (totp, password))
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
         Dream.post "/auth/verify/email" verify_email_otp;
         Dream.post "/auth/register" register;
         Dream.post "/auth/totp/enable" (Auth.with_user totp_enable);
         Dream.post "/auth/totp/disable" (Auth.with_user totp_disable);
         Dream.post "/auth/logout" (Auth.with_user logout);
         Dream.get "/public/**" @@ Dream.static "public";
       ]
