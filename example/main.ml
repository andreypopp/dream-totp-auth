module User : sig
  type t = private {
    username : string;
    password_hash : string;
  }

  val register :
    ?login:bool ->
    username:string ->
    password:string ->
    Dream.request ->
    (t, string) Lwt_result.t

  val login :
    username:string ->
    password:string ->
    Dream.request ->
    (t, string) Lwt_result.t

  val logout : Dream.request -> (unit, string) Lwt_result.t
  val user : Dream.request -> t option Lwt.t
end = struct
  type t = {
    username : string;
    password_hash : string;
  }

  let users = ref []
  let session_key = "user"

  let register ?(login = false) ~username ~password req =
    match List.assoc_opt username !users with
    | Some _ -> Lwt.return_error "username is not available"
    | None -> (
      match Password.hash password with
      | Error _ -> Lwt.return_error "unable to register"
      | Ok password_hash ->
        let user = { username; password_hash } in
        users := (username, user) :: !users;
        let%lwt () =
          if login then
            Dream.set_session_field req session_key username
          else
            Lwt.return ()
        in
        Lwt.return_ok user)

  let login ~username ~password req =
    match List.assoc_opt username !users with
    | None -> Lwt.return_error "incorrect username or password"
    | Some user -> (
      match Password.verify ~hash:user.password_hash password with
      | Error _ -> Lwt.return_error "unable to login, try again later"
      | Ok true ->
        let%lwt () = Dream.set_session_field req session_key username in
        Lwt.return_ok user
      | Ok false -> Lwt.return_error "incorrect username or password")

  let logout req =
    let%lwt () = Dream.set_session_field req session_key "" in
    Lwt.return_ok ()

  let user req =
    match Dream.session_field req session_key with
    | None -> Lwt.return_none
    | Some username -> Lwt.return (List.assoc_opt username !users)
end

module Page_template = struct
  let spf = Printf.sprintf

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

  let content_authenticated user req =
    Lwt.return
    @@ spf
         {|
          <h3>Welcome, %s!</h3>
          <form action="/auth/logout" method="POST">
            %s
            <button type="submit">Logout</button>
          </form>
         |}
         user.User.username (Dream.csrf_tag req)

  let main req =
    let messages =
      Dream.flash_messages req
      |> List.map (fun (category, text) ->
             spf {|<p class="flash-%s">%s: %s</p>|} category category text)
      |> String.concat "\n"
    in
    let%lwt content =
      match%lwt User.user req with
      | None -> content_anonymous req
      | Some user -> content_authenticated user req
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
    >>= fun (username, password) -> User.login ~username ~password req
  in
  match%lwt result with
  | Ok _user -> Dream.redirect req "/"
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
    >>= fun (username, password) -> User.register ~username ~password req
  in
  match%lwt result with
  | Ok _user ->
    Dream.add_flash_message req "success" "Success!";
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
    >>= fun () -> User.logout req
  in
  match%lwt result with
  | Ok _user -> Dream.redirect req "/"
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
         Dream.post "/auth/register" register;
         Dream.post "/auth/logout" logout;
       ]
