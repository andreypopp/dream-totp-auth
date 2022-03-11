val user : Dream.request -> User.t option Lwt.t
val with_user : (User.t -> Dream.handler) -> Dream.handler

type auth_result =
  [ `Auth_awaiting_totp of User.t
  | `Auth_none
  | `Auth_ok of User.t ]

val auth : Dream.request -> auth_result Lwt.t

val register :
  ?login:bool ->
  username:string ->
  password:string ->
  Dream.request ->
  (User.t, string) Lwt_result.t

val login :
  username:string -> password:string -> Dream.request -> auth_result Lwt.t

val verify_login : totp:string -> Dream.request -> auth_result Lwt.t
val logout : Dream.request -> unit Lwt.t
