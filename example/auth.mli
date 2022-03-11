val user : Dream.request -> User.t option Lwt.t
(** Get an authenticated user account associated with the request.*)

val with_user : (User.t -> Dream.handler) -> Dream.handler
(** Produce a handler which returns 403 in case request has no authenticated
    user account or calls the provided handler with a bound user account
    otherwise. *)

val register :
  ?login:bool ->
  username:string ->
  password:string ->
  Dream.request ->
  (User.t, string) Lwt_result.t
(** Register a new user account. *)

type auth_result =
  [ `Auth_none
  | `Auth_awaiting_totp of User.t
  | `Auth_ok of User.t ]
(** This type represents a state of authentication. *)

val auth : Dream.request -> auth_result Lwt.t
(** Authentication state of the [req]. *)

val login :
  username:string -> password:string -> Dream.request -> auth_result Lwt.t
(** Verify username/password and perform an auth state transition. *)

val verify_login : totp:string -> Dream.request -> auth_result Lwt.t
(** Verify TOTP and perform an auth state transition. *)

val logout : Dream.request -> unit Lwt.t
(** Performs a loggout. *)