val user : Dream.request -> Data.user option Lwt.t
(** Get an authenticated user account associated with the request.*)

val with_user : (Data.user -> Dream.handler) -> Dream.handler
(** Produce a handler which returns 403 in case request has no authenticated
    user account or calls the provided handler with a bound user account
    otherwise. *)

type registration = {
  registration_user : Data.user;
  registration_email_otp : string;
}

val register :
  username:string ->
  email:string ->
  password:string ->
  Dream.request ->
  (registration, string) Lwt_result.t
(** Register a new user account. *)

type auth_result =
  [ `User_anonymous
  | `User_awaiting_totp of Data.user
  | `User_awaiting_email_otp of Data.user
  | `User_authenticated of Data.user ]

val login :
  username:string -> password:string -> Dream.request -> auth_result Lwt.t
(** Verify username/password and perform an auth state transition. *)

val verify_totp :
  password:string -> totp:string -> Dream.request -> auth_result Lwt.t
(** Verify TOTP and perform an auth state transition. *)

val verify_email_otp : otp:string -> Dream.request -> auth_result Lwt.t
(** Verify TOTP and perform an auth state transition. *)

val totp_enable :
  password:string ->
  totp:string ->
  secret:string ->
  Data.user ->
  (unit, string) Lwt_result.t

val totp_disable :
  password:string -> totp:string -> Data.user -> (unit, string) Lwt_result.t

val refresh_email_otp : Dream.request -> string option Lwt.t

val login_with_email_otp :
  username:string -> Dream.request -> string option Lwt.t
(** Start login with email flow. *)

val logout : Dream.request -> unit Lwt.t
(** Performs a loggout. *)
