(** Query current request for authenticated user. *)

val user : Dream.request -> Data.user option Lwt.t
(** Get an authenticated user associated with request if there's one. *)

val with_user : (Data.user -> Dream.handler) -> Dream.handler
(** Produce a handler which returns 403 in case request has no authenticated
    user or calls the provided handler with a bound user account otherwise. *)

(** Registration. *)

type registration = {
  registration_user : Data.user;
  registration_email_otp : string;
}
(** Result of a successful registration.

    The [registration_user] field contains just created user account,
    [registration_email_otp] is an OTP to be sent to user's email address for
    verification.

    Note that after registration is completed the user has unconfirmed email
    address and will be prompted to enter email OTP on login. *)

val register :
  username:string ->
  email:string ->
  password:string ->
  Dream.request ->
  (registration, string) Lwt_result.t
(** Register a new user account. *)

(** Username/password verification. *)

type verify_password_transition =
  [ `User_awaiting_totp of Data.user
  | `User_awaiting_email_otp of Data.user
  | `User_authenticated of Data.user ]
(** Result of a successful password login. *)

val verify_password :
  username:string ->
  password:string ->
  Dream.request ->
  verify_password_transition option Lwt.t
(** Verify password and in case of a success make auth transition. *)

(** Email OTP verification. *)

type verify_email_otp_transition = [`User_authenticated of Data.user]
(** Result of a successful email OTP verification. *)

val verify_email_otp :
  username:string ->
  password:string option ->
  otp:string ->
  Dream.request ->
  verify_email_otp_transition option Lwt.t
(** Verify email OTP and in case of a success make auth transition.

    [password] is required for user accounts with unconfirmed emails. *)

val email_otp :
  username:string ->
  password:string option ->
  Dream.request ->
  string option Lwt.t
(** Produce a new OTP for checking with [verify_email_otp] function.

    Usually you'd want to send this OTP to a user's email.

    Note that in case user has unconfirmed email the [password] is required,
    otherwise OTP won't be produced. *)

(** TOTP (RFC6238) verification. *)

type verify_totp_transition = [`User_authenticated of Data.user]
(** Result of a successful TOTP verification. *)

val verify_totp :
  username:string ->
  password:string ->
  totp:string ->
  Dream.request ->
  verify_totp_transition option Lwt.t
(** Verify TOTP and in case of a success make auth transition. *)

val totp_enable :
  password:string ->
  totp:string ->
  secret:string ->
  Data.user ->
  (unit, string) Lwt_result.t

val totp_disable :
  password:string -> totp:string -> Data.user -> (unit, string) Lwt_result.t

val logout : Dream.request -> unit Lwt.t
(** Performs a logout. *)
