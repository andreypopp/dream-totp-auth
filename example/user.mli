val make :
  username:string -> email:string -> password:string -> unit -> Data.user

val verify_password : password:string -> Data.user -> bool
val verify_email_otp : otp:string -> Data.user -> bool Lwt.t
val verify_totp : password:string -> totp:string -> Data.user -> bool Lwt.t

val set_totp_secret :
  password:string -> secret:string option -> Data.user -> Data.user
