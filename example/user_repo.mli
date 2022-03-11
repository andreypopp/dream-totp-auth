(** A repository of user accounts.

    In this example app we store all accounts in memory, but real application
    would want to have this stored in a database or any other persistent
    storage. *)

val find : string -> User.t option Lwt.t
val store : User.t -> unit Lwt.t
