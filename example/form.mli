type 'a t
(** [a t] represents a form parser which produces a value of type [a]. *)

val field : string -> string t
(** [field name] parses a string typed value for form field [name]. *)

val map : 'a t -> ('a -> ('b, string) result) -> 'b t
(** [map v f] validates [v] with [f]. *)

val both : 'a t -> 'b t -> ('a * 'b) t
(** [both a b] combines [a] and [b] into a pair. *)

val value : 'a -> 'a t
(** [value v] is a form parser which always returns [v] value.  *)

val empty : unit t
(** [empty] is a shortcut for [value ()]. *)

val ( let+ ) : 'a t -> ('a -> ('b, string) result) -> 'b t
(** Same as [map]. *)

val ( and+ ) : 'a t -> 'b t -> ('a * 'b) t
(** Same as [both]. *)

val validate : 'a t -> Dream.request -> ('a, string) Lwt_result.t
(** [validate form req] parses form data from [req] according to supplied parser
  [form].

  Example:

    let form = 
      let+ username = field "username"
      and+ password = field "password"
      and+ confirm_password = field "confirm_password" in
      if String.equal password confirm_password then
        Ok (username, password)
      else
        Error "passwords do not match"
    in
    match%lwt validate form req with
    | Ok value -> ...
    | Error error -> ...

 *)
