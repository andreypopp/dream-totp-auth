type _ t =
  | Form_value : 'a -> 'a t
  | Form_field : string -> string t
  | Form_field_opt : string -> string option t
  | Form_map : 'a t * ('a -> ('b, string) result) -> 'b t
  | Form_both : 'a t * 'b t -> ('a * 'b) t

let value v = Form_value v
let empty = Form_value ()
let field name = Form_field name
let field_opt name = Form_field_opt name
let map v f = Form_map (v, f)
let both a b = Form_both (a, b)
let ( let+ ) = map
let ( and+ ) = both

let validate' form (fields : (string * string) list) =
  let rec aux : type a. a t -> (a, string) result = function
    | Form_value v -> Ok v
    | Form_map (v, f) -> Result.bind (aux v) f
    | Form_both (a, b) -> (
      match (aux a, aux b) with
      | Ok a, Ok b -> Ok (a, b)
      | Error err, _ | _, Error err -> Error err)
    | Form_field name -> (
      match List.assoc_opt name fields with
      | None | Some "" ->
        Error (Printf.sprintf "%s field value is missing" name)
      | Some v -> Ok v)
    | Form_field_opt name -> (
      match List.assoc_opt name fields with
      | None | Some "" -> Ok None
      | Some v -> Ok (Some v))
  in
  aux form

let validate form req =
  match%lwt Dream.form req with
  | `Ok fields -> Lwt.return (validate' form fields)
  | `Expired _ -> Lwt.return_error "invalid form submission"
  | `Wrong_session _ -> Lwt.return_error "invalid form submission"
  | `Invalid_token _ -> Lwt.return_error "invalid form submission"
  | `Missing_token _ -> Lwt.return_error "invalid form submission"
  | `Many_tokens _ -> Lwt.return_error "invalid form submission"
  | `Wrong_content_type -> Lwt.return_error "invalid form submission"
