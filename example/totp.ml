type secret = string

let secret_to_uri ~appname ~username secret =
  Printf.sprintf "otpauth://totp/%s:%s?secret=%s" appname username secret

let secret_to_svg ~appname ~username secret =
  match Qrc.encode (secret_to_uri ~appname ~username secret) with
  | Some qr -> Qrc.Matrix.to_svg qr
  | None -> assert false

let make_secret () = Twostep.TOTP.secret ()
let secret_to_string s = s
let secret_of_string s = s

module Seen = struct
  (* a very naive storage for used TOTP codes *)
  let by_id : (string, (string * float) list) Hashtbl.t = Hashtbl.create 100
  let find id = Hashtbl.find_opt by_id id
  let update id seen = Hashtbl.replace by_id id seen
  let lock = Lwt_mutex.create ()
end

let verify ~id ~totp secret =
  Lwt_mutex.with_lock Seen.lock (fun () ->
      let window = 30 in
      let now = Unix.gettimeofday () in
      (* Garbage collect old seen totp codes if they are older than 3 windows. It
         is safe to do because they are not longer valid anyway. *)
      let seen =
        match Seen.find id with
        | None -> []
        | Some ((_, prev) :: _) when now -. prev > Float.of_int (3 * window) ->
          []
        | Some seen -> seen
      in
      Lwt.return
        (match List.assoc_opt totp seen with
        | Some _ -> false
        | None ->
          let ok = Twostep.TOTP.verify ~window ~secret ~code:totp () in
          if ok then
            Seen.update id ((totp, now) :: seen);
          ok))
