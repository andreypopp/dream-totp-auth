let secret_to_uri ~appname ~username secret =
  Printf.sprintf "otpauth://totp/%s:%s?secret=%s" appname username secret

let secret_to_svg ~appname ~username secret =
  match Qrc.encode (secret_to_uri ~appname ~username secret) with
  | Some qr -> Qrc.Matrix.to_svg qr
  | None -> assert false

let make_secret () = Twostep.TOTP.secret ()

let verify ~username ~totp secret =
  Data.Totp.transaction (fun () ->
      let window = 30 in
      let now = Unix.gettimeofday () in
      (* Garbage collect old seen totp codes if they are older than 3 windows. It
         is safe to do because they are not longer valid anyway. *)
      let%lwt seen =
        match%lwt Data.Totp.find username with
        | None -> Lwt.return []
        | Some { Data.totp_code = (_, prev) :: _; _ }
          when now -. prev > Float.of_int (3 * window) -> Lwt.return []
        | Some { Data.totp_code; _ } -> Lwt.return totp_code
      in
      match List.assoc_opt totp seen with
      | Some _ -> Lwt.return false
      | None ->
        let ok = Twostep.TOTP.verify ~window ~secret ~code:totp () in
        let%lwt () =
          if ok then
            Data.Totp.store
              { Data.totp_username = username; totp_code = (totp, now) :: seen }
          else
            Lwt.return ()
        in
        Lwt.return ok)
