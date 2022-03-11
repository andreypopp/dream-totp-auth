let users =
  let users = Hashtbl.create 10 in
  Hashtbl.add users "user"
    {
      User.username = "user";
      password_hash =
        "$argon2id$v=19$m=102400,t=2,p=8$cC1Z3vVsyvDjp0PRjW7O7w$1MpRLlSifXJoLGYtkQZywQ";
      totp = Totp_disabled;
    };
  users

let find username = Lwt.return (Hashtbl.find_opt users username)
let store user = Lwt.return (Hashtbl.replace users user.User.username user)
