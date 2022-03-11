let users =
  let users = Hashtbl.create 10 in
  Hashtbl.add users "user"
    {
      User.username = "user";
      password_hash = Password.hash "password";
      totp_secret_cipher = None;
    };
  users

let find username = Lwt.return (Hashtbl.find_opt users username)
let store user = Lwt.return (Hashtbl.replace users user.User.username user)
