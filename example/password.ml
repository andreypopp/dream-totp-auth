module Hash = Argon2.ID

type params = {
  time_cost : int;
  memory_cost_kiB : int;
  parallelism : int;
  hash_len : int;
  salt_len : int;
}

(*
  Recommended parameters
  https://argon2-cffi.readthedocs.io/en/stable/api.html#argon2.PasswordHasher
*)
let recommend_params =
  {
    time_cost = 2;
    memory_cost_kiB = 100 * 1024;
    (* 100MiB *)
    parallelism = 8;
    hash_len = 16;
    salt_len = 16;
  }

(*
  Minimum parameters
  https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
*)
let _minimum_params =
  {
    time_cost = 1;
    memory_cost_kiB = 37 * 1024;
    parallelism = 1;
    hash_len = 16;
    salt_len = 16;
  }

let hash password =
  let {
    time_cost = t_cost;
    memory_cost_kiB = m_cost;
    parallelism;
    hash_len;
    salt_len;
  } =
    recommend_params
  in

  let salt = Dream.random salt_len in

  let encoded_len =
    Argon2.encoded_len ~t_cost ~m_cost ~parallelism ~salt_len ~hash_len ~kind:ID
  in

  let encoded =
    Hash.hash_encoded ~t_cost ~m_cost ~parallelism ~pwd:password ~salt ~hash_len
      ~encoded_len
  in

  match encoded with
  | Ok encoded -> Hash.encoded_to_string encoded
  | Error e -> failwith (Argon2.ErrorCodes.message e)

let verify ~hash password =
  match Argon2.verify ~encoded:hash ~pwd:password ~kind:ID with
  | Ok result -> result
  | Error Argon2.ErrorCodes.VERIFY_MISMATCH -> false
  | Error e -> failwith (Argon2.ErrorCodes.message e)
