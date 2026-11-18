use argon2::{Algorithm, Argon2, Params, Version};

pub type ServerId = [u8; 16];
pub type DerivedKey = [u8; 32];

// RFC 9106 section 4, second recommended option (64 MiB, 3 passes), with 4 lanes. A
// password client pays this once per connection; the server only ever stores the output.
const M_COST_KIB: u32 = 64 * 1024;
const T_COST: u32 = 3;
const P_COST: u32 = 4;

pub fn derive_key(password: &[u8], server_id: &ServerId, client: &str) -> DerivedKey {
    let params = Params::new(M_COST_KIB, T_COST, P_COST, Some(32)).expect("argon2 params");
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut salt = server_id.to_vec();
    salt.extend_from_slice(client.as_bytes());
    let mut out = [0u8; 32];
    argon.hash_password_into(password, &salt, &mut out).expect("argon2 with valid params");
    out
}

pub fn encode_key(key: &DerivedKey) -> String {
    hex::encode(key)
}

pub fn parse_key(text: &str) -> Result<DerivedKey, String> {
    let bytes = hex::decode(text.trim()).map_err(|e| format!("key is not hex: {e}"))?;
    bytes.try_into().map_err(|_| "key must be 32 bytes (64 hex digits)".to_string())
}

pub fn encode_server_id(id: &ServerId) -> String {
    hex::encode(id)
}

pub fn parse_server_id(text: &str) -> Result<ServerId, String> {
    let bytes = hex::decode(text.trim()).map_err(|e| format!("server id is not hex: {e}"))?;
    bytes.try_into().map_err(|_| "server id must be 16 bytes (32 hex digits)".to_string())
}

/// A password file holds the password itself; a trailing newline from `echo` or an editor
/// is not part of it.
pub fn password_from_file(contents: &[u8]) -> &[u8] {
    let mut p = contents;
    while let Some((&last, rest)) = p.split_last() {
        if last == b'\n' || last == b'\r' {
            p = rest;
        } else {
            break;
        }
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salt_binds_server_and_client() {
        let a = derive_key(b"pw", &[1; 16], "nas");
        assert_eq!(a, derive_key(b"pw", &[1; 16], "nas"));
        assert_ne!(a, derive_key(b"pw", &[2; 16], "nas"));
        assert_ne!(a, derive_key(b"pw", &[1; 16], "nas2"));
        assert_eq!(parse_key(&encode_key(&a)).unwrap(), a);
    }

    #[test]
    fn password_file_trailing_newlines() {
        assert_eq!(password_from_file(b"secret\n"), b"secret");
        assert_eq!(password_from_file(b"sec ret\r\n\n"), b"sec ret");
    }
}
