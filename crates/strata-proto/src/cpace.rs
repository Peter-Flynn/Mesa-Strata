//! CPace over ristretto255 with SHA-512 (draft-irtf-cfrg-cpace, initiator-responder
//! transcript), plus the draft's explicit key confirmation:
//! `mac_key = SHA-512("CPaceMac" || sid || ISK)`, `T = HMAC-SHA-512(mac_key, lv_cat(Y, AD))`.
//!
//! The client is the initiator (A), zfsd the responder (B). Function names follow the draft.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;

pub const DSI: &[u8] = b"CPaceRistretto255";
/// SHA-512 input block size (`H.s_in_bytes` in the draft).
const S_IN_BYTES: usize = 128;

pub type Element = [u8; 32];
pub type Tag = [u8; 64];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CpaceError {
    #[error("peer sent an invalid or identity group element")]
    InvalidElement,
    #[error("key confirmation tag mismatch")]
    BadTag,
}

fn leb128(mut n: usize, out: &mut Vec<u8>) {
    loop {
        if n < 128 {
            out.push(n as u8);
            return;
        }
        out.push((n & 0x7f) as u8 | 0x80);
        n >>= 7;
    }
}

pub fn prepend_len(out: &mut Vec<u8>, data: &[u8]) {
    leb128(data.len(), out);
    out.extend_from_slice(data);
}

pub fn lv_cat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        prepend_len(&mut out, p);
    }
    out
}

fn prepended_len(data: &[u8]) -> usize {
    let mut v = Vec::new();
    leb128(data.len(), &mut v);
    v.len() + data.len()
}

pub fn generator_string(prs: &[u8], ci: &[u8], sid: &[u8]) -> Vec<u8> {
    let zpad = S_IN_BYTES.saturating_sub(1 + prepended_len(prs) + prepended_len(DSI));
    lv_cat(&[DSI, prs, &vec![0u8; zpad], ci, sid])
}

pub fn calculate_generator(prs: &[u8], ci: &[u8], sid: &[u8]) -> RistrettoPoint {
    let hash: [u8; 64] = Sha512::digest(generator_string(prs, ci, sid)).into();
    RistrettoPoint::from_uniform_bytes(&hash)
}

pub fn sample_scalar() -> Scalar {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).expect("getrandom");
    // The draft samples group_size_bits = 252 random bits; clearing the top 4 bits of the
    // 256-bit little-endian string keeps the value below the group order.
    b[31] &= 0x0f;
    Scalar::from_bytes_mod_order(b)
}

fn scalar_mult(y: &Scalar, g: &RistrettoPoint) -> Element {
    (y * g).compress().to_bytes()
}

fn scalar_mult_vfy(y: &Scalar, x: &Element) -> Result<Element, CpaceError> {
    let point = CompressedRistretto(*x)
        .decompress()
        .ok_or(CpaceError::InvalidElement)?;
    let k = scalar_mult(y, &point);
    if k == [0u8; 32] {
        return Err(CpaceError::InvalidElement);
    }
    Ok(k)
}

fn isk(sid: &[u8], k: &Element, ya: &Element, ada: &[u8], yb: &Element, adb: &[u8]) -> [u8; 64] {
    let mut dsi_isk = DSI.to_vec();
    dsi_isk.extend_from_slice(b"_ISK");
    let mut h = Sha512::new();
    h.update(lv_cat(&[&dsi_isk, sid, k]));
    h.update(lv_cat(&[ya, ada]));
    h.update(lv_cat(&[yb, adb]));
    h.finalize().into()
}

/// Output of a CPace run: the intermediate session key and the key-confirmation MAC key.
pub struct Keys {
    pub isk: [u8; 64],
    sid: Vec<u8>,
    mac_key: [u8; 64],
}

impl Keys {
    fn new(isk: [u8; 64], sid: &[u8]) -> Keys {
        let mut h = Sha512::new();
        h.update(b"CPaceMac");
        h.update(sid);
        h.update(isk);
        Keys { isk, sid: sid.to_vec(), mac_key: h.finalize().into() }
    }

    pub fn tag(&self, y: &Element, ad: &[u8]) -> Tag {
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&self.mac_key).expect("hmac key");
        mac.update(&lv_cat(&[y, ad]));
        mac.finalize().into_bytes().into()
    }

    pub fn verify(&self, y: &Element, ad: &[u8], tag: &Tag) -> Result<(), CpaceError> {
        if bool::from(self.tag(y, ad).ct_eq(tag)) {
            Ok(())
        } else {
            Err(CpaceError::BadTag)
        }
    }

    /// A key derived from ISK for a higher-level protocol, separated by `label`.
    pub fn derive(&self, label: &[u8]) -> [u8; 32] {
        let mut h = Sha512::new();
        h.update(lv_cat(&[b"strata", label, &self.sid, &self.isk]));
        let out: [u8; 64] = h.finalize().into();
        out[..32].try_into().unwrap()
    }
}

pub struct Initiator {
    ya: Scalar,
    ya_enc: Element,
    ada: Vec<u8>,
    sid: Vec<u8>,
}

impl Initiator {
    pub fn start(prs: &[u8], ci: &[u8], sid: &[u8], ada: &[u8]) -> (Initiator, Element) {
        Self::start_with(prs, ci, sid, ada, sample_scalar())
    }

    fn start_with(prs: &[u8], ci: &[u8], sid: &[u8], ada: &[u8], ya: Scalar) -> (Initiator, Element) {
        let g = calculate_generator(prs, ci, sid);
        let ya_enc = scalar_mult(&ya, &g);
        let init = Initiator { ya, ya_enc, ada: ada.to_vec(), sid: sid.to_vec() };
        (init, ya_enc)
    }

    pub fn finish(self, yb: &Element, adb: &[u8]) -> Result<Keys, CpaceError> {
        let k = scalar_mult_vfy(&self.ya, yb)?;
        let isk = isk(&self.sid, &k, &self.ya_enc, &self.ada, yb, adb);
        Ok(Keys::new(isk, &self.sid))
    }
}

/// Responder side: computes `Yb` and the keys in one step from the initiator's `Ya`.
pub fn respond(
    prs: &[u8],
    ci: &[u8],
    sid: &[u8],
    ya: &Element,
    ada: &[u8],
    adb: &[u8],
) -> Result<(Element, Keys), CpaceError> {
    respond_with(prs, ci, sid, ya, ada, adb, sample_scalar())
}

fn respond_with(
    prs: &[u8],
    ci: &[u8],
    sid: &[u8],
    ya: &Element,
    ada: &[u8],
    adb: &[u8],
    yb: Scalar,
) -> Result<(Element, Keys), CpaceError> {
    let g = calculate_generator(prs, ci, sid);
    let yb_enc = scalar_mult(&yb, &g);
    let k = scalar_mult_vfy(&yb, ya)?;
    let isk = isk(sid, &k, ya, ada, &yb_enc, adb);
    Ok((yb_enc, Keys::new(isk, sid)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s.split_whitespace().collect::<String>()).unwrap()
    }

    fn h32(s: &str) -> [u8; 32] {
        h(s).try_into().unwrap()
    }

    // Test vectors: draft-irtf-cfrg-cpace, "Test vector for CPace using group ristretto255
    // and hash SHA-512".
    const PRS: &[u8] = b"Password";
    const CI: &str = "0b415f696e69746961746f720b425f726573706f6e646572";
    const SID: &str = "7e4b4791d6a8ef019b936c79fb7f2c57";
    const YA_SCALAR: &str = "da3d23700a9e5699258aef94dc060dfda5ebb61f02a5ea77fad53f4ff0976d08";
    const YB_SCALAR: &str = "d2316b454718c35362d83d69df6320f38578ed5984651435e2949762d900b80d";

    #[test]
    fn leb128_and_lv_cat() {
        assert_eq!(lv_cat(&[b"1234", b"5", b"", b"678"]), h("043132333401350003363738"));
        let r: Vec<u8> = (0..128u8).collect();
        assert_eq!(&lv_cat(&[&r])[..2], &[0x80, 0x01]);
    }

    #[test]
    fn generator() {
        let gs = generator_string(PRS, &h(CI), &h(SID));
        assert_eq!(gs.len(), 170);
        assert_eq!(
            gs,
            h("11435061636552697374726574746f3235350850617373776f726464
               00000000000000000000000000000000000000000000000000000000
               00000000000000000000000000000000000000000000000000000000
               00000000000000000000000000000000000000000000000000000000
               00000000000000000000000000000000180b415f696e69746961746f
               720b425f726573706f6e646572107e4b4791d6a8ef019b936c79fb7f
               2c57")
        );
        let g = calculate_generator(PRS, &h(CI), &h(SID));
        assert_eq!(
            g.compress().to_bytes(),
            h32("222b6b195fe84b1652badb6f6a3ae3d24341e7306967f0b8115b40d5698c7e56")
        );
    }

    #[test]
    fn full_exchange_matches_vectors() {
        let ya = Scalar::from_bytes_mod_order(h32(YA_SCALAR));
        let yb = Scalar::from_bytes_mod_order(h32(YB_SCALAR));
        let (init, ya_enc) = Initiator::start_with(PRS, &h(CI), &h(SID), b"ADa", ya);
        assert_eq!(ya_enc, h32("d6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0eec482b9157"));
        let (yb_enc, kb) = respond_with(PRS, &h(CI), &h(SID), &ya_enc, b"ADa", b"ADb", yb).unwrap();
        assert_eq!(yb_enc, h32("3ea7e0b19560d7c0b0f5734f63b955286dfa8232b5ebe63324e2d9e7433f7258"));
        let ka = init.finish(&yb_enc, b"ADb").unwrap();
        let expected_isk = h("b69effbf61b51d56401c0f65601abe428de8206feaaf0e32198896dc
                              ae7b35cd2b38950a39dfd5d4a79164614c2984f7daa460b588c1e80c
                              3fa2068af7900447");
        assert_eq!(ka.isk.to_vec(), expected_isk);
        assert_eq!(kb.isk.to_vec(), expected_isk);
    }

    #[test]
    fn scalar_mult_vfy_vectors() {
        let s = Scalar::from_bytes_mod_order(h32(
            "7cd0e075fa7955ba52c02759a6c90dbbfc10e6d40aea8d283e407d88cf538a05",
        ));
        let x = h32("2c3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c");
        assert_eq!(
            scalar_mult_vfy(&s, &x).unwrap(),
            h32("7c13645fe790a468f62c39beb7388e541d8405d1ade69d1778c5fe3e7f6b600e")
        );
        let bad = h32("2b3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c");
        assert_eq!(scalar_mult_vfy(&s, &bad), Err(CpaceError::InvalidElement));
        assert_eq!(scalar_mult_vfy(&s, &[0u8; 32]), Err(CpaceError::InvalidElement));
    }

    #[test]
    fn confirmation_and_wrong_password() {
        let (init, ya) = Initiator::start(b"right", b"ci", b"sid", b"");
        let (yb, kb) = respond(b"right", b"ci", b"sid", &ya, b"", b"").unwrap();
        let ka = init.finish(&yb, b"").unwrap();
        ka.verify(&yb, b"", &kb.tag(&yb, b"")).unwrap();
        kb.verify(&ya, b"", &ka.tag(&ya, b"")).unwrap();
        assert_eq!(ka.derive(b"x"), kb.derive(b"x"));

        let (init, ya) = Initiator::start(b"wrong", b"ci", b"sid", b"");
        let (yb, kb) = respond(b"right", b"ci", b"sid", &ya, b"", b"").unwrap();
        let ka = init.finish(&yb, b"").unwrap();
        assert_eq!(ka.verify(&yb, b"", &kb.tag(&yb, b"")), Err(CpaceError::BadTag));
    }
}
