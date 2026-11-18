/// OpenZFS fletcher-4 over native (little-endian) 32-bit words, as in
/// `fletcher_4_incremental_native`. Trailing bytes short of a word are ignored, matching
/// `fletcher_4_scalar_native`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fletcher4 {
    pub w: [u64; 4],
}

impl Fletcher4 {
    pub fn update(&mut self, data: &[u8]) {
        let [mut a, mut b, mut c, mut d] = self.w;
        for chunk in data.chunks_exact(4) {
            a = a.wrapping_add(u32::from_le_bytes(chunk.try_into().unwrap()) as u64);
            b = b.wrapping_add(a);
            c = c.wrapping_add(b);
            d = d.wrapping_add(c);
        }
        self.w = [a, b, c, d];
    }

    pub fn of(data: &[u8]) -> Fletcher4 {
        let mut f = Fletcher4::default();
        f.update(data);
        f
    }

    pub fn to_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, w) in self.w.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        out
    }

    pub fn from_bytes(b: &[u8]) -> Fletcher4 {
        let mut w = [0u64; 4];
        for (i, x) in w.iter_mut().enumerate() {
            *x = u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
        }
        Fletcher4 { w }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_values() {
        let f = Fletcher4::of(&[1, 0, 0, 0, 2, 0, 0, 0]);
        assert_eq!(f.w, [3, 4, 5, 6]);
        let mut g = Fletcher4::default();
        g.update(&[1, 0, 0, 0]);
        g.update(&[2, 0, 0, 0]);
        assert_eq!(f, g);
    }
}
