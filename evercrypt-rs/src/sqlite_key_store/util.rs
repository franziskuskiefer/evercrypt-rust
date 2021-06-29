/// Convert a byte slice into a hex string
#[inline]
pub(crate) fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|x| format!("{:02x}", x)).collect()
}

/// Compare two byte slices in a way that's hopefully not optimised out by the
/// compiler.
#[inline]
pub(crate) fn equal_ct(a: &[u8], b: &[u8]) -> bool {
    let mut diff = 0u8;
    for (l, r) in a.iter().zip(b.iter()) {
        diff |= l ^ r;
    }
    diff == 0
}
