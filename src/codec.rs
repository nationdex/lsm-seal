use std::io::{self, Write};

use crate::error::{Error, Result};

pub const FLAG_TOMBSTONE: u8 = 1;
pub const FLAG_COMPRESSED: u8 = 2;
const COMPRESS_MIN: usize = 128;
pub const MAX_RECORD: usize = 64 << 20;

/// Value frame: [flags u8][raw_len u32 le][body]. Body is zstd-compressed when
/// FLAG_COMPRESSED is set. Frame is what the AEAD seals.
pub fn encode_value(value: Option<&[u8]>, level: i32) -> Vec<u8> {
    match value {
        None => vec![FLAG_TOMBSTONE, 0, 0, 0, 0],
        Some(v) => {
            if v.len() >= COMPRESS_MIN
                && let Ok(z) = zstd::bulk::compress(v, level)
                    && z.len() < v.len() {
                        let mut f = Vec::with_capacity(5 + z.len());
                        f.push(FLAG_COMPRESSED);
                        f.extend_from_slice(&(v.len() as u32).to_le_bytes());
                        f.extend_from_slice(&z);
                        return f;
                    }
            let mut f = Vec::with_capacity(5 + v.len());
            f.push(0);
            f.extend_from_slice(&(v.len() as u32).to_le_bytes());
            f.extend_from_slice(v);
            f
        }
    }
}

pub fn decode_value(frame: &[u8]) -> Result<Option<Vec<u8>>> {
    if frame.len() < 5 {
        return Err(Error::Corrupt("short value frame".into()));
    }
    let flags = frame[0];
    if flags & FLAG_TOMBSTONE != 0 {
        return Ok(None);
    }
    let raw_len = u32::from_le_bytes(frame[1..5].try_into().unwrap()) as usize;
    let body = &frame[5..];
    if flags & FLAG_COMPRESSED != 0 {
        let raw =
            zstd::bulk::decompress(body, raw_len).map_err(|_| Error::Corrupt("zstd".into()))?;
        if raw.len() != raw_len {
            return Err(Error::Corrupt("zstd length".into()));
        }
        Ok(Some(raw))
    } else {
        if body.len() != raw_len {
            return Err(Error::Corrupt("frame length".into()));
        }
        Ok(Some(body.to_vec()))
    }
}

/// Record on disk: [u32 len][u32 crc32(body)][body].
/// Returns bytes written including header.
pub fn write_record(w: &mut impl Write, body: &[u8]) -> io::Result<u32> {
    debug_assert!(body.len() <= MAX_RECORD);
    let mut header = [0u8; 8];
    header[..4].copy_from_slice(&(body.len() as u32).to_le_bytes());
    header[4..].copy_from_slice(&crc32fast::hash(body).to_le_bytes());
    w.write_all(&header)?;
    w.write_all(body)?;
    Ok(8 + body.len() as u32)
}

/// Reads record at offset. `None` = torn tail or end of data.
pub fn read_record_at(f: &(impl ReadAt + ?Sized), off: u64) -> Option<(Vec<u8>, u64)> {
    let mut header = [0u8; 8];
    if !f.read_exact_at(&mut header, off).ok()? {
        return None;
    }
    let len = u32::from_le_bytes(header[..4].try_into().unwrap()) as usize;
    if len == 0 || len > MAX_RECORD {
        return None;
    }
    let mut body = vec![0u8; len];
    if !f.read_exact_at(&mut body, off + 8).ok()? {
        return None;
    }
    if crc32fast::hash(&body) != u32::from_le_bytes(header[4..].try_into().unwrap()) {
        return None;
    }
    Some((body, off + 8 + len as u64))
}

pub trait ReadAt {
    /// Ok(true) = filled, Ok(false) = short read.
    fn read_exact_at(&self, buf: &mut [u8], off: u64) -> io::Result<bool>;
}

impl ReadAt for std::fs::File {
    fn read_exact_at(&self, buf: &mut [u8], off: u64) -> io::Result<bool> {
        use std::os::unix::fs::FileExt;
        let mut n = 0;
        while n < buf.len() {
            match self.read_at(&mut buf[n..], off + n as u64)? {
                0 => return Ok(false),
                k => n += k,
            }
        }
        Ok(true)
    }
}

impl ReadAt for [u8] {
    fn read_exact_at(&self, buf: &mut [u8], off: u64) -> io::Result<bool> {
        let off = off as usize;
        if off.saturating_add(buf.len()) > self.len() {
            return Ok(false);
        }
        buf.copy_from_slice(&self[off..off + buf.len()]);
        Ok(true)
    }
}

/// Entry body layout shared by WAL and SST: [seq u64][klen u16][key][ciphertext].
pub fn encode_entry_body(seq: u64, key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(10 + key.len() + ciphertext.len());
    b.extend_from_slice(&seq.to_le_bytes());
    b.extend_from_slice(&(key.len() as u16).to_le_bytes());
    b.extend_from_slice(key);
    b.extend_from_slice(ciphertext);
    b
}

pub fn decode_entry_body(body: &[u8]) -> Option<(u64, &[u8], &[u8])> {
    if body.len() < 10 {
        return None;
    }
    let seq = u64::from_le_bytes(body[..8].try_into().unwrap());
    let klen = u16::from_le_bytes(body[8..10].try_into().unwrap()) as usize;
    if body.len() < 10 + klen {
        return None;
    }
    Some((seq, &body[10..10 + klen], &body[10 + klen..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_roundtrip_raw_and_compressed() {
        for v in [b"tiny".as_slice(), &vec![7u8; 5000]] {
            let f = encode_value(Some(v), 3);
            assert_eq!(decode_value(&f).unwrap().unwrap(), v);
        }
        let f = encode_value(Some(&vec![1u8; 4096]), 3);
        assert!(f[0] & FLAG_COMPRESSED != 0);
    }

    #[test]
    fn tombstone_roundtrip() {
        let f = encode_value(None, 3);
        assert!(decode_value(&f).unwrap().is_none());
    }

    #[test]
    fn record_torn_tail() {
        let mut buf = Vec::new();
        write_record(&mut buf, b"first").unwrap();
        let (b, next) = read_record_at(&buf[..], 0).unwrap();
        assert_eq!(b, b"first");
        assert_eq!(next, 13);

        let mut torn = buf.clone();
        torn.push(0x55);
        torn.push(0x00);
        assert!(read_record_at(&torn[..], next).is_none());

        let mut corrupt = buf;
        corrupt[9] ^= 0xff;
        assert!(read_record_at(&corrupt[..], 0).is_none());
    }
}
