use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::codec::{self, ReadAt};
use crate::error::{Error, Result};

const INDEX_STRIDE: usize = 16;
const MAGIC: u64 = 0x4C53_4D53_4541_4C31; // "LSMSEAL1"

pub type Entry = (u64, Vec<u8>, Vec<u8>);

pub struct SstWriter {
    f: File,
    off: u64,
    entries: u32,
    index: Vec<(Vec<u8>, u64)>,
}

impl SstWriter {
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        Ok(Self {
            f,
            off: 0,
            entries: 0,
            index: Vec::new(),
        })
    }

    /// Entries must be written in ascending key order.
    pub fn write_entry(&mut self, seq: u64, key: &[u8], ciphertext: &[u8]) -> Result<()> {
        if (self.entries as usize).is_multiple_of(INDEX_STRIDE) {
            self.index.push((key.to_vec(), self.off));
        }
        let body = codec::encode_entry_body(seq, key, ciphertext);
        self.off += codec::write_record(&mut self.f, &body)? as u64;
        self.entries += 1;
        Ok(())
    }

    pub fn finish(mut self) -> Result<()> {
        let index_off = self.off;
        let mut buf = Vec::with_capacity(self.index.len() * 32 + 16);
        for (key, off) in &self.index {
            buf.extend_from_slice(&(key.len() as u16).to_le_bytes());
            buf.extend_from_slice(key);
            buf.extend_from_slice(&off.to_le_bytes());
        }
        let mut footer = Vec::with_capacity(28);
        footer.extend_from_slice(&index_off.to_le_bytes());
        footer.extend_from_slice(&(self.index.len() as u32).to_le_bytes());
        footer.extend_from_slice(&self.entries.to_le_bytes());
        let crc = crc32fast::hash(&footer);
        footer.extend_from_slice(&crc.to_le_bytes());
        footer.extend_from_slice(&MAGIC.to_le_bytes());
        buf.extend_from_slice(&footer);
        self.f.write_all(&buf)?;
        self.f.sync_all()?;
        Ok(())
    }
}

pub struct SstReader {
    f: File,
    index: Vec<(Vec<u8>, u64)>,
    entries: u32,
}

impl SstReader {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let f = OpenOptions::new().read(true).open(path)?;
        let len = f.metadata()?.len();
        if len < 28 {
            return Err(Error::Corrupt("sst too small".into()));
        }
        let mut footer = [0u8; 28];
        if !f.read_exact_at(&mut footer, len - 28)? {
            return Err(Error::Corrupt("sst footer".into()));
        }
        if u64::from_le_bytes(footer[20..28].try_into().unwrap()) != MAGIC {
            return Err(Error::Corrupt("sst magic".into()));
        }
        if crc32fast::hash(&footer[..16]) != u32::from_le_bytes(footer[16..20].try_into().unwrap())
        {
            return Err(Error::Corrupt("sst footer crc".into()));
        }
        let index_off = u64::from_le_bytes(footer[..8].try_into().unwrap());
        let index_count = u32::from_le_bytes(footer[8..12].try_into().unwrap()) as u64;
        let entries = u32::from_le_bytes(footer[12..16].try_into().unwrap());
        if index_off > len - 28 {
            return Err(Error::Corrupt("sst index bounds".into()));
        }
        let mut index = Vec::with_capacity(index_count as usize);
        let mut off = index_off;
        for _ in 0..index_count {
            let mut hdr = [0u8; 2];
            if !f.read_exact_at(&mut hdr, off)? {
                return Err(Error::Corrupt("sst index".into()));
            }
            let klen = u16::from_le_bytes(hdr) as u64;
            let mut key = vec![0u8; klen as usize];
            if !f.read_exact_at(&mut key, off + 2)? {
                return Err(Error::Corrupt("sst index key".into()));
            }
            let mut pos = [0u8; 8];
            if !f.read_exact_at(&mut pos, off + 2 + klen)? {
                return Err(Error::Corrupt("sst index off".into()));
            }
            index.push((key, u64::from_le_bytes(pos)));
            off += 2 + klen + 8;
        }
        Ok(Self { f, index, entries })
    }

    fn locate(&self, key: &[u8]) -> u64 {
        // Largest index entry with stored key <= target.
        let mut lo = 0usize;
        let mut hi = self.index.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.index[mid].0.as_slice() <= key {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo == 0 {
            0
        } else {
            self.index[lo - 1].1
        }
    }

    /// Point lookup: newest table already guaranteed by caller ordering.
    /// Each key appears at most once per table.
    pub fn get(&self, key: &[u8]) -> Result<Option<(u64, Vec<u8>)>> {
        let mut off = self.locate(key);
        while let Some((body, next)) = codec::read_record_at(&self.f, off) {
            let (seq, k, ct) = decode(&body)?;
            if k == key {
                return Ok(Some((seq, ct.to_vec())));
            }
            if k > key {
                return Ok(None);
            }
            off = next;
        }
        Ok(None)
    }

    pub fn iter_from(&self, start: Option<&[u8]>) -> SstCursor<'_> {
        let off = match start {
            Some(k) => self.locate(k),
            None => 0,
        };
        SstCursor {
            f: &self.f,
            off,
            start: start.map(|k| k.to_vec()),
        }
    }

    pub fn entries(&self) -> u32 {
        self.entries
    }
}

fn decode(body: &[u8]) -> Result<(u64, &[u8], &[u8])> {
    codec::decode_entry_body(body).ok_or_else(|| Error::Corrupt("sst entry".into()))
}

pub struct SstCursor<'a> {
    f: &'a File,
    off: u64,
    start: Option<Vec<u8>>,
}

impl SstCursor<'_> {
    /// Yields (seq, key, ciphertext) in ascending key order, first key >= start.
    pub fn next_entry(&mut self) -> Option<Result<Entry>> {
        loop {
            let (body, next) = codec::read_record_at(self.f, self.off)?;
            self.off = next;
            let e = decode(&body).map(|(s, k, c)| (s, k.to_vec(), c.to_vec()));
            if let Ok((_, k, _)) = &e
                && let Some(start) = &self.start
                    && k < start {
                        continue;
                    }
            return Some(e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_read_roundtrip() {
        let dir = std::env::temp_dir().join(format!("sst-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.sst");
        let mut w = SstWriter::create(&path).unwrap();
        for i in 0..200u32 {
            let key = format!("key{:04}", i).into_bytes();
            w.write_entry(i as u64, &key, b"ct").unwrap();
        }
        w.finish().unwrap();
        let r = SstReader::open(&path).unwrap();
        assert_eq!(r.entries(), 200);
        for i in 0..200u32 {
            let key = format!("key{:04}", i).into_bytes();
            let (seq, ct) = r.get(&key).unwrap().unwrap();
            assert_eq!(seq, i as u64);
            assert_eq!(ct, b"ct");
        }
        assert!(r.get(b"key9999").unwrap().is_none());
        let mut c = r.iter_from(Some(b"key0050"));
        let (s, k, _) = c.next_entry().unwrap().unwrap();
        assert_eq!(s, 50);
        assert_eq!(k, b"key0050");
        std::fs::remove_dir_all(&dir).ok();
    }
}
