use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;

use crate::codec;
use crate::error::Result;

/// Append-only write-ahead log. Records: [len][crc][seq|klen|key|ct].
pub struct Wal {
    path: std::path::PathBuf,
    writer: BufWriter<File>,
}

impl Wal {
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)?;
        Ok(Self {
            path,
            writer: BufWriter::with_capacity(64 << 10, file),
        })
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            writer: BufWriter::with_capacity(64 << 10, file),
        })
    }

    pub fn append(&mut self, body: &[u8]) -> Result<()> {
        codec::write_record(&mut self.writer, body)?;
        Ok(())
    }

    pub fn sync(&mut self) -> Result<()> {
        self.writer.flush()?;
        self.writer.get_ref().sync_data()?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

}

impl Drop for Wal {
    fn drop(&mut self) {
        let _ = self.writer.flush();
    }
}

/// Replays a WAL into `sink`. Torn tail is truncated; returns next sequence
/// number seen and whether truncation happened.
pub fn replay<F>(path: &Path, mut sink: F) -> Result<(u64, bool)>
where
    F: FnMut(u64, &[u8], &[u8]) -> Result<()>,
{
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    let total = file.metadata()?.len();
    let mut off = 0u64;
    let mut max_seq = 0u64;
    while off < total {
        match codec::read_record_at(&file, off) {
            Some((body, next)) => {
                let (seq, key, ct) = codec::decode_entry_body(&body)
                    .ok_or_else(|| crate::error::Error::Corrupt("wal entry".into()))?;
                max_seq = max_seq.max(seq);
                sink(seq, key, ct)?;
                off = next;
            }
            None => {
                file.set_len(off)?;
                file.sync_all()?;
                return Ok((max_seq, true));
            }
        }
    }
    Ok((max_seq, false))
}
