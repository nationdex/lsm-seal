use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::codec;
use crate::crypto::{Cipher, SealKey};
use crate::error::{Error, Result};
use crate::sstable::{Entry, SstCursor, SstReader, SstWriter};
use crate::wal::{self, Wal};

type MemTable = BTreeMap<Vec<u8>, (u64, Vec<u8>)>;
type Heads = Vec<Option<Entry>>;

pub struct Options {
    /// Enforce ascii-hex even-length keys (MindVote contract). Default: true.
    pub hex_keys: bool,
    /// zstd level for values >= 128 bytes. Default: 3.
    pub compress_level: i32,
    /// Memtable byte budget before auto-flush. Default: 4 MiB.
    pub memtable_bytes: usize,
    /// Full compaction triggers at this many sstables. Default: 4.
    pub compact_threshold: usize,
    /// fsync WAL on every write. Default: false (`flush`/`close` sync).
    pub sync_writes: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            hex_keys: true,
            compress_level: 3,
            memtable_bytes: 4 << 20,
            compact_threshold: 4,
            sync_writes: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Stats {
    pub mem_entries: usize,
    pub mem_bytes: usize,
    pub sst_count: usize,
    pub sst_entries: u64,
    pub next_seq: u64,
}

struct State {
    mem: MemTable,
    mem_bytes: usize,
    wal: Wal,
    wal_id: u64,
    ssts: Vec<(u64, Arc<SstReader>)>,
    next_seq: u64,
    next_file_id: u64,
    closed: bool,
}

/// Single-table embedded key-value engine. No async runtime, no background
/// threads: `close` is instant and lock-free by construction.
pub struct Db {
    root: PathBuf,
    cipher: Cipher,
    opts: Options,
    state: Mutex<State>,
}

impl Db {
    pub fn open(path: impl AsRef<Path>, key: &SealKey) -> Result<Self> {
        Self::open_with(path, key, Options::default())
    }

    pub fn open_with(path: impl AsRef<Path>, key: &SealKey, opts: Options) -> Result<Self> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("wal"))?;
        fs::create_dir_all(root.join("sst"))?;
        let cipher = Cipher::new(key);

        let state = if root.join("MANIFEST").exists() {
            recover(&root)?
        } else {
            let mut st = State {
                mem: MemTable::new(),
                mem_bytes: 0,
                wal: Wal::create(root.join("wal").join("000001.wal"))?,
                wal_id: 1,
                ssts: Vec::new(),
                next_seq: 1,
                next_file_id: 2,
                closed: false,
            };
            write_manifest(&root, &st)?;
            st.wal.sync()?;
            st
        };

        Ok(Self {
            root,
            cipher,
            opts,
            state: Mutex::new(state),
        })
    }

    fn check_key(&self, key: &[u8]) -> Result<()> {
        if self.opts.hex_keys && !is_hex_key(key) {
            return Err(Error::InvalidHexKey);
        }
        Ok(())
    }

    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        self.write(key, Some(value))
    }

    pub fn delete(&self, key: &[u8]) -> Result<()> {
        self.write(key, None)
    }

    fn write(&self, key: &[u8], value: Option<&[u8]>) -> Result<()> {
        self.check_key(key)?;
        let frame = codec::encode_value(value, self.opts.compress_level);
        let mut st = self.state.lock().unwrap();
        if st.closed {
            return Err(Error::Closed);
        }
        let seq = st.next_seq;
        st.next_seq += 1;
        let ct = self.cipher.seal(seq, key, &frame)?;
        st.wal.append(&codec::encode_entry_body(seq, key, &ct))?;
        if self.opts.sync_writes {
            st.wal.sync()?;
        }
        st.mem_bytes += key.len() + ct.len() + 16;
        if let Some((_, old)) = st.mem.insert(key.to_vec(), (seq, ct)) {
            st.mem_bytes = st.mem_bytes.saturating_sub(old.len() + 16);
        }
        if st.mem_bytes >= self.opts.memtable_bytes {
            flush_locked(
                &self.root,
                &self.cipher,
                self.opts.compact_threshold,
                &mut st,
            )?;
        }
        Ok(())
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.check_key(key)?;
        let st = self.state.lock().unwrap();
        if st.closed {
            return Err(Error::Closed);
        }
        if let Some((seq, ct)) = st.mem.get(key) {
            return decode_entry(&self.cipher, *seq, key, ct);
        }
        for (_, sst) in st.ssts.iter().rev() {
            if let Some((seq, ct)) = sst.get(key)? {
                return decode_entry(&self.cipher, seq, key, &ct);
            }
        }
        Ok(None)
    }

    /// Prefix scan over the single table. Ascending (key, value) pairs;
    /// deleted and superseded keys hidden.
    pub fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        if !prefix.is_empty() {
            self.check_key(prefix)?;
        }
        let (mem, ssts) = {
            let st = self.state.lock().unwrap();
            if st.closed {
                return Err(Error::Closed);
            }
            let mem = st
                .mem
                .range(prefix.to_vec()..)
                .map(|(k, (seq, ct))| (*seq, k.clone(), ct.clone()))
                .collect::<Vec<_>>();
            let ssts = st
                .ssts
                .iter()
                .rev()
                .map(|(_, s)| s.clone())
                .collect::<Vec<_>>();
            (mem, ssts)
        };
        merge_scan(&self.cipher, prefix, &mem, &ssts)
    }

    /// Durably sync the WAL without rotating it.
    pub fn sync(&self) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        if st.closed {
            return Err(Error::Closed);
        }
        st.wal.sync()
    }

    /// Persist memtable to an sstable and rotate the WAL.
    pub fn flush(&self) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        if st.closed {
            return Err(Error::Closed);
        }
        flush_locked(
            &self.root,
            &self.cipher,
            self.opts.compact_threshold,
            &mut st,
        )
    }

    /// Merge all sstables, drop tombstones and superseded versions.
    pub fn compact(&self) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        if st.closed {
            return Err(Error::Closed);
        }
        compact_locked(&self.root, &self.cipher, &mut st)
    }

    pub fn stats(&self) -> Stats {
        let st = self.state.lock().unwrap();
        Stats {
            mem_entries: st.mem.len(),
            mem_bytes: st.mem_bytes,
            sst_count: st.ssts.len(),
            sst_entries: st.ssts.iter().map(|(_, s)| s.entries() as u64).sum(),
            next_seq: st.next_seq,
        }
    }

    /// Persist and close. Consumes the handle: zero lock contention.
    pub fn close(mut self) -> Result<()> {
        let st = self.state.get_mut().unwrap();
        if st.closed {
            return Ok(());
        }
        flush_locked(
            &self.root,
            &self.cipher,
            self.opts.compact_threshold,
            st,
        )?;
        st.closed = true;
        Ok(())
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        if let Ok(st) = self.state.get_mut()
            && !st.closed {
                let _ = flush_locked(&self.root, &self.cipher, self.opts.compact_threshold, st);
                st.closed = true;
            }
    }
}

fn decode_entry(cipher: &Cipher, seq: u64, key: &[u8], ct: &[u8]) -> Result<Option<Vec<u8>>> {
    let frame = cipher.open(seq, key, ct)?;
    codec::decode_value(&frame)
}

/// K-way merge: memtable first (newest), then sstables newest-first.
/// Winner per key = highest sequence number. Errors from a source fail the scan.
fn merge_scan(
    cipher: &Cipher,
    prefix: &[u8],
    mem: &[Entry],
    ssts: &[Arc<SstReader>],
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut cursors: Vec<SstCursor<'_>> = ssts.iter().map(|s| s.iter_from(Some(prefix))).collect();
    let mut mem_i = 0usize;
    let mut heads: Heads = Vec::with_capacity(1 + ssts.len());
    for _ in 0..1 + ssts.len() {
        heads.push(None);
    }

    let pull = |heads: &mut Heads,
                    mem: &[Entry],
                    mem_i: &mut usize,
                    cursors: &mut Vec<SstCursor<'_>>,
                    i: usize|
     -> Result<()> {
        if heads[i].is_some() {
            return Ok(());
        }
        if i == 0 {
            if *mem_i < mem.len() {
                heads[0] = Some(mem[*mem_i].clone());
                *mem_i += 1;
            }
        } else {
            if let Some(e) = cursors[i - 1].next_entry() { heads[i] = Some(e?) }
        }
        Ok(())
    };

    let mut out = Vec::new();
    loop {
        for i in 0..heads.len() {
            pull(&mut heads, mem, &mut mem_i, &mut cursors, i)?;
        }
        // Sources are ascending: any head outside the prefix means source done.
        for h in heads.iter_mut() {
            if let Some((_, k, _)) = h
                && !k.starts_with(prefix) {
                    *h = None;
                }
        }
        let mut best: Option<(Vec<u8>, usize)> = None;
        for (i, h) in heads.iter().enumerate() {
            if let Some((_, k, _)) = h
                && best
                    .as_ref()
                    .is_none_or(|(bk, bi)| k < bk || (k == bk && i < *bi))
            {
                best = Some((k.clone(), i));
            }
        }
        let Some((key, _)) = best else { break };

        let mut winner: Option<(u64, Vec<u8>)> = None;
        for h in heads.iter_mut() {
            if let Some((seq, k, ct)) = h.take() {
                if k == key {
                    match &winner {
                        Some((wseq, _)) if *wseq >= seq => {}
                        _ => winner = Some((seq, ct)),
                    }
                } else {
                    *h = Some((seq, k, ct));
                }
            }
        }
        if let Some((seq, ct)) = winner
            && let Some(v) = decode_entry(cipher, seq, &key, &ct)? {
                out.push((key, v));
            }
    }
    Ok(out)
}

fn flush_locked(root: &Path, cipher: &Cipher, threshold: usize, st: &mut State) -> Result<()> {
    if st.mem.is_empty() {
        return Ok(());
    }
    let mem = std::mem::take(&mut st.mem);
    st.mem_bytes = 0;

    let sst_id = st.next_file_id;
    st.next_file_id += 1;
    let sst_path = root.join("sst").join(format!("{sst_id:06}.sst"));
    let mut w = SstWriter::create(&sst_path)?;
    for (k, (seq, ct)) in &mem {
        w.write_entry(*seq, k, ct)?;
    }
    w.finish()?;

    let wal_id = st.next_file_id;
    st.next_file_id += 1;
    let old_wal = st.wal.path().to_path_buf();
    st.wal = Wal::create(root.join("wal").join(format!("{wal_id:06}.wal")))?;
    st.wal_id = wal_id;
    st.ssts
        .push((sst_id, Arc::new(SstReader::open(&sst_path)?)));

    write_manifest(root, st)?;
    st.wal.sync()?;
    fs::remove_file(old_wal)?;

    if st.ssts.len() >= threshold {
        compact_locked(root, cipher, st)?;
    }
    Ok(())
}

fn compact_locked(root: &Path, cipher: &Cipher, st: &mut State) -> Result<()> {
    if st.ssts.is_empty() {
        return Ok(());
    }
    let sst_id = st.next_file_id;
    st.next_file_id += 1;
    let sst_path = root.join("sst").join(format!("{sst_id:06}.sst"));
    let mut w = SstWriter::create(&sst_path)?;

    let ssts: Vec<Arc<SstReader>> = st.ssts.iter().map(|(_, s)| s.clone()).collect();
    let mut cursors: Vec<SstCursor<'_>> = ssts.iter().map(|s| s.iter_from(None)).collect();
    let mut heads: Heads = vec![None; ssts.len()];

    loop {
        for (i, c) in cursors.iter_mut().enumerate() {
            if heads[i].is_none() {
                heads[i] = c.next_entry().transpose()?;
            }
        }
        let mut best: Option<(Vec<u8>, usize)> = None;
        for (i, h) in heads.iter().enumerate() {
            if let Some((_, k, _)) = h
                && best
                    .as_ref()
                    .is_none_or(|(bk, bi)| k < bk || (k == bk && i < *bi))
            {
                best = Some((k.clone(), i));
            }
        }
        let Some((key, _)) = best else { break };

        let mut winner: Option<(u64, Vec<u8>)> = None;
        for h in heads.iter_mut() {
            if let Some((seq, k, ct)) = h.take() {
                if k == key {
                    match &winner {
                        Some((wseq, _)) if *wseq >= seq => {}
                        _ => winner = Some((seq, ct)),
                    }
                } else {
                    *h = Some((seq, k, ct));
                }
            }
        }
        if let Some((seq, ct)) = winner
            && decode_entry(cipher, seq, &key, &ct)?.is_some() {
                w.write_entry(seq, &key, &ct)?;
            }
    }
    w.finish()?;

    let old: Vec<u64> = st.ssts.iter().map(|(id, _)| *id).collect();
    st.ssts = vec![(sst_id, Arc::new(SstReader::open(&sst_path)?))];
    write_manifest(root, st)?;
    for id in old {
        let _ = fs::remove_file(root.join("sst").join(format!("{id:06}.sst")));
    }
    Ok(())
}

fn write_manifest(root: &Path, st: &State) -> Result<()> {
    let mut buf = String::with_capacity(256);
    buf.push_str("lsm-seal 1\n");
    buf.push_str(&format!("next_seq {}\n", st.next_seq));
    buf.push_str(&format!("next_file_id {}\n", st.next_file_id));
    buf.push_str(&format!("wal {}\n", st.wal_id));
    for (id, _) in &st.ssts {
        buf.push_str(&format!("sst {id}\n"));
    }
    let tmp = root.join("MANIFEST.tmp");
    let mut f = File::create(&tmp)?;
    f.write_all(buf.as_bytes())?;
    f.sync_all()?;
    fs::rename(&tmp, root.join("MANIFEST"))?;
    File::open(root)?.sync_all()?;
    Ok(())
}

fn recover(root: &Path) -> Result<State> {
    let text = fs::read_to_string(root.join("MANIFEST"))?;
    let mut next_seq = 0u64;
    let mut next_file_id = 0u64;
    let mut wal_id = 0u64;
    let mut sst_ids: Vec<u64> = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if i == 0 {
            if line != "lsm-seal 1" {
                return Err(Error::Corrupt("manifest version".into()));
            }
            continue;
        }
        let mut it = line.split_whitespace();
        let (Some(k), Some(v)) = (it.next(), it.next()) else {
            return Err(Error::Corrupt("manifest line".into()));
        };
        let v: u64 = v
            .parse()
            .map_err(|_| Error::Corrupt("manifest num".into()))?;
        match k {
            "next_seq" => next_seq = v,
            "next_file_id" => next_file_id = v,
            "wal" => wal_id = v,
            "sst" => sst_ids.push(v),
            _ => return Err(Error::Corrupt("manifest key".into())),
        }
    }
    if wal_id == 0 {
        return Err(Error::Corrupt("manifest wal".into()));
    }
    let mut ssts = Vec::with_capacity(sst_ids.len());
    for id in &sst_ids {
        ssts.push((
            *id,
            Arc::new(SstReader::open(
                root.join("sst").join(format!("{id:06}.sst")),
            )?),
        ));
    }
    let wal_path = root.join("wal").join(format!("{wal_id:06}.wal"));
    let mut mem = MemTable::new();
    let mut mem_bytes = 0usize;
    let (max_seq, _) = wal::replay(&wal_path, |seq, key, ct| {
        mem_bytes += key.len() + ct.len() + 16;
        mem.insert(key.to_vec(), (seq, ct.to_vec()));
        Ok(())
    })?;
    next_seq = next_seq.max(max_seq + 1).max(1);
    let max_id = wal_id
        .max(sst_ids.iter().copied().max().unwrap_or(0))
        .max(next_file_id.saturating_sub(1));
    Ok(State {
        mem,
        mem_bytes,
        wal: Wal::open(wal_path)?,
        wal_id,
        ssts,
        next_seq,
        next_file_id: max_id + 1,
        closed: false,
    })
}

pub fn is_hex_key(key: &[u8]) -> bool {
    !key.is_empty()
        && key.len().is_multiple_of(2)
        && key
            .iter()
            .all(|b: &u8| b.is_ascii_hexdigit())
}
