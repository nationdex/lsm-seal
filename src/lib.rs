//! lsm-seal: tailored SurrealKV compact key-value wrapper.
//!
//! Append-only LSM tree with embedded AEAD authentication (ChaCha20-Poly1305)
//! and zstd compression directly in the storage layer. Single table, hex keys,
//! prefix scans. No async runtime, no background threads, no isolation
//! boilerplate: closing is instant and lock-free.
//!
//! ```no_run
//! use lsm_seal::{Db, SealKey};
//!
//! let key = SealKey::generate();
//! let db = Db::open("./data", &key)?;
//! db.put(b"a1b2", b"hello")?;
//! assert_eq!(db.get(b"a1b2")?, Some(b"hello".to_vec()));
//! let rows = db.scan_prefix(b"a1")?;
//! db.close()?;
//! # Ok::<(), lsm_seal::Error>(())
//! ```

mod codec;
mod crypto;
mod db;
mod error;
mod sstable;
mod wal;

pub use crypto::SealKey;
pub use db::{is_hex_key, Db, Options, Stats};
pub use error::{Error, Result};
