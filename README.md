# lsm-seal

Tailored SurrealKV compact key-value wrapper. Purpose-built embedded key-value
engine pairing an append-only LSM tree with embedded AEAD authentication and
zstd compression directly in the storage layer.

Built for MindVote: single table, hex keys, prefix scans. Nothing else.

## What it replaces

SurrealKV is a generic key-value store; MindVote needs one table with prefix
scans, hex keys, and AEAD-authenticated values. lsm-seal drops the generic
machinery and the Tokio runtime isolation boilerplate (`run_db`, `InnerDb`)
that comes with it. The API is synchronous, there are no background threads,
and `close()` consumes the handle — instant, zero-lock shutdown by
construction. Half the dependency tree, half the binary size.

## Properties

- **Append-only LSM tree** — memtable + WAL + sstables, auto-flush at a
  configurable byte budget, full compaction that drops tombstones and
  superseded versions.
- **AEAD at the storage layer** — every value is sealed with ChaCha20-Poly1305.
  Nonces derive from the entry sequence number; AAD binds entry key and
  sequence so ciphertext cannot be spliced, reordered, or moved across keys.
  Wrong key, tampered bytes, or forged records fail closed with `Error::Crypto`.
- **zstd compression** — values >= 128 bytes are zstd-compressed before sealing.
- **Crash-safe WAL** — record-level CRC; torn tails are truncated cleanly on
  recovery. `sync()` for durable writes, `flush()` to persist memtable to an
  sstable and rotate the WAL, `close()` to sync everything and shut down.
- **Hex-key contract** — keys are enforced ascii-hex, even length
  (`Options::hex_keys`, on by default). Empty prefix = full table scan.

## Usage

```rust
use lsm_seal::{Db, SealKey, Options};

let key = SealKey::generate(); // or SealKey::new([u8; 32])
let db = Db::open("./data", &key)?;

db.put(b"a1b2c3", b"payload")?;
assert_eq!(db.get(b"a1b2c3")?, Some(b"payload".to_vec()));

let rows = db.scan_prefix(b"a1")?; // ascending (key, value), deletes hidden
db.delete(b"a1b2c3")?;

db.flush()?; // memtable -> sstable, WAL rotates
db.compact()?; // merge sstables, drop tombstones
db.close()?; // instant, zero-lock
```

Tuning:

```rust
let opts = Options {
    hex_keys: true,          // enforce hex keys (default true)
    compress_level: 3,       // zstd level
    memtable_bytes: 4 << 20, // auto-flush budget
    compact_threshold: 4,    // compact at this many sstables
    sync_writes: false,      // fsync WAL on every write
};
let db = Db::open_with("./data", &key, opts)?;
```

## Layout

```
data/
  MANIFEST      # atomic (write + rename + dir fsync)
  wal/000001.wal
  sst/000002.sst
```

## Build

```
cargo build --release   # lto=fat, codegen-units=1, panic=abort, strip
cargo test
cargo run --release --example bench
```
