use std::fs::OpenOptions;

use lsm_seal::{Db, Error, Options, SealKey};

fn tmp(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("lsm-seal-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn key32(fill: u8) -> SealKey {
    SealKey::new([fill; 32])
}

#[test]
fn put_get_delete_scan() {
    let dir = tmp("basic");
    let db = Db::open(&dir, &key32(1)).unwrap();
    db.put(b"aabb", b"one").unwrap();
    b"aabb01".to_vec();
    db.put(b"aabb01", b"two").unwrap();
    db.put(b"aabb02", b"three").unwrap();
    db.put(b"ff00", b"four").unwrap();

    assert_eq!(db.get(b"aabb").unwrap().unwrap(), b"one");
    assert_eq!(db.get(b"aabb01").unwrap().unwrap(), b"two");
    assert!(db.get(b"ffee00").unwrap().is_none());

    let rows = db.scan_prefix(b"aabb").unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0], (b"aabb".to_vec(), b"one".to_vec()));
    assert_eq!(rows[2], (b"aabb02".to_vec(), b"three".to_vec()));

    db.delete(b"aabb01").unwrap();
    assert!(db.get(b"aabb01").unwrap().is_none());
    let rows = db.scan_prefix(b"aabb").unwrap();
    assert_eq!(rows.len(), 2);

    db.close().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn hex_key_enforced() {
    let dir = tmp("hex");
    let db = Db::open(&dir, &key32(2)).unwrap();
    assert!(matches!(db.put(b"zzzz", b"x"), Err(Error::InvalidHexKey)));
    assert!(matches!(db.put(b"abc", b"x"), Err(Error::InvalidHexKey)));
    assert!(matches!(db.get(b"not hex!"), Err(Error::InvalidHexKey)));
    assert!(matches!(db.scan_prefix(b"xy"), Err(Error::InvalidHexKey)));
    db.close().unwrap();

    let opts = Options {
        hex_keys: false,
        ..Default::default()
    };
    let db = Db::open_with(&dir, &key32(2), opts).unwrap();
    db.put(b"any key", b"raw").unwrap();
    assert_eq!(db.get(b"any key").unwrap().unwrap(), b"raw");
    db.close().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn persistence_across_reopen() {
    let dir = tmp("persist");
    {
        let db = Db::open(&dir, &key32(3)).unwrap();
        for i in 0..500u32 {
            db.put(
                format!("dead{:04x}", i).as_bytes(),
                format!("v{i}").as_bytes(),
            )
            .unwrap();
        }
        db.delete(b"dead0000").unwrap();
        db.close().unwrap();
    }
    {
        let db = Db::open(&dir, &key32(3)).unwrap();
        assert!(db.get(b"dead0000").unwrap().is_none());
        assert_eq!(db.get(b"dead0001").unwrap().unwrap(), b"v1");
        assert_eq!(db.get(b"dead01f3").unwrap().unwrap(), b"v499");
        assert_eq!(db.scan_prefix(b"dead").unwrap().len(), 499);
        db.close().unwrap();
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wal_replay_after_drop_and_torn_tail() {
    let dir = tmp("torn");
    let key = key32(4);
    {
        let db = Db::open(&dir, &key).unwrap();
        db.put(b"cafe01", b"keep-me").unwrap();
        db.put(b"cafe02", b"also-keep").unwrap();
        db.put(b"cafe03", b"tail").unwrap();
        db.close().unwrap();
    }
    // Reopen, write more without close (simulate crash: data lives in WAL).
    {
        let db = Db::open(&dir, &key).unwrap();
        db.put(b"cafe04", b"wal-only").unwrap();
        db.sync().unwrap();
        // crash: no close, no drop flush
        std::mem::forget(db);
    }
    // Tear the WAL tail mid-record.
    let wal_dir = dir.join("wal");
    let wal_path = std::fs::read_dir(&wal_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .max()
        .unwrap();
    let f = OpenOptions::new().read(true).write(true).open(&wal_path).unwrap();
    let len = f.metadata().unwrap().len();
    f.set_len(len - 3).unwrap();
    f.sync_all().unwrap();

    let db = Db::open(&dir, &key).unwrap();
    assert_eq!(db.get(b"cafe01").unwrap().unwrap(), b"keep-me");
    assert_eq!(db.get(b"cafe02").unwrap().unwrap(), b"also-keep");
    assert_eq!(db.get(b"cafe03").unwrap().unwrap(), b"tail");
    assert!(db.get(b"cafe04").unwrap().is_none()); // torn away cleanly
    db.put(b"cafe05", b"after").unwrap();
    db.close().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wrong_key_rejected() {
    let dir = tmp("wrongkey");
    {
        let db = Db::open(&dir, &key32(5)).unwrap();
        db.put(b"beef00", b"secret").unwrap();
        db.close().unwrap();
    }
    let db = Db::open(&dir, &key32(6)).unwrap();
    assert!(matches!(db.get(b"beef00"), Err(Error::Crypto)));
    assert!(matches!(db.scan_prefix(b"beef"), Err(Error::Crypto)));
    db.close().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tamper_detected_in_sst() {
    let dir = tmp("tamper");
    let key = key32(7);
    let db = Db::open(&dir, &key).unwrap();
    for i in 0..100u32 {
        db.put(format!("aa{:04x}", i).as_bytes(), b"payload")
            .unwrap();
    }
    db.flush().unwrap();
    db.close().unwrap();

    // Tamper first record body and repair its crc: only AEAD can catch this.
    let sst = std::fs::read_dir(dir.join("sst"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .next()
        .unwrap();
    let mut data = std::fs::read(&sst).unwrap();
    let len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    data[8] ^= 0xff;
    let crc = crc32fast::hash(&data[8..8 + len]);
    data[4..8].copy_from_slice(&crc.to_le_bytes());
    std::fs::write(&sst, &data).unwrap();

    let db = Db::open(&dir, &key).unwrap();
    assert!(matches!(db.get(b"aa0000"), Err(Error::Crypto)));
    db.close().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn auto_flush_and_compaction() {
    let dir = tmp("compact");
    let opts = Options {
        memtable_bytes: 8 << 10,
        compact_threshold: 3,
        ..Default::default()
    };
    let db = Db::open_with(&dir, &key32(8), opts).unwrap();
    for i in 0..2000u32 {
        db.put(format!("bb{:04x}", i).as_bytes(), &[i as u8; 40])
            .unwrap();
    }
    for i in 0..1000u32 {
        db.put(format!("bb{:04x}", i).as_bytes(), &[0xeeu8; 40])
            .unwrap();
    }
    for i in 1000..1500u32 {
        db.delete(format!("bb{:04x}", i).as_bytes()).unwrap();
    }
    db.compact().unwrap();
    let stats = db.stats();
    assert_eq!(stats.sst_count, 1);

    for i in 0..1000u32 {
        assert_eq!(
            db.get(format!("bb{:04x}", i).as_bytes()).unwrap().unwrap(),
            vec![0xeeu8; 40]
        );
    }
    for i in 1000..1500u32 {
        assert!(db.get(format!("bb{:04x}", i).as_bytes()).unwrap().is_none());
    }
    for i in 1500..2000u32 {
        assert_eq!(
            db.get(format!("bb{:04x}", i).as_bytes()).unwrap().unwrap(),
            vec![i as u8; 40]
        );
    }
    assert_eq!(db.scan_prefix(b"bb").unwrap().len(), 1500);
    db.close().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn compression_roundtrip_large_values() {
    let dir = tmp("zstd");
    let db = Db::open(&dir, &key32(9)).unwrap();
    let big = vec![0xabu8; 100_000];
    let mixed: Vec<u8> = (0..50_000u32).map(|i| (i % 7) as u8).collect();
    db.put(b"cc0001", &big).unwrap();
    db.put(b"cc0002", &mixed).unwrap();
    db.put(b"cc0003", b"small").unwrap();
    db.flush().unwrap();
    assert_eq!(db.get(b"cc0001").unwrap().unwrap(), big);
    assert_eq!(db.get(b"cc0002").unwrap().unwrap(), mixed);
    assert_eq!(db.get(b"cc0003").unwrap().unwrap(), b"small");
    db.close().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn empty_scan_and_empty_close() {
    let dir = tmp("empty");
    let db = Db::open(&dir, &key32(10)).unwrap();
    assert!(db.scan_prefix(b"").unwrap().is_empty() || db.scan_prefix(b"aa").unwrap().is_empty());
    assert!(db.get(b"aa00").unwrap().is_none());
    db.close().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
