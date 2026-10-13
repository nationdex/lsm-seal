use std::time::Instant;

use lsm_seal::{Db, SealKey};

fn main() {
    let dir = std::env::temp_dir().join(format!("lsm-seal-bench-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let key = SealKey::generate();
    let n: u32 = 20_000;

    let t = Instant::now();
    let db = Db::open(&dir, &key).unwrap();
    let payload = vec![0x5au8; 256];
    for i in 0..n {
        db.put(format!("{:08x}", i * 2654435761u32).as_bytes(), &payload)
            .unwrap();
    }
    let w = t.elapsed();

    let t = Instant::now();
    for i in 0..n {
        db.get(format!("{:08x}", i * 2654435761u32).as_bytes())
            .unwrap()
            .unwrap();
    }
    let r = t.elapsed();

    let t = Instant::now();
    let rows = db.scan_prefix(b"0000").unwrap();
    let s = t.elapsed();

    let t = Instant::now();
    db.close().unwrap();
    let c = t.elapsed();

    println!(
        "put    {n:>6}  {w:>10.2?}  ({:.0} ops/s)",
        n as f64 / w.as_secs_f64()
    );
    println!(
        "get    {n:>6}  {r:>10.2?}  ({:.0} ops/s)",
        n as f64 / r.as_secs_f64()
    );
    println!("scan   {:>6}  {s:>10.2?}", rows.len());
    println!("close         {c:>10.2?}");
    let _ = std::fs::remove_dir_all(&dir);
}
