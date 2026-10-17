//! The disk-backed path snapshot (port of snapshot_store.py): SQLite, the same
//! file and schema, so a machine switching builds keeps its snapshot and is
//! not re-alerted on everything it already saw.
//!
//!   table paths(path PRIMARY KEY, mtime REAL, gen INTEGER)
//!   * each polling pass takes a new generation number;
//!   * upsert_batch() writes rows and reports which paths are new or newer;
//!   * sweep_deleted() drops rows the latest pass didn't see.

use std::path::Path;

use rusqlite::{params, params_from_iter, Connection, OptionalExtension};

pub type Res<T> = rusqlite::Result<T>;

pub struct Store {
    conn: Option<Connection>,
}

/// "new" or "changed"
pub type Change = (String, &'static str);

const UPSERT: &str = "INSERT INTO paths(path,mtime,gen) VALUES(?,?,?) \
                      ON CONFLICT(path) DO UPDATE SET mtime=excluded.mtime, gen=excluded.gen";

impl Store {
    pub fn open(db: &Path) -> Res<Store> {
        let conn = Connection::open(db)?;
        conn.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(()))?;
        conn.execute_batch(
            "PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS paths ( path TEXT PRIMARY KEY, mtime REAL NOT NULL, gen INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER);",
        )?;
        Ok(Store { conn: Some(conn) })
    }

    fn c(&self) -> &Connection {
        self.conn.as_ref().expect("snapshot store is open")
    }

    pub fn current_generation(&self) -> Res<i64> {
        Ok(self
            .c()
            .query_row("SELECT v FROM meta WHERE k='gen'", [], |r| {
                r.get::<_, Option<i64>>(0)
            })
            .optional()?
            .flatten()
            .unwrap_or(0))
    }

    pub fn next_generation(&self) -> Res<i64> {
        let gen = self.current_generation()? + 1;
        self.c().execute(
            "INSERT INTO meta(k,v) VALUES('gen',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            [gen],
        )?;
        Ok(gen)
    }

    pub fn is_empty(&self) -> Res<bool> {
        Ok(self
            .c()
            .query_row("SELECT 1 FROM paths LIMIT 1", [], |_| Ok(()))
            .optional()?
            .is_none())
    }

    /// Forgets a deleted path and everything under it, so a file put back at
    /// the same path with the same date is new again.
    pub fn remove(&self, path: &str) -> Res<usize> {
        let sep = if cfg!(windows) { '\\' } else { '/' };
        let under = format!("{}{sep}", path.trim_end_matches(sep));
        self.c().execute(
            "DELETE FROM paths WHERE path=? OR substr(path, 1, length(?))=?",
            [path, &under, &under],
        )
    }

    pub fn contains(&self, path: &str) -> Res<bool> {
        Ok(self
            .c()
            .query_row("SELECT 1 FROM paths WHERE path=?", [path], |_| Ok(()))
            .optional()?
            .is_some())
    }

    pub fn count(&self) -> Res<i64> {
        self.c()
            .query_row("SELECT COUNT(*) FROM paths", [], |r| r.get(0))
    }

    fn write_rows(&self, batch: &[(String, f64)], gen: i64) -> Res<()> {
        let tx = self.c().unchecked_transaction()?;
        {
            let mut st = tx.prepare_cached(UPSERT)?;
            for (p, m) in batch {
                st.execute(params![p, m, gen])?;
            }
        }
        tx.commit()
    }

    /// Records a batch of (path, mtime) and returns the paths that are new or
    /// have a newer mtime than the snapshot holds.
    pub fn upsert_batch(&self, batch: &[(String, f64)], gen: i64) -> Res<Vec<Change>> {
        if batch.is_empty() {
            return Ok(vec![]);
        }
        let mut existing = std::collections::HashMap::new();
        for chunk in batch.chunks(500) {
            let q = format!(
                "SELECT path, mtime FROM paths WHERE path IN ({})",
                vec!["?"; chunk.len()].join(",")
            );
            let mut st = self.c().prepare(&q)?;
            let rows = st.query_map(params_from_iter(chunk.iter().map(|(p, _)| p)), |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, f64>(1)?))
            })?;
            for row in rows {
                let (p, m) = row?;
                existing.insert(p, m);
            }
        }
        let mut changes = vec![];
        for (path, mtime) in batch {
            match existing.get(path) {
                None => changes.push((path.clone(), "new")),
                // any change: a file swapped for one with an older date
                // (a Finder copy keeps the original's) is changed too
                Some(prev) if mtime != prev => changes.push((path.clone(), "changed")),
                _ => {}
            }
        }
        self.write_rows(batch, gen)?;
        Ok(changes)
    }

    /// First run: record rows without reporting changes.
    pub fn touch_batch(&self, batch: &[(String, f64)], gen: i64) -> Res<()> {
        self.write_rows(batch, gen)
    }

    /// Drops rows the latest pass didn't see (deleted files).
    pub fn sweep_deleted(&self, gen: i64) -> Res<usize> {
        self.c().execute("DELETE FROM paths WHERE gen < ?", [gen])
    }

    pub fn close(&mut self) {
        if let Some(c) = self.conn.take() {
            let _ = c.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generations_and_changes() {
        let dir = std::env::temp_dir().join(format!("guard-store-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut s = Store::open(&dir.join("s.db")).unwrap();
        assert!(s.is_empty().unwrap());
        let g = s.next_generation().unwrap();
        assert_eq!(g, 1);
        let b = vec![("a".to_string(), 1.5), ("b".to_string(), 2.0)];
        assert_eq!(s.upsert_batch(&b, g).unwrap().len(), 2);
        let g2 = s.next_generation().unwrap();
        let ch = s
            .upsert_batch(&[("a".to_string(), 1.5), ("b".to_string(), 3.0)], g2)
            .unwrap();
        assert_eq!(ch, vec![("b".to_string(), "changed")]);
        s.touch_batch(&[("c".to_string(), 0.0)], g2).unwrap();
        assert!(s.contains("c").unwrap());
        assert_eq!(s.sweep_deleted(g2).unwrap(), 0);
        let g3 = s.next_generation().unwrap();
        s.upsert_batch(&[("a".to_string(), 1.5)], g3).unwrap();
        assert_eq!(s.sweep_deleted(g3).unwrap(), 2);
        assert_eq!(s.count().unwrap(), 1);
        s.close();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
