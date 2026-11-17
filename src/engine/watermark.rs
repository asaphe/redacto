use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Watermark {
    files: HashMap<String, FileState>,
    // Fingerprint of the rules that produced each cached unresolved result; under different rules the file is read again.
    #[serde(default)]
    rules: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileState {
    mtime_nanos: u128,
    size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unresolved: Option<Unresolved>,
}

// What a file holds that needs a human, kept so an unchanged file is reported again without being re-read.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Unresolved {
    pub pem_orphan_begin: usize,
    pub pem_orphan_end: usize,
    pub pem_aborted_lines: Vec<usize>,
    pub unsafe_lines: Vec<usize>,
}

fn nanos_of(mtime: SystemTime) -> Option<u128> {
    mtime
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_nanos())
}

// Canonicalizes so the same file is recognized under any relative path it's invoked with; falls back to the given path if canonicalization fails (e.g. a symlink race), which only costs a redundant re-scan, never a false "unchanged".
fn key_for(path: &Path) -> String {
    std::fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .to_string()
}

impl Watermark {
    // Clean stamps survive a rules change as they always have; only cached unresolved results are dropped with it.
    pub fn load(state_path: &Path, rules: &str) -> Self {
        let mut wm: Self = std::fs::read_to_string(state_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        if wm.rules != rules {
            wm.files.retain(|_, state| state.unresolved.is_none());
            wm.rules = rules.to_string();
        }
        wm
    }

    pub fn save(&self, state_path: &Path) -> Result<()> {
        if let Some(parent) = state_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        // Temp + rename: a run killed mid-write would otherwise leave torn JSON, which loads as empty and forces a full re-scan.
        let tmp = state_path.with_extension(format!("json.tmp-{}", std::process::id()));
        if let Err(e) = std::fs::write(&tmp, json).and_then(|()| std::fs::rename(&tmp, state_path))
        {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
        Ok(())
    }

    // True when this file's mtime+size match what we recorded on its last successful scan — safe to skip. Nanosecond precision (not seconds): second-granularity let a same-second file replacement (rsync -a/cp -p preserve mtimes) go undetected.
    pub fn is_unchanged(&self, path: &Path, mtime: SystemTime, size: u64) -> bool {
        self.matching(path, mtime, size)
            .is_some_and(|state| state.unresolved.is_none())
    }

    // The cached result for a file whose bytes have not changed since it was last read in full.
    pub fn cached_unresolved(
        &self,
        path: &Path,
        mtime: SystemTime,
        size: u64,
    ) -> Option<Unresolved> {
        self.matching(path, mtime, size)
            .and_then(|state| state.unresolved.clone())
    }

    pub fn record(&mut self, path: &Path, mtime: SystemTime, size: u64) {
        self.insert(path, mtime, size, None);
    }

    pub fn record_unresolved(
        &mut self,
        path: &Path,
        mtime: SystemTime,
        size: u64,
        found: Unresolved,
    ) {
        self.insert(path, mtime, size, Some(found));
    }

    fn matching(&self, path: &Path, mtime: SystemTime, size: u64) -> Option<&FileState> {
        let state = self.files.get(&key_for(path))?;
        (Some(state.mtime_nanos) == nanos_of(mtime) && state.size == size).then_some(state)
    }

    fn insert(
        &mut self,
        path: &Path,
        mtime: SystemTime,
        size: u64,
        unresolved: Option<Unresolved>,
    ) {
        self.files.insert(
            key_for(path),
            FileState {
                mtime_nanos: nanos_of(mtime).unwrap_or(0),
                size,
                unresolved,
            },
        );
    }
}

pub fn default_state_path() -> PathBuf {
    let base = std::env::var("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(".local/state"))
                .unwrap_or_else(|_| PathBuf::from(".redacto-state"))
        });
    base.join("redacto").join("watermark.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("watermark.json");
        let target = Path::new("/some/file.jsonl");
        let mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

        let mut wm = Watermark::load(&state_path, "rules");
        assert!(!wm.is_unchanged(target, mtime, 100));
        wm.record(target, mtime, 100);
        wm.save(&state_path).unwrap();

        let reloaded = Watermark::load(&state_path, "rules");
        assert!(reloaded.is_unchanged(target, mtime, 100));
        assert!(
            !reloaded.is_unchanged(target, mtime, 200),
            "size change must invalidate"
        );
        assert!(
            !reloaded.is_unchanged(target, mtime + Duration::from_secs(1), 100),
            "mtime change must invalidate"
        );
    }

    #[test]
    fn detects_a_same_second_same_size_file_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("watermark.json");
        let target = Path::new("/some/other-file.jsonl");
        let mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let mtime_same_second_later_nanos = mtime + Duration::from_nanos(500);

        let mut wm = Watermark::load(&state_path, "rules");
        wm.record(target, mtime, 100);
        assert!(
            !wm.is_unchanged(target, mtime_same_second_later_nanos, 100),
            "a replacement within the same second (rsync -a/cp -p preserve mtimes) must not be missed"
        );
    }
}
