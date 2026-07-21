use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Watermark {
    files: HashMap<String, FileState>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct FileState {
    mtime_nanos: u128,
    size: u64,
}

// Canonicalizes so the same file is recognized under any relative path it's invoked with; falls back to the given path if canonicalization fails (e.g. a symlink race), which only costs a redundant re-scan, never a false "unchanged".
fn key_for(path: &Path) -> String {
    std::fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .to_string()
}

impl Watermark {
    pub fn load(state_path: &Path) -> Self {
        std::fs::read_to_string(state_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, state_path: &Path) -> Result<()> {
        if let Some(parent) = state_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(state_path, json)?;
        Ok(())
    }

    // True when this file's mtime+size match what we recorded on its last successful scan — safe to skip. Nanosecond precision (not seconds): second-granularity let a same-second file replacement (rsync -a/cp -p preserve mtimes) go undetected.
    pub fn is_unchanged(&self, path: &Path, mtime: SystemTime, size: u64) -> bool {
        let Some(state) = self.files.get(&key_for(path)) else {
            return false;
        };
        let Ok(elapsed) = mtime.duration_since(std::time::UNIX_EPOCH) else {
            return false;
        };
        state.mtime_nanos == elapsed.as_nanos() && state.size == size
    }

    pub fn record(&mut self, path: &Path, mtime: SystemTime, size: u64) {
        let nanos = mtime
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        self.files.insert(
            key_for(path),
            FileState {
                mtime_nanos: nanos,
                size,
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

        let mut wm = Watermark::load(&state_path);
        assert!(!wm.is_unchanged(target, mtime, 100));
        wm.record(target, mtime, 100);
        wm.save(&state_path).unwrap();

        let reloaded = Watermark::load(&state_path);
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

        let mut wm = Watermark::load(&state_path);
        wm.record(target, mtime, 100);
        assert!(
            !wm.is_unchanged(target, mtime_same_second_later_nanos, 100),
            "a replacement within the same second (rsync -a/cp -p preserve mtimes) must not be missed"
        );
    }
}
