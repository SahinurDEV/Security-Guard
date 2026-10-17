//! Native file-change events for the watcher (step 3 of the Rust migration).
//!
//! Wraps the `notify` crate: inotify on Linux, FSEvents on macOS,
//! ReadDirectoryChangesW on Windows. Events are coalesced into a bounded,
//! de-duplicated queue of paths that Python drains; Python still stats each
//! path and diffs it against the SQLite snapshot, so it decides what changed
//! exactly as the polling pass does. When the OS drops events (inotify queue
//! overflow, FSEvents "must rescan") or the queue cap is hit, `overflow` is
//! set and Python falls back to one full snapshot pass.
//!
//! inotify has no recursive mode: one watch per directory. `notify`'s own
//! recursive mode would also watch every `node_modules`, so on Linux we watch
//! each directory non-recursively, pruned by the same excludes and depth
//! limit as the polling walk, and add watches for directories as they appear.

use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

/// Most recent error messages kept for Python to log.
const MAX_ERRORS: usize = 32;

#[derive(Default)]
struct Queue {
    paths: Vec<PathBuf>,
    seen: HashSet<PathBuf>,
    overflow: bool,
    errors: Vec<String>,
}

struct Shared {
    queue: Mutex<Queue>,
    ready: Condvar,
}

#[derive(Clone)]
struct Filter {
    roots: Vec<PathBuf>,
    exclude: HashSet<OsString>,
    ignore: Vec<PathBuf>,
    max_depth: usize,
}

impl Filter {
    /// The deepest watch root containing `path`.
    fn root_of(&self, path: &Path) -> Option<&PathBuf> {
        self.roots
            .iter()
            .filter(|r| path.starts_with(r))
            .max_by_key(|r| r.components().count())
    }

    /// False for paths inside an excluded directory, an ignored prefix
    /// (Guard's own state dir) or outside every root. With `is_dir` the last
    /// component counts too; event paths leave it to Python, which knows
    /// whether a file named like an excluded directory is a file.
    fn wanted(&self, path: &Path, is_dir: bool) -> bool {
        if self.ignore.iter().any(|p| path.starts_with(p)) {
            return false;
        }
        let Some(root) = self.root_of(path) else { return false };
        let rel = path.strip_prefix(root).unwrap_or(path);
        let mut parts: Vec<&OsStr> = rel.iter().collect();
        if !is_dir {
            parts.pop();
        }
        !parts.iter().any(|p| self.exclude.contains(*p))
    }

    /// Depth of `dir` below its root (root itself = 0).
    fn depth(&self, dir: &Path) -> Option<usize> {
        let root = self.root_of(dir)?;
        Some(dir.components().count() - root.components().count())
    }
}

pub struct FsWatcher {
    shared: Arc<Shared>,
    watcher: Mutex<RecommendedWatcher>,
    filter: Filter,
    per_dir: bool,
    watched: Mutex<HashSet<PathBuf>>,
}

fn push_error(q: &mut Queue, msg: String) {
    if q.errors.len() >= MAX_ERRORS {
        q.errors.remove(0);
    }
    q.errors.push(msg);
}

fn on_event(shared: &Shared, filter: &Filter, cap: usize, res: notify::Result<Event>) {
    let mut q = shared.queue.lock().unwrap();
    match res {
        Err(e) => {
            q.overflow = true;
            push_error(&mut q, format!("watch error: {e}"));
        }
        Ok(ev) => {
            if ev.need_rescan() {
                q.overflow = true;
            }
            // Reads change nothing. Deletions are passed on so the snapshot
            // forgets the path: a file put back there later is new again.
            if matches!(ev.kind, EventKind::Access(_)) {
                return;
            }
            for p in ev.paths {
                if !filter.wanted(&p, false) || q.seen.contains(&p) {
                    continue;
                }
                if q.paths.len() >= cap {
                    q.overflow = true;
                    break;
                }
                q.seen.insert(p.clone());
                q.paths.push(p);
            }
        }
    }
    if !q.paths.is_empty() || q.overflow || !q.errors.is_empty() {
        shared.ready.notify_all();
    }
}

/// What a drain hands back: changed paths, whether events were lost (so a
/// full rescan is needed), and errors since the last drain.
pub type Drained = (Vec<PathBuf>, bool, Vec<String>);

impl FsWatcher {
    /// Starts watching `roots` (those that exist). Fails only when the OS
    /// backend can't be created at all; per-root failures go to `errors`.
    pub fn new(roots: Vec<PathBuf>, exclude: Vec<String>, ignore: Vec<PathBuf>,
               max_depth: usize, cap: usize) -> Result<Self, String> {
        let shared = Arc::new(Shared { queue: Mutex::new(Queue::default()), ready: Condvar::new() });
        let filter = Filter {
            roots: roots.clone(),
            exclude: exclude.into_iter().map(OsString::from).collect(),
            ignore,
            max_depth,
        };
        let (s, f) = (shared.clone(), filter.clone());
        let watcher = notify::recommended_watcher(move |res| on_event(&s, &f, cap, res))
            .map_err(|e| format!("cannot start native file events: {e}"))?;
        let me = FsWatcher {
            shared,
            watcher: Mutex::new(watcher),
            filter,
            per_dir: cfg!(any(target_os = "linux", target_os = "android")),
            watched: Mutex::new(HashSet::new()),
        };
        for root in roots.iter().filter(|r| r.is_dir()) {
            if me.per_dir {
                me.watch_tree(root);
            } else {
                me.add_watch(root, RecursiveMode::Recursive);
            }
        }
        Ok(me)
    }

    pub fn backend(&self) -> &'static str {
        match RecommendedWatcher::kind() {
            notify::WatcherKind::Inotify => "inotify",
            notify::WatcherKind::Fsevent => "fsevents",
            notify::WatcherKind::Kqueue => "kqueue",
            notify::WatcherKind::ReadDirectoryChangesWatcher => "ReadDirectoryChangesW",
            notify::WatcherKind::PollWatcher => "poll",
            _ => "other",
        }
    }

    /// Number of OS watches held (directories on Linux, roots elsewhere).
    pub fn watch_count(&self) -> usize {
        self.watched.lock().unwrap().len()
    }

    fn add_watch(&self, dir: &Path, mode: RecursiveMode) -> bool {
        if !self.watched.lock().unwrap().insert(dir.to_path_buf()) {
            return true;
        }
        if let Err(e) = self.watcher.lock().unwrap().watch(dir, mode) {
            self.watched.lock().unwrap().remove(dir);
            let mut q = self.shared.queue.lock().unwrap();
            // Unwatched dirs are invisible to events: make Python rescan.
            q.overflow = true;
            // Python stops trusting events once the OS watch limit is hit.
            let what = if matches!(e.kind, notify::ErrorKind::MaxFilesWatch) {
                "watch limit reached"
            } else {
                "cannot watch"
            };
            push_error(&mut q, format!("{what}: {}: {e}", dir.display()));
            self.shared.ready.notify_all();
            return false;
        }
        true
    }

    /// Per-directory backends: watch `dir` (a root, or a directory that just
    /// appeared) and every directory below it that the polling walk visits.
    fn watch_tree(&self, dir: &Path) {
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            if !self.filter.wanted(&d, true) || !self.add_watch(&d, RecursiveMode::NonRecursive) {
                continue;
            }
            // Same depth rule as the polling walk: entries of a directory at
            // max_depth are reported, but its subdirectories aren't descended.
            if self.filter.depth(&d).is_none_or(|n| n >= self.filter.max_depth) {
                continue;
            }
            let Ok(rd) = std::fs::read_dir(&d) else { continue };
            for ent in rd.flatten() {
                // file_type() doesn't follow symlinks, like os.walk.
                if ent.file_type().is_ok_and(|t| t.is_dir())
                    && !self.filter.exclude.contains(&ent.file_name())
                {
                    stack.push(ent.path());
                }
            }
        }
    }

    /// Waits up to `timeout` for events, then returns everything queued.
    pub fn drain(&self, timeout: Duration) -> Drained {
        let deadline = Instant::now() + timeout;
        let mut q = self.shared.queue.lock().unwrap();
        while q.paths.is_empty() && !q.overflow && q.errors.is_empty() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            q = self.shared.ready.wait_timeout(q, left).unwrap().0;
        }
        let paths = std::mem::take(&mut q.paths);
        q.seen.clear();
        let overflow = std::mem::take(&mut q.overflow);
        let errors = std::mem::take(&mut q.errors);
        drop(q);
        if self.per_dir {
            for p in &paths {
                // New (or renamed-in) directory: watch it and what's under it.
                if std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir()) {
                    self.watch_tree(p);
                }
            }
        }
        (paths, overflow, errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("guard-watch-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d.canonicalize().unwrap()
    }

    fn collect(w: &FsWatcher, want: &Path) -> (Vec<PathBuf>, bool) {
        let mut all = Vec::new();
        let mut overflow = false;
        let end = Instant::now() + Duration::from_secs(5);
        while Instant::now() < end && !all.iter().any(|p: &PathBuf| p == want) {
            let (p, o, _) = w.drain(Duration::from_millis(200));
            all.extend(p);
            overflow |= o;
        }
        (all, overflow)
    }

    fn watcher(root: &Path, depth: usize, cap: usize) -> FsWatcher {
        FsWatcher::new(vec![root.to_path_buf()], vec!["node_modules".into()],
                       vec![root.join(".guard")], depth, cap).unwrap()
    }

    #[test]
    fn reports_new_files_and_nested_dirs() {
        let root = tmpdir("new");
        let w = watcher(&root, 6, 1000);
        let f = root.join("a.js");
        fs::write(&f, b"x").unwrap();
        assert!(collect(&w, &f).0.contains(&f));
        // a directory created after start gets watched (inotify) on drain
        let sub = root.join("pkg");
        fs::create_dir(&sub).unwrap();
        assert!(collect(&w, &sub).0.contains(&sub));
        let g = sub.join("b.js");
        fs::write(&g, b"y").unwrap();
        assert!(collect(&w, &g).0.contains(&g));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn skips_excluded_and_ignored() {
        let root = tmpdir("excl");
        fs::create_dir_all(root.join("node_modules/x")).unwrap();
        fs::create_dir_all(root.join(".guard")).unwrap();
        let w = watcher(&root, 6, 1000);
        fs::write(root.join("node_modules/x/evil.js"), b"x").unwrap();
        fs::write(root.join(".guard/watcher.log"), b"x").unwrap();
        let marker = root.join("ok.txt");
        fs::write(&marker, b"x").unwrap();
        let (paths, _) = collect(&w, &marker);
        // The excluded directory itself may be reported (FSEvents delivers its
        // creation late); Python drops it. Nothing inside it may be.
        let nm = root.join("node_modules");
        assert!(paths.iter().all(|p| p == &nm || !p.starts_with(&nm)));
        assert!(paths.iter().all(|p| !p.starts_with(root.join(".guard"))));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn queue_cap_sets_overflow() {
        let root = tmpdir("cap");
        let w = watcher(&root, 6, 2);
        for i in 0..10 {
            fs::write(root.join(format!("f{i}")), b"x").unwrap();
        }
        std::thread::sleep(Duration::from_millis(300));
        let (paths, overflow, _) = w.drain(Duration::from_millis(500));
        assert!(paths.len() <= 2);
        assert!(overflow);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn per_dir_watches_respect_depth_and_excludes() {
        let root = tmpdir("depth");
        fs::create_dir_all(root.join("a/b/c")).unwrap();
        fs::create_dir_all(root.join("node_modules/deep")).unwrap();
        let w = watcher(&root, 1, 1000);
        // root (0) and a (1) are watched; a/b would be depth 2: not descended
        assert_eq!(w.watch_count(), 2);
        assert_eq!(w.backend(), "inotify");
        fs::remove_dir_all(&root).unwrap();
    }
}
