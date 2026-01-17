use agus_core_domain::{Host, OpsEvent, OpsKnowledgeEntry};
use flate2::write::GzEncoder;
use flate2::Compression;
use fs2::FileExt;
use rusqlite::{params, Connection};
use std::env;
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub enum StorageError {
    IoError { message: String },
    ParseError { message: String },
    NotFound { key: String },
    Duplicate { key: String },
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::IoError { message } => write!(f, "io error: {}", message),
            StorageError::ParseError { message } => write!(f, "parse error: {}", message),
            StorageError::NotFound { key } => write!(f, "not found: {}", key),
            StorageError::Duplicate { key } => write!(f, "duplicate: {}", key),
        }
    }
}

impl Error for StorageError {}

pub trait StorageBackend: Send + Sync {
    fn load_hosts(&self) -> Result<Vec<Host>, StorageError>;
    fn save_hosts(&self, hosts: &[Host]) -> Result<(), StorageError>;
    fn load_events(&self) -> Result<Vec<OpsEvent>, StorageError>;
    fn append_event(&self, event: &OpsEvent) -> Result<(), StorageError>;
    fn load_knowledge(&self) -> Result<Vec<OpsKnowledgeEntry>, StorageError>;
    fn append_knowledge(&self, entry: &OpsKnowledgeEntry) -> Result<(), StorageError>;
}

pub struct JsonFileStorage {
    base_path: PathBuf,
}

impl JsonFileStorage {
    pub fn new(base_path: PathBuf) -> Self {
        Self { base_path }
    }

    fn hosts_path(&self) -> PathBuf {
        self.base_path.join("hosts.json")
    }

    fn events_path(&self) -> PathBuf {
        self.base_path.join("events.jsonl")
    }

    fn knowledge_path(&self) -> PathBuf {
        self.base_path.join("knowledge.jsonl")
    }

    fn ensure_dir(&self) -> Result<(), StorageError> {
        if let Some(parent) = self.base_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| StorageError::IoError {
                message: format!("failed to create directory: {}", e),
            })?;
        }
        std::fs::create_dir_all(&self.base_path).map_err(|e| StorageError::IoError {
            message: format!("failed to create directory: {}", e),
        })?;
        Ok(())
    }

    fn max_jsonl_bytes(&self) -> u64 {
        env::var("AGUS_STORAGE_MAX_JSONL_BYTES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(20 * 1024 * 1024)
    }

    fn archive_compress(&self) -> bool {
        match env::var("AGUS_STORAGE_ARCHIVE_COMPRESS") {
            Ok(value) => matches!(value.to_lowercase().as_str(), "1" | "true" | "yes"),
            Err(_) => true,
        }
    }

    fn max_archive_files(&self) -> usize {
        env::var("AGUS_STORAGE_ARCHIVE_MAX_FILES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(10)
    }

    fn archive_dir(&self) -> PathBuf {
        if let Ok(path) = env::var("AGUS_STORAGE_ARCHIVE_DIR") {
            let trimmed = path.trim();
            if !trimmed.is_empty() {
                return PathBuf::from(trimmed);
            }
        }
        self.base_path.join("archive")
    }

    fn rotate_jsonl_if_needed(&self, path: &Path, prefix: &str) -> Result<(), StorageError> {
        let max_bytes = self.max_jsonl_bytes();
        if max_bytes == 0 {
            return Ok(());
        }

        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => {
                return Err(StorageError::IoError {
                    message: format!("failed to stat {}: {}", path.display(), err),
                })
            }
        };

        if metadata.len() < max_bytes {
            return Ok(());
        }

        let archive_dir = self.archive_dir();
        fs::create_dir_all(&archive_dir).map_err(|e| StorageError::IoError {
            message: format!(
                "failed to create archive dir {}: {}",
                archive_dir.display(),
                e
            ),
        })?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let archive_name = format!("{}-{}.jsonl", prefix, timestamp);
        let archive_path = archive_dir.join(archive_name);

        fs::rename(path, &archive_path).map_err(|e| StorageError::IoError {
            message: format!("failed to rotate {}: {}", path.display(), e),
        })?;

        if self.archive_compress() {
            self.compress_archive(&archive_path)?;
        }

        self.prune_archives(&archive_dir, prefix)?;
        Ok(())
    }

    fn compress_archive(&self, path: &Path) -> Result<(), StorageError> {
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("archive.jsonl");
        let gz_path = path.with_file_name(format!("{}.gz", file_name));

        let mut input = File::open(path).map_err(|e| StorageError::IoError {
            message: format!("failed to open archive {}: {}", path.display(), e),
        })?;
        let output = File::create(&gz_path).map_err(|e| StorageError::IoError {
            message: format!("failed to create gzip {}: {}", gz_path.display(), e),
        })?;
        let mut encoder = GzEncoder::new(output, Compression::default());
        std::io::copy(&mut input, &mut encoder).map_err(|e| StorageError::IoError {
            message: format!("failed to compress archive: {}", e),
        })?;
        encoder.finish().map_err(|e| StorageError::IoError {
            message: format!("failed to finalize gzip: {}", e),
        })?;

        fs::remove_file(path).map_err(|e| StorageError::IoError {
            message: format!("failed to remove uncompressed archive: {}", e),
        })?;
        Ok(())
    }

    fn prune_archives(&self, archive_dir: &Path, prefix: &str) -> Result<(), StorageError> {
        let max_files = self.max_archive_files();
        if max_files == 0 {
            return Ok(());
        }

        let mut entries = Vec::new();
        for entry in fs::read_dir(archive_dir).map_err(|e| StorageError::IoError {
            message: format!(
                "failed to read archive dir {}: {}",
                archive_dir.display(),
                e
            ),
        })? {
            let entry = entry.map_err(|e| StorageError::IoError {
                message: format!("failed to read archive entry: {}", e),
            })?;
            let path = entry.path();
            let name = match path.file_name().and_then(|v| v.to_str()) {
                Some(name) => name,
                None => continue,
            };
            if !name.starts_with(prefix) {
                continue;
            }
            if !name.contains(".jsonl") {
                continue;
            }
            let mtime = entry
                .metadata()
                .ok()
                .and_then(|meta| meta.modified().ok())
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            entries.push((mtime, path));
        }

        if entries.len() <= max_files {
            return Ok(());
        }

        entries.sort_by_key(|(mtime, _)| *mtime);
        let remove_count = entries.len().saturating_sub(max_files);
        for (_, path) in entries.into_iter().take(remove_count) {
            let _ = fs::remove_file(path);
        }

        Ok(())
    }

    fn lock_path_for(&self, path: &Path) -> PathBuf {
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("storage");
        self.base_path.join(format!(".{}.lock", name))
    }

    fn with_lock<T, F>(&self, path: &Path, exclusive: bool, action: F) -> Result<T, StorageError>
    where
        F: FnOnce() -> Result<T, StorageError>,
    {
        self.ensure_dir()?;
        let lock_path = self.lock_path_for(path);
        let lock_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|e| StorageError::IoError {
                message: format!("failed to open lock file {}: {}", lock_path.display(), e),
            })?;

        if exclusive {
            lock_file
                .lock_exclusive()
                .map_err(|e| StorageError::IoError {
                    message: format!("failed to lock {} exclusively: {}", lock_path.display(), e),
                })?;
        } else {
            lock_file.lock_shared().map_err(|e| StorageError::IoError {
                message: format!("failed to lock {} shared: {}", lock_path.display(), e),
            })?;
        }

        let result = action();
        let _ = lock_file.unlock();
        result
    }
}

impl StorageBackend for JsonFileStorage {
    fn load_hosts(&self) -> Result<Vec<Host>, StorageError> {
        let path = self.hosts_path();
        self.with_lock(&path, false, || {
            if !path.exists() {
                return Ok(Vec::new());
            }

            let content = std::fs::read_to_string(&path).map_err(|e| StorageError::IoError {
                message: format!("failed to read hosts file: {}", e),
            })?;

            if content.trim().is_empty() {
                return Ok(Vec::new());
            }

            let stored: Vec<Host> =
                serde_json::from_str(&content).map_err(|e| StorageError::ParseError {
                    message: format!("failed to parse hosts: {}", e),
                })?;

            Ok(stored)
        })
    }

    fn save_hosts(&self, hosts: &[Host]) -> Result<(), StorageError> {
        let path = self.hosts_path();
        self.with_lock(&path, true, || {
            let content =
                serde_json::to_string_pretty(&hosts).map_err(|e| StorageError::ParseError {
                    message: format!("failed to serialize hosts: {}", e),
                })?;

            let tmp_path = path.with_extension("json.tmp");
            {
                let mut tmp_file = File::create(&tmp_path).map_err(|e| StorageError::IoError {
                    message: format!("failed to create temp hosts file: {}", e),
                })?;
                tmp_file
                    .write_all(content.as_bytes())
                    .map_err(|e| StorageError::IoError {
                        message: format!("failed to write temp hosts file: {}", e),
                    })?;
                tmp_file.sync_all().ok();
            }

            if path.exists() {
                let _ = std::fs::remove_file(&path);
            }
            std::fs::rename(&tmp_path, &path).map_err(|e| StorageError::IoError {
                message: format!("failed to replace hosts file: {}", e),
            })?;

            Ok(())
        })
    }

    fn load_events(&self) -> Result<Vec<OpsEvent>, StorageError> {
        let path = self.events_path();
        self.with_lock(&path, false, || {
            if !path.exists() {
                return Ok(Vec::new());
            }

            let content = std::fs::read_to_string(&path).map_err(|e| StorageError::IoError {
                message: format!("failed to read events file: {}", e),
            })?;

            let mut events = Vec::new();
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let event: OpsEvent =
                    serde_json::from_str(trimmed).map_err(|e| StorageError::ParseError {
                        message: format!("failed to parse event: {}", e),
                    })?;
                events.push(event);
            }

            Ok(events)
        })
    }

    fn append_event(&self, event: &OpsEvent) -> Result<(), StorageError> {
        let path = self.events_path();
        self.with_lock(&path, true, || {
            self.rotate_jsonl_if_needed(&path, "events")?;
            let line = serde_json::to_string(event).map_err(|e| StorageError::ParseError {
                message: format!("failed to serialize event: {}", e),
            })?;

            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .map_err(|e| StorageError::IoError {
                    message: format!("failed to open events file: {}", e),
                })?;

            writeln!(file, "{}", line).map_err(|e| StorageError::IoError {
                message: format!("failed to write event: {}", e),
            })?;
            file.sync_all().ok();

            Ok(())
        })
    }

    fn load_knowledge(&self) -> Result<Vec<OpsKnowledgeEntry>, StorageError> {
        let path = self.knowledge_path();
        self.with_lock(&path, false, || {
            if !path.exists() {
                return Ok(Vec::new());
            }

            let content = std::fs::read_to_string(&path).map_err(|e| StorageError::IoError {
                message: format!("failed to read knowledge file: {}", e),
            })?;

            let mut entries = Vec::new();
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let entry: OpsKnowledgeEntry =
                    serde_json::from_str(trimmed).map_err(|e| StorageError::ParseError {
                        message: format!("failed to parse knowledge entry: {}", e),
                    })?;
                entries.push(entry);
            }

            Ok(entries)
        })
    }

    fn append_knowledge(&self, entry: &OpsKnowledgeEntry) -> Result<(), StorageError> {
        let path = self.knowledge_path();
        self.with_lock(&path, true, || {
            self.rotate_jsonl_if_needed(&path, "knowledge")?;
            let line = serde_json::to_string(entry).map_err(|e| StorageError::ParseError {
                message: format!("failed to serialize knowledge entry: {}", e),
            })?;

            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .map_err(|e| StorageError::IoError {
                    message: format!("failed to open knowledge file: {}", e),
                })?;

            writeln!(file, "{}", line).map_err(|e| StorageError::IoError {
                message: format!("failed to write knowledge entry: {}", e),
            })?;
            file.sync_all().ok();

            Ok(())
        })
    }
}

pub struct SqliteStorage {
    db_path: PathBuf,
}

impl SqliteStorage {
    pub fn new(db_path: PathBuf) -> Self {
        Self { db_path }
    }

    fn connection(&self) -> Result<Connection, StorageError> {
        if let Some(parent) = self.db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| StorageError::IoError {
                message: format!("failed to create sqlite directory: {}", e),
            })?;
        }
        let conn = Connection::open(&self.db_path).map_err(|e| StorageError::IoError {
            message: format!("failed to open sqlite db: {}", e),
        })?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS hosts (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS knowledge (id INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL);",
        )
        .map_err(|e| StorageError::IoError {
            message: format!("failed to initialize sqlite schema: {}", e),
        })?;
        Ok(conn)
    }
}

impl StorageBackend for SqliteStorage {
    fn load_hosts(&self) -> Result<Vec<Host>, StorageError> {
        let conn = self.connection()?;
        let mut stmt = conn
            .prepare("SELECT payload FROM hosts ORDER BY id")
            .map_err(|e| StorageError::IoError {
                message: format!("failed to query hosts: {}", e),
            })?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| StorageError::IoError {
                message: format!("failed to map hosts: {}", e),
            })?;
        let mut hosts = Vec::new();
        for row in rows {
            let payload = row.map_err(|e| StorageError::IoError {
                message: format!("failed to read host row: {}", e),
            })?;
            let host: Host =
                serde_json::from_str(&payload).map_err(|e| StorageError::ParseError {
                    message: format!("failed to parse host: {}", e),
                })?;
            hosts.push(host);
        }
        Ok(hosts)
    }

    fn save_hosts(&self, hosts: &[Host]) -> Result<(), StorageError> {
        let mut conn = self.connection()?;
        let tx = conn.transaction().map_err(|e| StorageError::IoError {
            message: format!("failed to start sqlite transaction: {}", e),
        })?;
        tx.execute("DELETE FROM hosts", [])
            .map_err(|e| StorageError::IoError {
                message: format!("failed to clear hosts: {}", e),
            })?;
        for host in hosts {
            let payload = serde_json::to_string(host).map_err(|e| StorageError::ParseError {
                message: format!("failed to serialize host: {}", e),
            })?;
            tx.execute(
                "INSERT INTO hosts (id, payload) VALUES (?1, ?2)",
                params![host.id, payload],
            )
            .map_err(|e| StorageError::IoError {
                message: format!("failed to insert host: {}", e),
            })?;
        }
        tx.commit().map_err(|e| StorageError::IoError {
            message: format!("failed to commit hosts: {}", e),
        })?;
        Ok(())
    }

    fn load_events(&self) -> Result<Vec<OpsEvent>, StorageError> {
        let conn = self.connection()?;
        let mut stmt = conn
            .prepare("SELECT payload FROM events ORDER BY id")
            .map_err(|e| StorageError::IoError {
                message: format!("failed to query events: {}", e),
            })?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| StorageError::IoError {
                message: format!("failed to map events: {}", e),
            })?;
        let mut events = Vec::new();
        for row in rows {
            let payload = row.map_err(|e| StorageError::IoError {
                message: format!("failed to read event row: {}", e),
            })?;
            let event: OpsEvent =
                serde_json::from_str(&payload).map_err(|e| StorageError::ParseError {
                    message: format!("failed to parse event: {}", e),
                })?;
            events.push(event);
        }
        Ok(events)
    }

    fn append_event(&self, event: &OpsEvent) -> Result<(), StorageError> {
        let conn = self.connection()?;
        let payload = serde_json::to_string(event).map_err(|e| StorageError::ParseError {
            message: format!("failed to serialize event: {}", e),
        })?;
        conn.execute("INSERT INTO events (payload) VALUES (?1)", params![payload])
            .map_err(|e| StorageError::IoError {
                message: format!("failed to insert event: {}", e),
            })?;
        Ok(())
    }

    fn load_knowledge(&self) -> Result<Vec<OpsKnowledgeEntry>, StorageError> {
        let conn = self.connection()?;
        let mut stmt = conn
            .prepare("SELECT payload FROM knowledge ORDER BY id")
            .map_err(|e| StorageError::IoError {
                message: format!("failed to query knowledge: {}", e),
            })?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| StorageError::IoError {
                message: format!("failed to map knowledge: {}", e),
            })?;
        let mut entries = Vec::new();
        for row in rows {
            let payload = row.map_err(|e| StorageError::IoError {
                message: format!("failed to read knowledge row: {}", e),
            })?;
            let entry: OpsKnowledgeEntry =
                serde_json::from_str(&payload).map_err(|e| StorageError::ParseError {
                    message: format!("failed to parse knowledge entry: {}", e),
                })?;
            entries.push(entry);
        }
        Ok(entries)
    }

    fn append_knowledge(&self, entry: &OpsKnowledgeEntry) -> Result<(), StorageError> {
        let conn = self.connection()?;
        let payload = serde_json::to_string(entry).map_err(|e| StorageError::ParseError {
            message: format!("failed to serialize knowledge entry: {}", e),
        })?;
        conn.execute(
            "INSERT INTO knowledge (payload) VALUES (?1)",
            params![payload],
        )
        .map_err(|e| StorageError::IoError {
            message: format!("failed to insert knowledge entry: {}", e),
        })?;
        Ok(())
    }
}

pub fn create_storage_backend() -> Box<dyn StorageBackend> {
    use std::env;
    let base_path = if let Ok(custom) = env::var("AGUS_HOME") {
        PathBuf::from(custom)
    } else {
        let home = env::var("HOME")
            .or_else(|_| env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".agus")
    };

    let backend = env::var("AGUS_STORAGE_BACKEND")
        .unwrap_or_else(|_| "json".to_string())
        .to_lowercase();
    if backend == "sqlite" {
        let db_path = env::var("AGUS_STORAGE_SQLITE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| base_path.join("agus.db"));
        Box::new(SqliteStorage::new(db_path))
    } else {
        Box::new(JsonFileStorage::new(base_path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_json_storage_hosts() {
        let temp_dir = TempDir::new().unwrap();
        let storage = JsonFileStorage::new(temp_dir.path().to_path_buf());

        let hosts = vec![Host {
            id: "test1".to_string(),
            address: "192.168.1.1".to_string(),
            environment: agus_core_domain::Environment::Dev,
            labels: vec!["test".to_string()],
            user: "root".to_string(),
            port: 22,
            identity_file: None,
            password: None,
            group_id: None,
        }];

        storage.save_hosts(&hosts).unwrap();
        let loaded = storage.load_hosts().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "test1");
    }

    #[test]
    fn test_sqlite_storage_hosts() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("agus.db");
        let storage = SqliteStorage::new(db_path);

        let hosts = vec![Host {
            id: "sqlite1".to_string(),
            address: "10.0.0.1".to_string(),
            environment: agus_core_domain::Environment::Dev,
            labels: vec!["db".to_string()],
            user: "root".to_string(),
            port: 22,
            identity_file: None,
            password: None,
            group_id: None,
        }];

        storage.save_hosts(&hosts).unwrap();
        let loaded = storage.load_hosts().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "sqlite1");
    }
}
