-- Echo Document Manager v1.0.0
-- Cloud file management, sharing, version control, and collaboration

CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  plan TEXT DEFAULT 'starter',
  max_storage_mb INTEGER DEFAULT 5120, -- 5GB starter
  used_storage_mb REAL DEFAULT 0,
  max_files INTEGER DEFAULT 5000,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS folders (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  parent_id TEXT, -- null = root
  name TEXT NOT NULL,
  path TEXT NOT NULL, -- /folder/subfolder
  color TEXT,
  file_count INTEGER DEFAULT 0,
  created_by TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_folders_tenant ON folders(tenant_id);
CREATE INDEX IF NOT EXISTS idx_folders_parent ON folders(parent_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_folders_path ON folders(tenant_id, path);

CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  folder_id TEXT,
  name TEXT NOT NULL,
  extension TEXT,
  mime_type TEXT,
  size_bytes INTEGER DEFAULT 0,
  r2_key TEXT NOT NULL, -- R2 object key
  thumbnail_key TEXT, -- R2 key for thumbnail
  current_version INTEGER DEFAULT 1,
  description TEXT,
  tags TEXT DEFAULT '',
  is_starred INTEGER DEFAULT 0,
  is_archived INTEGER DEFAULT 0,
  download_count INTEGER DEFAULT 0,
  last_accessed_at TEXT,
  created_by TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_files_tenant ON files(tenant_id);
CREATE INDEX IF NOT EXISTS idx_files_folder ON files(folder_id);
CREATE INDEX IF NOT EXISTS idx_files_extension ON files(extension);
CREATE INDEX IF NOT EXISTS idx_files_name ON files(tenant_id, name);

CREATE TABLE IF NOT EXISTS file_versions (
  id TEXT PRIMARY KEY,
  file_id TEXT NOT NULL,
  version_number INTEGER NOT NULL,
  r2_key TEXT NOT NULL,
  size_bytes INTEGER DEFAULT 0,
  change_summary TEXT,
  created_by TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_versions_file ON file_versions(file_id);

CREATE TABLE IF NOT EXISTS shares (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  file_id TEXT,
  folder_id TEXT,
  share_token TEXT NOT NULL, -- public share link token
  permission TEXT DEFAULT 'view', -- view, download, edit
  password_hash TEXT, -- optional password protection
  expires_at TEXT,
  max_downloads INTEGER,
  download_count INTEGER DEFAULT 0,
  is_active INTEGER DEFAULT 1,
  created_by TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_shares_token ON shares(share_token);
CREATE INDEX IF NOT EXISTS idx_shares_file ON shares(file_id);

CREATE TABLE IF NOT EXISTS comments (
  id TEXT PRIMARY KEY,
  file_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  parent_id TEXT, -- threaded comments
  author_name TEXT NOT NULL,
  author_email TEXT,
  content TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_comments_file ON comments(file_id);

CREATE TABLE IF NOT EXISTS recent_activity (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  action TEXT NOT NULL, -- upload, download, share, delete, rename, move, comment
  file_id TEXT,
  folder_id TEXT,
  file_name TEXT,
  performed_by TEXT,
  details TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_activity_tenant ON recent_activity(tenant_id);
CREATE INDEX IF NOT EXISTS idx_activity_created ON recent_activity(created_at);

CREATE TABLE IF NOT EXISTS trash (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  file_id TEXT,
  folder_id TEXT,
  original_name TEXT NOT NULL,
  original_path TEXT,
  deleted_at TEXT DEFAULT (datetime('now')),
  auto_delete_at TEXT -- 30 days from deletion
);
CREATE INDEX IF NOT EXISTS idx_trash_tenant ON trash(tenant_id);
CREATE INDEX IF NOT EXISTS idx_trash_auto ON trash(auto_delete_at);
