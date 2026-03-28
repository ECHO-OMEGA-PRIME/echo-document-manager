import { Hono } from 'hono';
import { cors } from 'hono/cors';

type Env = {
  DB: D1Database;
  CACHE: KVNamespace;
  STORAGE: R2Bucket;
  ECHO_API_KEY: string;
  ENGINE_RUNTIME: Fetcher;
  SHARED_BRAIN: Fetcher;
};

const app = new Hono<{ Bindings: Env }>();

function uid(): string { return crypto.randomUUID(); }
function sanitize(s: string, max = 2000): string { return (s || '').replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '').slice(0, max); }

interface RLState { c: number; t: number; }
async function rateLimit(kv: KVNamespace, key: string, limit: number, windowSec = 60): Promise<boolean> {
  const now = Date.now();
  const raw = await kv.get<RLState>(`rl:${key}`, 'json');
  if (!raw || (now - raw.t) > windowSec * 1000) {
    await kv.put(`rl:${key}`, JSON.stringify({ c: 1, t: now }), { expirationTtl: windowSec * 2 });
    return true;
  }
  const elapsed = (now - raw.t) / 1000;
  const decayed = raw.c * Math.max(0, 1 - elapsed / windowSec);
  const newCount = decayed + 1;
  if (newCount > limit) return false;
  await kv.put(`rl:${key}`, JSON.stringify({ c: newCount, t: now }), { expirationTtl: windowSec * 2 });
  return true;
}

// CORS
app.use('*', cors());

// Auth
app.use('*', async (c, next) => {
  const path = new URL(c.req.url).pathname;
  if (path === '/health' || path === '/status') return next();
  if (path.startsWith('/shared/')) return next(); // Public share links
  if (c.req.method === 'GET') return next();
  const key = c.req.header('X-Echo-API-Key') || c.req.header('Authorization')?.replace('Bearer ', '');
  if (!key || key !== c.env.ECHO_API_KEY) return c.json({ error: 'Unauthorized' }, 401);
  return next();
});

// Rate limiting
app.use('*', async (c, next) => {
  const path = new URL(c.req.url).pathname;
  if (path === '/health' || path === '/status') return next();
  const tenant = c.req.header('X-Tenant-ID') || c.req.query('tenant_id') || 'default';
  const limit = c.req.method === 'GET' ? 200 : 60;
  if (!(await rateLimit(c.env.CACHE, `${tenant}:${c.req.method}`, limit))) return c.json({ error: 'Rate limited' }, 429);
  return next();
});

// ── Health ──
app.get('/', (c) => c.redirect('/health'));
app.get('/health', (c) => c.json({ ok: true, service: 'echo-document-manager', version: '1.0.0', timestamp: new Date().toISOString() }));
app.get('/status', async (c) => {
  const files = await c.env.DB.prepare('SELECT COUNT(*) as c FROM files WHERE is_archived=0').first<{c:number}>();
  const folders = await c.env.DB.prepare('SELECT COUNT(*) as c FROM folders').first<{c:number}>();
  return c.json({ ok: true, files: files?.c || 0, folders: folders?.c || 0 });
});

// ── Tenants ──
app.post('/tenants', async (c) => {
  const b = await c.req.json() as any;
  const id = uid();
  await c.env.DB.prepare('INSERT INTO tenants (id,name,plan) VALUES (?,?,?)').bind(id, sanitize(b.name || 'Default'), b.plan || 'starter').run();
  return c.json({ id });
});
app.get('/tenants/:id', async (c) => {
  const r = await c.env.DB.prepare('SELECT * FROM tenants WHERE id=?').bind(c.req.param('id')).first();
  return r ? c.json(r) : c.json({ error: 'Not found' }, 404);
});

// ── Folders ──
app.get('/folders', async (c) => {
  const tid = c.req.query('tenant_id') || 'default';
  const parentId = c.req.query('parent_id') || null;
  let sql = 'SELECT * FROM folders WHERE tenant_id=?';
  const params: (string | null)[] = [tid];
  if (parentId) { sql += ' AND parent_id=?'; params.push(parentId); }
  else { sql += ' AND parent_id IS NULL'; }
  sql += ' ORDER BY name';
  const rows = await c.env.DB.prepare(sql).bind(...params).all();
  return c.json({ folders: rows.results });
});

app.post('/folders', async (c) => {
  const b = await c.req.json() as any;
  const tid = b.tenant_id || 'default';
  const id = uid();
  let parentPath = '/';
  if (b.parent_id) {
    const parent = await c.env.DB.prepare('SELECT path FROM folders WHERE id=?').bind(b.parent_id).first<{path:string}>();
    parentPath = parent ? parent.path + '/' : '/';
  }
  const path = parentPath + sanitize(b.name, 200);
  await c.env.DB.prepare('INSERT INTO folders (id,tenant_id,parent_id,name,path,color,created_by) VALUES (?,?,?,?,?,?,?)')
    .bind(id, tid, b.parent_id || null, sanitize(b.name, 200), path, b.color || null, b.created_by || 'system').run();
  return c.json({ id, path });
});

app.put('/folders/:id', async (c) => {
  const b = await c.req.json() as any;
  if (b.name) {
    await c.env.DB.prepare('UPDATE folders SET name=?, updated_at=datetime(\'now\') WHERE id=?').bind(sanitize(b.name, 200), c.req.param('id')).run();
  }
  if (b.color !== undefined) {
    await c.env.DB.prepare('UPDATE folders SET color=?, updated_at=datetime(\'now\') WHERE id=?').bind(b.color, c.req.param('id')).run();
  }
  return c.json({ updated: true });
});

app.delete('/folders/:id', async (c) => {
  const folderId = c.req.param('id');
  const folder = await c.env.DB.prepare('SELECT * FROM folders WHERE id=?').bind(folderId).first<any>();
  if (!folder) return c.json({ error: 'Not found' }, 404);
  // Move to trash
  await c.env.DB.prepare('INSERT INTO trash (id,tenant_id,folder_id,original_name,original_path,auto_delete_at) VALUES (?,?,?,?,?,datetime(\'now\',\'+30 days\'))')
    .bind(uid(), folder.tenant_id, folderId, folder.name, folder.path).run();
  await c.env.DB.prepare('DELETE FROM folders WHERE id=?').bind(folderId).run();
  return c.json({ deleted: true, recoverable: true });
});

// ── Files ──
app.get('/files', async (c) => {
  const tid = c.req.query('tenant_id') || 'default';
  const folderId = c.req.query('folder_id');
  const ext = c.req.query('extension');
  const starred = c.req.query('starred');
  const search = c.req.query('q');
  let sql = 'SELECT * FROM files WHERE tenant_id=? AND is_archived=0';
  const params: string[] = [tid];
  if (folderId) { sql += ' AND folder_id=?'; params.push(folderId); }
  if (ext) { sql += ' AND extension=?'; params.push(ext); }
  if (starred === '1') { sql += ' AND is_starred=1'; }
  if (search) { sql += ' AND (name LIKE ? OR description LIKE ? OR tags LIKE ?)'; const s = `%${search}%`; params.push(s, s, s); }
  sql += ' ORDER BY updated_at DESC LIMIT 100';
  const rows = await c.env.DB.prepare(sql).bind(...params).all();
  return c.json({ files: rows.results });
});

app.get('/files/:id', async (c) => {
  const r = await c.env.DB.prepare('SELECT * FROM files WHERE id=?').bind(c.req.param('id')).first();
  if (!r) return c.json({ error: 'Not found' }, 404);
  await c.env.DB.prepare('UPDATE files SET last_accessed_at=datetime(\'now\') WHERE id=?').bind(c.req.param('id')).run();
  return c.json(r);
});

// Upload file (expects multipart form or JSON with base64)
app.post('/files', async (c) => {
  const contentType = c.req.header('Content-Type') || '';

  if (contentType.includes('application/json')) {
    // JSON upload with base64 content
    const b = await c.req.json() as any;
    const tid = b.tenant_id || 'default';

    // Check storage limits
    const tenant = await c.env.DB.prepare('SELECT max_storage_mb, used_storage_mb, max_files FROM tenants WHERE id=?').bind(tid).first<any>();
    const fileCount = await c.env.DB.prepare('SELECT COUNT(*) as c FROM files WHERE tenant_id=?').bind(tid).first<{c:number}>();
    if (tenant && (fileCount?.c || 0) >= (tenant.max_files || 5000)) return c.json({ error: 'File limit reached' }, 400);

    const id = uid();
    const name = sanitize(b.name || 'untitled', 255);
    const ext = name.includes('.') ? name.split('.').pop()?.toLowerCase() || '' : '';
    const r2Key = `docs/${tid}/${id}/${name}`;

    // Decode base64 and upload to R2
    const data = b.content_base64 ? Uint8Array.from(atob(b.content_base64), c => c.charCodeAt(0)) : new Uint8Array(0);
    const sizeBytes = data.length;
    const sizeMb = sizeBytes / (1024 * 1024);

    if (tenant && (tenant.used_storage_mb + sizeMb) > tenant.max_storage_mb) return c.json({ error: 'Storage limit exceeded' }, 400);

    await c.env.STORAGE.put(r2Key, data, { httpMetadata: { contentType: b.mime_type || 'application/octet-stream' } });

    await c.env.DB.prepare('INSERT INTO files (id,tenant_id,folder_id,name,extension,mime_type,size_bytes,r2_key,description,tags,created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
      .bind(id, tid, b.folder_id || null, name, ext, b.mime_type || 'application/octet-stream', sizeBytes, r2Key, sanitize(b.description || ''), b.tags || '', b.created_by || 'system').run();

    // Create version 1
    await c.env.DB.prepare('INSERT INTO file_versions (id,file_id,version_number,r2_key,size_bytes,change_summary,created_by) VALUES (?,?,1,?,?,?,?)')
      .bind(uid(), id, r2Key, sizeBytes, 'Initial upload', b.created_by || 'system').run();

    // Update folder file count
    if (b.folder_id) await c.env.DB.prepare('UPDATE folders SET file_count=file_count+1 WHERE id=?').bind(b.folder_id).run();

    // Update tenant storage
    await c.env.DB.prepare('UPDATE tenants SET used_storage_mb=used_storage_mb+? WHERE id=?').bind(sizeMb, tid).run();

    // Activity log
    await c.env.DB.prepare('INSERT INTO recent_activity (tenant_id,action,file_id,file_name,performed_by) VALUES (?,\'upload\',?,?,?)').bind(tid, id, name, b.created_by || 'system').run();

    return c.json({ id, r2_key: r2Key, size_bytes: sizeBytes });
  }

  return c.json({ error: 'Use Content-Type: application/json with content_base64 field' }, 400);
});

// Download file
app.get('/files/:id/download', async (c) => {
  const file = await c.env.DB.prepare('SELECT * FROM files WHERE id=?').bind(c.req.param('id')).first<any>();
  if (!file) return c.json({ error: 'Not found' }, 404);
  const obj = await c.env.STORAGE.get(file.r2_key);
  if (!obj) return c.json({ error: 'File not in storage' }, 404);
  await c.env.DB.prepare('UPDATE files SET download_count=download_count+1, last_accessed_at=datetime(\'now\') WHERE id=?').bind(file.id).run();
  return new Response(obj.body, { headers: { 'Content-Type': file.mime_type || 'application/octet-stream', 'Content-Disposition': `attachment; filename="${file.name}"` } });
});

// Update file metadata
app.put('/files/:id', async (c) => {
  const b = await c.req.json() as any;
  const sets: string[] = [];
  const vals: any[] = [];
  if (b.name) { sets.push('name=?'); vals.push(sanitize(b.name, 255)); }
  if (b.description !== undefined) { sets.push('description=?'); vals.push(sanitize(b.description)); }
  if (b.tags !== undefined) { sets.push('tags=?'); vals.push(b.tags); }
  if (b.is_starred !== undefined) { sets.push('is_starred=?'); vals.push(b.is_starred ? 1 : 0); }
  if (b.folder_id !== undefined) { sets.push('folder_id=?'); vals.push(b.folder_id); }
  if (sets.length === 0) return c.json({ error: 'No fields' }, 400);
  sets.push('updated_at=datetime(\'now\')');
  vals.push(c.req.param('id'));
  await c.env.DB.prepare(`UPDATE files SET ${sets.join(',')} WHERE id=?`).bind(...vals).run();
  return c.json({ updated: true });
});

// Upload new version
app.post('/files/:id/versions', async (c) => {
  const file = await c.env.DB.prepare('SELECT * FROM files WHERE id=?').bind(c.req.param('id')).first<any>();
  if (!file) return c.json({ error: 'Not found' }, 404);
  const b = await c.req.json() as any;
  const newVersion = file.current_version + 1;
  const r2Key = `docs/${file.tenant_id}/${file.id}/v${newVersion}_${file.name}`;
  const data = b.content_base64 ? Uint8Array.from(atob(b.content_base64), ch => ch.charCodeAt(0)) : new Uint8Array(0);
  await c.env.STORAGE.put(r2Key, data, { httpMetadata: { contentType: file.mime_type } });

  await c.env.DB.prepare('INSERT INTO file_versions (id,file_id,version_number,r2_key,size_bytes,change_summary,created_by) VALUES (?,?,?,?,?,?,?)')
    .bind(uid(), file.id, newVersion, r2Key, data.length, sanitize(b.change_summary || ''), b.created_by || 'system').run();
  await c.env.DB.prepare('UPDATE files SET current_version=?, r2_key=?, size_bytes=?, updated_at=datetime(\'now\') WHERE id=?')
    .bind(newVersion, r2Key, data.length, file.id).run();
  return c.json({ version: newVersion });
});

// Get file versions
app.get('/files/:id/versions', async (c) => {
  const rows = await c.env.DB.prepare('SELECT * FROM file_versions WHERE file_id=? ORDER BY version_number DESC').bind(c.req.param('id')).all();
  return c.json({ versions: rows.results });
});

// Delete file (to trash)
app.delete('/files/:id', async (c) => {
  const file = await c.env.DB.prepare('SELECT * FROM files WHERE id=?').bind(c.req.param('id')).first<any>();
  if (!file) return c.json({ error: 'Not found' }, 404);
  await c.env.DB.prepare('INSERT INTO trash (id,tenant_id,file_id,original_name,auto_delete_at) VALUES (?,?,?,?,datetime(\'now\',\'+30 days\'))')
    .bind(uid(), file.tenant_id, file.id, file.name).run();
  await c.env.DB.prepare('UPDATE files SET is_archived=1, updated_at=datetime(\'now\') WHERE id=?').bind(file.id).run();
  if (file.folder_id) await c.env.DB.prepare('UPDATE folders SET file_count=file_count-1 WHERE id=?').bind(file.folder_id).run();
  return c.json({ deleted: true, recoverable: true });
});

// ── Sharing ──
app.post('/shares', async (c) => {
  const b = await c.req.json() as any;
  const id = uid();
  const token = uid().replace(/-/g, '').slice(0, 16);
  await c.env.DB.prepare('INSERT INTO shares (id,tenant_id,file_id,folder_id,share_token,permission,expires_at,max_downloads,created_by) VALUES (?,?,?,?,?,?,?,?,?)')
    .bind(id, b.tenant_id || 'default', b.file_id || null, b.folder_id || null, token, b.permission || 'view', b.expires_at || null, b.max_downloads || null, b.created_by || 'system').run();
  return c.json({ id, share_token: token, share_url: `/shared/${token}` });
});

app.get('/shares', async (c) => {
  const tid = c.req.query('tenant_id') || 'default';
  const rows = await c.env.DB.prepare('SELECT s.*, f.name as file_name FROM shares s LEFT JOIN files f ON s.file_id=f.id WHERE s.tenant_id=? AND s.is_active=1 ORDER BY s.created_at DESC').bind(tid).all();
  return c.json({ shares: rows.results });
});

app.delete('/shares/:id', async (c) => {
  await c.env.DB.prepare('UPDATE shares SET is_active=0 WHERE id=?').bind(c.req.param('id')).run();
  return c.json({ revoked: true });
});

// Public share access
app.get('/shared/:token', async (c) => {
  const share = await c.env.DB.prepare('SELECT * FROM shares WHERE share_token=? AND is_active=1').bind(c.req.param('token')).first<any>();
  if (!share) return c.json({ error: 'Share link not found or expired' }, 404);
  if (share.expires_at && new Date(share.expires_at) < new Date()) return c.json({ error: 'Share link expired' }, 410);
  if (share.max_downloads && share.download_count >= share.max_downloads) return c.json({ error: 'Download limit reached' }, 410);

  if (share.file_id) {
    const file = await c.env.DB.prepare('SELECT id,name,extension,mime_type,size_bytes,description,created_at FROM files WHERE id=?').bind(share.file_id).first();
    return c.json({ type: 'file', permission: share.permission, file });
  }
  if (share.folder_id) {
    const folder = await c.env.DB.prepare('SELECT * FROM folders WHERE id=?').bind(share.folder_id).first();
    const files = await c.env.DB.prepare('SELECT id,name,extension,size_bytes FROM files WHERE folder_id=? AND is_archived=0').bind(share.folder_id).all();
    return c.json({ type: 'folder', permission: share.permission, folder, files: files.results });
  }
  return c.json({ error: 'Invalid share' }, 400);
});

// Public share download
app.get('/shared/:token/download', async (c) => {
  const share = await c.env.DB.prepare('SELECT * FROM shares WHERE share_token=? AND is_active=1').bind(c.req.param('token')).first<any>();
  if (!share || !share.file_id) return c.json({ error: 'Not found' }, 404);
  if (share.permission === 'view') return c.json({ error: 'View only — downloads not permitted' }, 403);
  if (share.expires_at && new Date(share.expires_at) < new Date()) return c.json({ error: 'Expired' }, 410);
  if (share.max_downloads && share.download_count >= share.max_downloads) return c.json({ error: 'Limit reached' }, 410);

  const file = await c.env.DB.prepare('SELECT * FROM files WHERE id=?').bind(share.file_id).first<any>();
  if (!file) return c.json({ error: 'File not found' }, 404);
  const obj = await c.env.STORAGE.get(file.r2_key);
  if (!obj) return c.json({ error: 'File not in storage' }, 404);

  await c.env.DB.prepare('UPDATE shares SET download_count=download_count+1 WHERE id=?').bind(share.id).run();
  await c.env.DB.prepare('UPDATE files SET download_count=download_count+1 WHERE id=?').bind(file.id).run();
  return new Response(obj.body, { headers: { 'Content-Type': file.mime_type, 'Content-Disposition': `attachment; filename="${file.name}"` } });
});

// ── Comments ──
app.get('/files/:id/comments', async (c) => {
  const rows = await c.env.DB.prepare('SELECT * FROM comments WHERE file_id=? ORDER BY created_at DESC').bind(c.req.param('id')).all();
  return c.json({ comments: rows.results });
});

app.post('/files/:id/comments', async (c) => {
  const b = await c.req.json() as any;
  const file = await c.env.DB.prepare('SELECT tenant_id FROM files WHERE id=?').bind(c.req.param('id')).first<{tenant_id:string}>();
  if (!file) return c.json({ error: 'File not found' }, 404);
  const id = uid();
  await c.env.DB.prepare('INSERT INTO comments (id,file_id,tenant_id,parent_id,author_name,author_email,content) VALUES (?,?,?,?,?,?,?)')
    .bind(id, c.req.param('id'), file.tenant_id, b.parent_id || null, sanitize(b.author_name || 'Anonymous'), b.author_email || '', sanitize(b.content)).run();
  return c.json({ id });
});

// ── Trash ──
app.get('/trash', async (c) => {
  const tid = c.req.query('tenant_id') || 'default';
  const rows = await c.env.DB.prepare('SELECT * FROM trash WHERE tenant_id=? ORDER BY deleted_at DESC').bind(tid).all();
  return c.json({ items: rows.results });
});

app.post('/trash/:id/restore', async (c) => {
  const item = await c.env.DB.prepare('SELECT * FROM trash WHERE id=?').bind(c.req.param('id')).first<any>();
  if (!item) return c.json({ error: 'Not found' }, 404);
  if (item.file_id) {
    await c.env.DB.prepare('UPDATE files SET is_archived=0, updated_at=datetime(\'now\') WHERE id=?').bind(item.file_id).run();
  }
  await c.env.DB.prepare('DELETE FROM trash WHERE id=?').bind(c.req.param('id')).run();
  return c.json({ restored: true });
});

// ── Recent Activity ──
app.get('/activity', async (c) => {
  const tid = c.req.query('tenant_id') || 'default';
  const rows = await c.env.DB.prepare('SELECT * FROM recent_activity WHERE tenant_id=? ORDER BY created_at DESC LIMIT 50').bind(tid).all();
  return c.json({ activity: rows.results });
});

// ── Analytics ──
app.get('/analytics/overview', async (c) => {
  const tid = c.req.query('tenant_id') || 'default';
  const tenant = await c.env.DB.prepare('SELECT * FROM tenants WHERE id=?').bind(tid).first<any>();
  const files = await c.env.DB.prepare('SELECT COUNT(*) as total, SUM(size_bytes) as total_size FROM files WHERE tenant_id=? AND is_archived=0').bind(tid).first<any>();
  const folders = await c.env.DB.prepare('SELECT COUNT(*) as c FROM folders WHERE tenant_id=?').bind(tid).first<{c:number}>();
  const shares = await c.env.DB.prepare('SELECT COUNT(*) as c FROM shares WHERE tenant_id=? AND is_active=1').bind(tid).first<{c:number}>();
  const byType = await c.env.DB.prepare('SELECT extension, COUNT(*) as count, SUM(size_bytes) as total_size FROM files WHERE tenant_id=? AND is_archived=0 GROUP BY extension ORDER BY count DESC LIMIT 10').bind(tid).all();
  const recentUploads = await c.env.DB.prepare('SELECT date(created_at) as day, COUNT(*) as uploads FROM files WHERE tenant_id=? AND created_at > datetime(\'now\',\'-30 days\') GROUP BY day ORDER BY day').bind(tid).all();
  return c.json({
    storage: { used_mb: tenant?.used_storage_mb || 0, max_mb: tenant?.max_storage_mb || 5120, usage_percent: tenant ? ((tenant.used_storage_mb / tenant.max_storage_mb) * 100).toFixed(1) : '0' },
    files: files?.total || 0, total_size_bytes: files?.total_size || 0,
    folders: folders?.c || 0, active_shares: shares?.c || 0,
    by_type: byType.results, recent_uploads: recentUploads.results,
  });
});

// ── AI: Summarize document ──
app.post('/ai/summarize', async (c) => {
  const b = await c.req.json() as { file_id: string };
  const file = await c.env.DB.prepare('SELECT * FROM files WHERE id=?').bind(b.file_id).first<any>();
  if (!file) return c.json({ error: 'File not found' }, 404);
  // Only summarize text-based files
  const textTypes = ['text/', 'application/json', 'application/xml', 'application/pdf'];
  if (!textTypes.some(t => (file.mime_type || '').startsWith(t))) return c.json({ error: 'Cannot summarize this file type' }, 400);
  const obj = await c.env.STORAGE.get(file.r2_key);
  if (!obj) return c.json({ error: 'File not in storage' }, 404);
  const text = await obj.text();
  const resp = await c.env.ENGINE_RUNTIME.fetch('https://engine/query', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ engine_id: 'GEN-01', query: `Summarize this document in 3-5 bullet points. Document name: ${file.name}. Content: ${text.slice(0, 8000)}` }),
  });
  return c.json(await resp.json().catch(() => ({ error: 'AI summarization failed' })));
});

// ── AI: Auto-tag ──
app.post('/ai/auto-tag', async (c) => {
  const b = await c.req.json() as { file_id: string };
  const file = await c.env.DB.prepare('SELECT name, description, extension FROM files WHERE id=?').bind(b.file_id).first<any>();
  if (!file) return c.json({ error: 'Not found' }, 404);
  const resp = await c.env.ENGINE_RUNTIME.fetch('https://engine/query', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ engine_id: 'GEN-01', query: `Suggest 5-8 tags for this file based on its name, type, and description. Name: ${file.name}, Type: ${file.extension}, Description: ${file.description || 'none'}. Return JSON array of tag strings.` }),
  });
  return c.json(await resp.json().catch(() => ({ error: 'AI tagging failed' })));
});

// ── Scheduled ──
export default {
  fetch: app.fetch,
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    // Permanently delete files in trash past auto_delete_at
    const expired = await env.DB.prepare('SELECT * FROM trash WHERE auto_delete_at <= datetime(\'now\') LIMIT 20').all();
    for (const item of expired.results as any[]) {
      if (item.file_id) {
        const file = await env.DB.prepare('SELECT r2_key, tenant_id, size_bytes FROM files WHERE id=?').bind(item.file_id).first<any>();
        if (file) {
          await env.STORAGE.delete(file.r2_key);
          const versions = await env.DB.prepare('SELECT r2_key FROM file_versions WHERE file_id=?').bind(item.file_id).all();
          for (const v of versions.results as any[]) await env.STORAGE.delete(v.r2_key);
          await env.DB.prepare('DELETE FROM file_versions WHERE file_id=?').bind(item.file_id).run();
          await env.DB.prepare('DELETE FROM comments WHERE file_id=?').bind(item.file_id).run();
          await env.DB.prepare('DELETE FROM files WHERE id=?').bind(item.file_id).run();
          await env.DB.prepare('UPDATE tenants SET used_storage_mb=MAX(0,used_storage_mb-?) WHERE id=?').bind(file.size_bytes / (1024 * 1024), file.tenant_id).run();
        }
      }
      await env.DB.prepare('DELETE FROM trash WHERE id=?').bind(item.id).run();
    }
    // Cleanup old activity
    await env.DB.prepare('DELETE FROM recent_activity WHERE created_at < datetime(\'now\',\'-90 days\')').run();
  },
};
