import { Hono } from 'hono';
import { cors } from 'hono/cors';

type Env = {
  DB: D1Database;
  CACHE: KVNamespace;
  STORAGE: R2Bucket;
  ECHO_API_KEY: string;
  ENGINE_RUNTIME: Fetcher;
  SHARED_BRAIN: Fetcher;
  STRIPE_SECRET_KEY?: string;
  STRIPE_WEBHOOK_SECRET?: string;
};

const app = new Hono<{ Bindings: Env }>();
// Security headers middleware
app.use('*', async (c, next) => {
  await next();
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  c.header('X-XSS-Protection', '1; mode=block');
  c.header('Referrer-Policy', 'strict-origin-when-cross-origin');
  c.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
});


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

function slog(level: 'info' | 'warn' | 'error', msg: string, data?: Record<string, unknown>) {
  const entry = { ts: new Date().toISOString(), level, worker: 'echo-document-manager', version: '2.0.0', msg, ...data };
  if (level === 'error') console.error(JSON.stringify(entry));
  else console.log(JSON.stringify(entry));
}

// ── Plan Definitions ──
const PLAN_CONFIG: Record<string, { storage_mb: number; max_files: number; price_cents: number; stripe_price_id?: string }> = {
  free:       { storage_mb: 100,     max_files: 50,    price_cents: 0 },
  starter:    { storage_mb: 1024,    max_files: 500,   price_cents: 999 },
  pro:        { storage_mb: 10240,   max_files: 5000,  price_cents: 2999 },
  enterprise: { storage_mb: 102400,  max_files: 999999, price_cents: 9999 },
};

// ── Stripe Helpers ──
async function stripeRequest(secretKey: string, path: string, method: string, body?: URLSearchParams): Promise<any> {
  const resp = await fetch(`https://api.stripe.com/v1${path}`, {
    method,
    headers: {
      'Authorization': `Bearer ${secretKey}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: body?.toString(),
  });
  return resp.json();
}

async function verifyStripeSignature(payload: string, sigHeader: string, secret: string): Promise<boolean> {
  const parts = sigHeader.split(',');
  let timestamp = '';
  const signatures: string[] = [];
  for (const part of parts) {
    const [k, v] = part.split('=');
    if (k === 't') timestamp = v;
    if (k === 'v1') signatures.push(v);
  }
  if (!timestamp || signatures.length === 0) return false;

  // Replay protection: reject signatures older than 5 minutes
  const age = Math.abs(Date.now() / 1000 - parseInt(timestamp));
  if (age > 300) return false;

  const signedPayload = `${timestamp}.${payload}`;
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(signedPayload));
  const expectedHex = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');

  // Constant-time compare
  if (expectedHex.length !== signatures[0].length) return false;
  let mismatch = 0;
  for (let i = 0; i < expectedHex.length; i++) {
    mismatch |= expectedHex.charCodeAt(i) ^ signatures[0].charCodeAt(i);
  }
  return mismatch === 0;
}

// Global error handler — catches D1 errors and returns structured 500 instead of crashing
app.onError((err, c) => {
  slog('error', 'Unhandled request error', { method: c.req.method, url: c.req.url, error: err.message, stack: err.stack });
  return c.json({
    error: 'Internal server error',
    message: err.message,
    path: new URL(c.req.url).pathname,
  }, 500);
});

// CORS
app.use('*', cors());

// Auth
app.use('*', async (c, next) => {
  const path = new URL(c.req.url).pathname;
  if (path === '/health' || path === '/status') return next();
  if (path.startsWith('/shared/')) return next(); // Public share links
  if (path === '/webhooks/stripe') return next(); // Stripe webhook (signature-verified)
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
app.get('/', (c) => c.json({ service: 'echo-document-manager', version: '2.0.0', status: 'operational' }));
app.get('/health', (c) => c.json({
  ok: true, service: 'echo-document-manager', version: '2.0.0', timestamp: new Date().toISOString(),
  stripe: { configured: !!c.env.STRIPE_SECRET_KEY, webhook_configured: !!c.env.STRIPE_WEBHOOK_SECRET },
  plans: Object.keys(PLAN_CONFIG),
}));
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

// ── Stripe: Create Checkout Session ──
app.post('/plans/upgrade', async (c) => {
  if (!c.env.STRIPE_SECRET_KEY) return c.json({ error: 'Stripe not configured' }, 503);
  const b = await c.req.json() as { tenant_id: string; plan: string; success_url?: string; cancel_url?: string };
  const plan = PLAN_CONFIG[b.plan];
  if (!plan || b.plan === 'free') return c.json({ error: 'Invalid plan. Choose: starter, pro, enterprise' }, 400);

  const tenant = await c.env.DB.prepare('SELECT * FROM tenants WHERE id=?').bind(b.tenant_id).first<any>();
  if (!tenant) return c.json({ error: 'Tenant not found' }, 404);
  if (tenant.plan === b.plan) return c.json({ error: 'Already on this plan' }, 400);

  // If tenant already has a Stripe customer ID, use it; otherwise create one
  let customerId = tenant.stripe_customer_id;
  if (!customerId) {
    const customer = await stripeRequest(c.env.STRIPE_SECRET_KEY, '/customers', 'POST', new URLSearchParams({
      'metadata[tenant_id]': b.tenant_id,
      'name': tenant.name || b.tenant_id,
    }));
    customerId = customer.id;
    await c.env.DB.prepare('UPDATE tenants SET stripe_customer_id=? WHERE id=?').bind(customerId, b.tenant_id).run();
  }

  // Create a Stripe Checkout session
  const params = new URLSearchParams({
    'customer': customerId,
    'mode': 'subscription',
    'success_url': b.success_url || 'https://echo-op.com/dashboard?upgrade=success',
    'cancel_url': b.cancel_url || 'https://echo-op.com/dashboard?upgrade=cancelled',
    'metadata[tenant_id]': b.tenant_id,
    'metadata[plan]': b.plan,
    'line_items[0][price_data][currency]': 'usd',
    'line_items[0][price_data][recurring][interval]': 'month',
    'line_items[0][price_data][unit_amount]': plan.price_cents.toString(),
    'line_items[0][price_data][product_data][name]': `Document Manager — ${b.plan.charAt(0).toUpperCase() + b.plan.slice(1)} Plan`,
    'line_items[0][quantity]': '1',
  });

  const session = await stripeRequest(c.env.STRIPE_SECRET_KEY, '/checkout/sessions', 'POST', params);
  if (session.error) {
    slog('error', 'Stripe checkout creation failed', { error: session.error });
    return c.json({ error: 'Stripe checkout failed', detail: session.error.message }, 500);
  }

  slog('info', 'Checkout session created', { tenant_id: b.tenant_id, plan: b.plan, session_id: session.id });
  return c.json({ checkout_url: session.url, session_id: session.id });
});

// ── Stripe: Get billing portal link ──
app.post('/plans/portal', async (c) => {
  if (!c.env.STRIPE_SECRET_KEY) return c.json({ error: 'Stripe not configured' }, 503);
  const b = await c.req.json() as { tenant_id: string; return_url?: string };
  const tenant = await c.env.DB.prepare('SELECT stripe_customer_id FROM tenants WHERE id=?').bind(b.tenant_id).first<any>();
  if (!tenant?.stripe_customer_id) return c.json({ error: 'No billing account found' }, 404);

  const portal = await stripeRequest(c.env.STRIPE_SECRET_KEY, '/billing_portal/sessions', 'POST', new URLSearchParams({
    'customer': tenant.stripe_customer_id,
    'return_url': b.return_url || 'https://echo-op.com/dashboard',
  }));
  return c.json({ portal_url: portal.url });
});

// ── Stripe: Get current plan/subscription info ──
app.get('/plans/:tenant_id', async (c) => {
  const tenant = await c.env.DB.prepare('SELECT id,name,plan,max_storage_mb,max_files,used_storage_mb,stripe_customer_id,stripe_subscription_id FROM tenants WHERE id=?').bind(c.req.param('tenant_id')).first<any>();
  if (!tenant) return c.json({ error: 'Tenant not found' }, 404);
  const planDef = PLAN_CONFIG[tenant.plan] || PLAN_CONFIG.free;
  return c.json({
    tenant_id: tenant.id,
    plan: tenant.plan,
    price_cents: planDef.price_cents,
    limits: { storage_mb: planDef.storage_mb, max_files: planDef.max_files },
    usage: { storage_mb: tenant.used_storage_mb || 0 },
    stripe: { customer_id: tenant.stripe_customer_id || null, subscription_id: tenant.stripe_subscription_id || null },
    available_upgrades: Object.entries(PLAN_CONFIG)
      .filter(([k]) => k !== tenant.plan && k !== 'free')
      .map(([k, v]) => ({ plan: k, price_cents: v.price_cents, storage_mb: v.storage_mb, max_files: v.max_files })),
  });
});

// ── Stripe Webhook ──
app.post('/webhooks/stripe', async (c) => {
  const body = await c.req.text();
  const sig = c.req.header('Stripe-Signature') || '';

  if (c.env.STRIPE_WEBHOOK_SECRET) {
    const valid = await verifyStripeSignature(body, sig, c.env.STRIPE_WEBHOOK_SECRET);
    if (!valid) {
      slog('warn', 'Stripe webhook signature verification failed');
      return c.json({ error: 'Invalid signature' }, 401);
    }
  }

  const event = JSON.parse(body);
  slog('info', 'Stripe webhook received', { type: event.type, id: event.id });

  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object;
      const tenantId = session.metadata?.tenant_id;
      const plan = session.metadata?.plan;
      if (tenantId && plan && PLAN_CONFIG[plan]) {
        const cfg = PLAN_CONFIG[plan];
        await c.env.DB.prepare('UPDATE tenants SET plan=?, max_storage_mb=?, max_files=?, stripe_customer_id=?, stripe_subscription_id=?, updated_at=datetime(\'now\') WHERE id=?')
          .bind(plan, cfg.storage_mb, cfg.max_files, session.customer, session.subscription, tenantId).run();
        slog('info', 'Tenant plan upgraded via checkout', { tenant_id: tenantId, plan });

        // Log activity
        await c.env.DB.prepare('INSERT INTO recent_activity (tenant_id,action,file_name,performed_by) VALUES (?,\'plan_upgrade\',?,\'stripe\')')
          .bind(tenantId, `Upgraded to ${plan}`).run();
      }
      break;
    }

    case 'customer.subscription.updated': {
      const sub = event.data.object;
      const customerId = sub.customer;
      const tenant = await c.env.DB.prepare('SELECT id FROM tenants WHERE stripe_customer_id=?').bind(customerId).first<any>();
      if (tenant) {
        const status = sub.status;
        if (status === 'active') {
          await c.env.DB.prepare('UPDATE tenants SET stripe_subscription_id=?, updated_at=datetime(\'now\') WHERE id=?')
            .bind(sub.id, tenant.id).run();
        }
        slog('info', 'Subscription updated', { tenant_id: tenant.id, status });
      }
      break;
    }

    case 'customer.subscription.deleted': {
      const sub = event.data.object;
      const customerId = sub.customer;
      const tenant = await c.env.DB.prepare('SELECT id FROM tenants WHERE stripe_customer_id=?').bind(customerId).first<any>();
      if (tenant) {
        const freeCfg = PLAN_CONFIG.free;
        await c.env.DB.prepare('UPDATE tenants SET plan=\'free\', max_storage_mb=?, max_files=?, stripe_subscription_id=NULL, updated_at=datetime(\'now\') WHERE id=?')
          .bind(freeCfg.storage_mb, freeCfg.max_files, tenant.id).run();
        slog('info', 'Subscription cancelled, downgraded to free', { tenant_id: tenant.id });

        await c.env.DB.prepare('INSERT INTO recent_activity (tenant_id,action,file_name,performed_by) VALUES (?,\'plan_downgrade\',\'Downgraded to free\',\'stripe\')')
          .bind(tenant.id).run();
      }
      break;
    }

    case 'invoice.payment_failed': {
      const invoice = event.data.object;
      const customerId = invoice.customer;
      const tenant = await c.env.DB.prepare('SELECT id FROM tenants WHERE stripe_customer_id=?').bind(customerId).first<any>();
      if (tenant) {
        slog('warn', 'Payment failed', { tenant_id: tenant.id, invoice_id: invoice.id });
        await c.env.DB.prepare('INSERT INTO recent_activity (tenant_id,action,file_name,performed_by) VALUES (?,\'payment_failed\',\'Payment failed — action required\',\'stripe\')')
          .bind(tenant.id).run();
      }
      break;
    }

    default:
      slog('info', 'Unhandled Stripe event type', { type: event.type });
  }

  return c.json({ received: true });
});

// ── Admin: Migrate Stripe columns ──
app.post('/admin/migrate-stripe', async (c) => {
  const migrations = [
    `ALTER TABLE tenants ADD COLUMN stripe_customer_id TEXT`,
    `ALTER TABLE tenants ADD COLUMN stripe_subscription_id TEXT`,
    `ALTER TABLE tenants ADD COLUMN max_storage_mb REAL DEFAULT 100`,
    `ALTER TABLE tenants ADD COLUMN max_files INTEGER DEFAULT 50`,
    `ALTER TABLE tenants ADD COLUMN used_storage_mb REAL DEFAULT 0`,
  ];
  const results: { sql: string; status: string }[] = [];
  for (const sql of migrations) {
    try {
      await c.env.DB.prepare(sql).run();
      results.push({ sql, status: 'applied' });
    } catch (e: any) {
      if (e.message?.includes('duplicate column') || e.message?.includes('already exists')) {
        results.push({ sql, status: 'already_exists' });
      } else {
        results.push({ sql, status: `error: ${e.message}` });
      }
    }
  }
  slog('info', 'Stripe migration executed', { results });
  return c.json({ migrated: true, results });
});

app.onError((err, c) => {
  if (err.message?.includes('JSON')) {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }
  console.error(`[echo-document-manager] ${err.message}`);
  return c.json({ error: 'Internal server error' }, 500);
});

app.notFound((c) => {
  return c.json({ error: 'Not found' }, 404);
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
