import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import http from 'http';
import crypto from 'crypto';
import { promisify } from 'util';
import { Server } from 'socket.io';
import pg from 'pg';

const { Pool } = pg;
const scryptAsync = promisify(crypto.scrypt);
const app = express();
const server = http.createServer(app);
const PORT = Number(process.env.PORT || 3000);
const FRONTEND_ORIGINS = (process.env.FRONTEND_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);
const ADMIN_NAME = process.env.ADMIN_NAME || 'Didik Suntoro';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'D1d1kSunt0r0@#$';

// ===== CORS / FRONTEND ACCESS =====
// Production frontend is explicitly allowed. Keep the old frontend origin
// during the migration so an older cached client is not unexpectedly blocked.
const ALLOWED_CORS_ORIGINS = Array.from(new Set([
  ...FRONTEND_ORIGINS,
  'https://komunikasi-group-1.netlify.app',
  'https://komunikasi-group.netlify.app'
]));

function corsOriginAllowed(origin) {
  if (!origin) return true; // server-to-server / curl / health checks
  if (ALLOWED_CORS_ORIGINS.includes('*')) return true;
  return ALLOWED_CORS_ORIGINS.includes(origin);
}

const corsOptions = {
  origin(origin, callback) {
    if (corsOriginAllowed(origin)) return callback(null, true);
    console.warn(`[CORS] Origin ditolak: ${origin}`);
    return callback(null, false);
  },
  methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 204
};

const io = new Server(server, {
  cors: {
    origin: (origin, callback) => {
      if (corsOriginAllowed(origin)) return callback(null, true);
      console.warn(`[SOCKET CORS] Origin ditolak: ${origin}`);
      return callback(null, false);
    },
    methods: corsOptions.methods,
    allowedHeaders: corsOptions.allowedHeaders
  },
  transports: ['websocket', 'polling']
});

// Express-level CORS handles browser preflight (OPTIONS) before auth routes.
app.use(cors(corsOptions));
app.options(/.*/, cors(corsOptions));
app.use(express.json({ limit: '64kb' }));

console.log('[CORS] Allowed origins:', ALLOWED_CORS_ORIGINS.join(', '));

let db = null;
if (process.env.DATABASE_URL) {
  db = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  console.log('[DB] DATABASE_URL ditemukan.');
} else console.warn('[DB] DATABASE_URL tidak ditemukan. Database dinonaktifkan.');

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = await scryptAsync(password, salt, 64);
  return `scrypt$${salt}$${Buffer.from(derived).toString('hex')}`;
}
async function verifyPassword(password, stored) {
  if (!stored) return false;
  if (!stored.startsWith('scrypt$')) return crypto.timingSafeEqual(Buffer.from(String(password)), Buffer.from(String(stored)));
  const [, salt, hex] = stored.split('$');
  const derived = Buffer.from(await scryptAsync(password, salt, 64));
  const expected = Buffer.from(hex, 'hex');
  return derived.length === expected.length && crypto.timingSafeEqual(derived, expected);
}

// ===== USER TOKEN AUTH (A1.3) =====
const USER_TOKEN_TTL_DAYS = Math.max(1, Number(process.env.USER_TOKEN_TTL_DAYS || 30));
function hashUserToken(token) { return crypto.createHash('sha256').update(String(token)).digest('hex'); }
function createUserToken() { return crypto.randomBytes(32).toString('base64url'); }
function userTokenExpiry() { return new Date(Date.now() + USER_TOKEN_TTL_DAYS * 86400000); }
function bearerToken(req) { const v=String(req.get('authorization')||''); const m=v.match(/^Bearer\s+(.+)$/i); return m?m[1].trim():''; }
async function getUserFromToken(token) {
  if(!db||!token) return null;
  const r=await db.query(`SELECT u.*,s.id AS session_id,s.expires_at AS session_expires_at FROM auth_sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>NOW() AND u.active=TRUE AND u.banned=FALSE LIMIT 1`,[hashUserToken(token)]);
  const u=r.rows[0]; if(!u) return null;
  await db.query(`UPDATE auth_sessions SET last_used_at=NOW() WHERE id=$1`,[u.session_id]);
  return u;
}
async function requireUser(req,res,next) {
  if(!requireDb(res)) return;
  try { const token=bearerToken(req); const user=await getUserFromToken(token); if(!user)return res.status(401).json({ok:false,message:'Token tidak valid atau sudah kedaluwarsa.'}); req.user=user; req.userToken=token; next(); }
  catch(e){ console.error('[AUTH] TOKEN ERROR:',e.message); res.status(500).json({ok:false,message:'Gagal memvalidasi token.'}); }
}
// ===== ADMIN TOKEN AUTH (A1.5) =====
const ADMIN_TOKEN_TTL_HOURS = Math.max(1, Number(process.env.ADMIN_TOKEN_TTL_HOURS || 8));
function createAdminToken() { return crypto.randomBytes(32).toString('base64url'); }
function hashAdminToken(token) { return crypto.createHash('sha256').update(String(token)).digest('hex'); }
function adminTokenExpiry() { return new Date(Date.now() + ADMIN_TOKEN_TTL_HOURS * 3600000); }
function adminBearerToken(req) { const v=String(req.get('authorization')||''); const m=v.match(/^Bearer\s+(.+)$/i); return m?m[1].trim():''; }
async function getAdminFromToken(token) {
  if(!db || !token) return null;
  const r=await db.query(`SELECT a.*,u.username FROM admin_sessions a JOIN users u ON u.id=a.admin_user_id WHERE a.token_hash=$1 AND a.revoked_at IS NULL AND a.expires_at>NOW() AND u.role='admin' AND u.active=TRUE AND u.banned=FALSE LIMIT 1`,[hashAdminToken(token)]);
  const a=r.rows[0]; if(!a) return null;
  await db.query(`UPDATE admin_sessions SET last_used_at=NOW() WHERE id=$1`,[a.id]);
  return a;
}
async function requireAdminToken(req,res,next) {
  if(!requireDb(res)) return;
  try {
    const token=adminBearerToken(req); const admin=await getAdminFromToken(token);
    if(!admin) return res.status(401).json({ok:false,message:'Admin Token tidak valid atau sudah berakhir.'});
    req.adminSession=admin; req.adminToken=token; next();
  } catch(e) { console.error('[ADMIN AUTH] TOKEN ERROR:',e.message); res.status(500).json({ok:false,message:'Gagal memvalidasi Admin Token.'}); }
}
async function requireAdminAny(req,res,next) {
  if (adminBearerToken(req)) return requireAdminToken(req,res,next);
  if (isAdminRequest(req)) { req.adminSession={admin_name:ADMIN_NAME,legacy:true}; return next(); }
  return res.status(401).json({ok:false,message:'Admin tidak terautentikasi'});
}
async function auditAdmin(adminSession, action, target='', detail='') {
  if(!db) return;
  const name=adminSession?.admin_name || ADMIN_NAME;
  await db.query(`INSERT INTO audit_logs(admin_name,action,target,detail) VALUES($1,$2,$3,$4)`,[name,action,target,detail]);
}

function publicUser(row) {
  return { id: row.id, nama: row.username, role: row.role || 'user', status: row.active ? 'aktif' : 'nonaktif', banned: !!row.banned, muted: !!row.muted, dibuatOleh: row.created_by || 'system', tanggalDibuat: row.created_at ? new Date(row.created_at).toLocaleDateString('id-ID') : '-' };
}
function requireDb(res) { if (db) return true; res.status(503).json({ok:false,message:'Database belum tersedia'}); return false; }
function isAdminRequest(req) { return req.get('x-admin-name') === ADMIN_NAME && req.get('x-admin-password') === ADMIN_PASSWORD; }
function requireAdmin(req,res,next) { if (!isAdminRequest(req)) return res.status(401).json({ok:false,message:'Admin tidak terautentikasi'}); next(); }

async function testDatabase() {
  if (!db) return;
  try { const r = await db.query('SELECT NOW() AS waktu'); console.log('[DB] PostgreSQL CONNECTED:', r.rows[0].waktu); }
  catch (e) { console.error('[DB] PostgreSQL CONNECTION ERROR:', e.message); }
}
async function initializeDatabase() {
  if (!db) return;
  try {
    await db.query(`CREATE TABLE IF NOT EXISTS users (id BIGSERIAL PRIMARY KEY, username VARCHAR(100) UNIQUE NOT NULL, password_hash TEXT, role VARCHAR(30) DEFAULT 'user', active BOOLEAN DEFAULT TRUE, muted BOOLEAN DEFAULT FALSE, created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW())`);
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS banned BOOLEAN DEFAULT FALSE`);
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS created_by VARCHAR(100) DEFAULT 'system'`);
    await db.query(`CREATE TABLE IF NOT EXISTS online_sessions (socket_id VARCHAR(255) PRIMARY KEY, username VARCHAR(100) NOT NULL, group_name VARCHAR(100), channel_name VARCHAR(100), peer_id VARCHAR(255), mic_status BOOLEAN DEFAULT FALSE, floor_status VARCHAR(30) DEFAULT 'idle', updated_at TIMESTAMPTZ DEFAULT NOW())`);
    await db.query(`CREATE TABLE IF NOT EXISTS chat_messages (id BIGSERIAL PRIMARY KEY, username VARCHAR(100) NOT NULL, group_name VARCHAR(100), channel_name VARCHAR(100), message TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW())`);
    await db.query(`CREATE TABLE IF NOT EXISTS auth_sessions (id BIGSERIAL PRIMARY KEY,user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,token_hash CHAR(64) UNIQUE NOT NULL,created_at TIMESTAMPTZ DEFAULT NOW(),last_used_at TIMESTAMPTZ DEFAULT NOW(),expires_at TIMESTAMPTZ NOT NULL,revoked_at TIMESTAMPTZ)`);
    await db.query(`CREATE INDEX IF NOT EXISTS idx_auth_sessions_token_hash ON auth_sessions(token_hash)`);
    await db.query(`CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_id ON auth_sessions(user_id)`);
    await db.query(`CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires_at ON auth_sessions(expires_at)`);
    await db.query(`CREATE TABLE IF NOT EXISTS admin_sessions (id BIGSERIAL PRIMARY KEY,admin_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,token_hash CHAR(64) UNIQUE NOT NULL,created_at TIMESTAMPTZ DEFAULT NOW(),last_used_at TIMESTAMPTZ DEFAULT NOW(),expires_at TIMESTAMPTZ NOT NULL,revoked_at TIMESTAMPTZ)`);
    await db.query(`CREATE INDEX IF NOT EXISTS idx_admin_sessions_token_hash ON admin_sessions(token_hash)`);
    await db.query(`CREATE INDEX IF NOT EXISTS idx_admin_sessions_admin_user_id ON admin_sessions(admin_user_id)`);
    await db.query(`DELETE FROM admin_sessions WHERE expires_at<=NOW() OR revoked_at IS NOT NULL`);
    await db.query(`DELETE FROM auth_sessions WHERE expires_at<=NOW() OR revoked_at IS NOT NULL`);
    // ===== ADMIN SYNC STAGE A: PostgreSQL schema only =====
    await db.query(`CREATE TABLE IF NOT EXISTS app_config (
      config_key VARCHAR(100) PRIMARY KEY,
      config_value JSONB NOT NULL,
      updated_by VARCHAR(100) DEFAULT 'system',
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )`);

    await db.query(`CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGSERIAL PRIMARY KEY,
      admin_name VARCHAR(100) NOT NULL,
      action VARCHAR(100) NOT NULL,
      target TEXT,
      detail TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);

    const defaultGroups = [
      {nama:'Grup 1',prefix:'',status:'aktif',channel:[
        {nama:'CH 01',prefix:'',maxUsers:0,pttTimeout:0,status:'aktif',locked:false,muted:false},
        {nama:'CH 02',prefix:'',maxUsers:5,pttTimeout:30,status:'aktif',locked:false,muted:false},
        {nama:'CH 03',prefix:'',maxUsers:0,pttTimeout:0,status:'aktif',locked:false,muted:false}
      ]},
      {nama:'Grup 2',prefix:'',status:'aktif',channel:[
        {nama:'CH 01',prefix:'',maxUsers:0,pttTimeout:0,status:'aktif',locked:false,muted:false},
        {nama:'CH 02',prefix:'',maxUsers:3,pttTimeout:15,status:'aktif',locked:false,muted:false}
      ]}
    ];

    await db.query(
      `INSERT INTO app_config(config_key,config_value,updated_by)
       VALUES($1,$2::jsonb,$3)
       ON CONFLICT(config_key) DO NOTHING`,
      ['groups', JSON.stringify(defaultGroups), 'system']
    );

    const adminHash = await hashPassword(ADMIN_PASSWORD);
    await db.query(`INSERT INTO users(username,password_hash,role,active,banned,muted,created_by) VALUES($1,$2,'admin',TRUE,FALSE,FALSE,'system') ON CONFLICT(username) DO UPDATE SET role='admin'`, [ADMIN_NAME, adminHash]);
    console.log('[DB] Database tables READY.');
  } catch(e) { console.error('[DB] Database initialization ERROR:', e.message); }
}

// ===== USER / AUTH API =====
app.post('/api/auth/register', async (req,res) => {
  if (!requireDb(res)) return;
  try {
    const nama=String(req.body?.nama||'').trim(), sandi=String(req.body?.sandi||'');
    if(nama.length<2 || sandi.length<4) return res.status(400).json({ok:false,message:'Nama minimal 2 karakter dan password minimal 4 karakter.'});
    if(nama.toLowerCase()===ADMIN_NAME.toLowerCase()) return res.status(400).json({ok:false,message:'Nama ini tidak boleh digunakan.'});
    const h=await hashPassword(sandi);
    const r=await db.query(`INSERT INTO users(username,password_hash,role,active,banned,muted,created_by) VALUES($1,$2,'user',TRUE,FALSE,FALSE,$1) RETURNING *`,[nama,h]);
    console.log('[USER] REGISTER:', nama); res.json({ok:true,user:publicUser(r.rows[0])});
  } catch(e) { if(e.code==='23505') return res.status(409).json({ok:false,message:'Nama sudah terdaftar.'}); console.error('[USER] REGISTER ERROR:',e.message); res.status(500).json({ok:false,message:'Gagal mendaftar user.'}); }
});
app.post('/api/auth/login', async (req,res) => {
  if (!requireDb(res)) return;
  try {
    const nama=String(req.body?.nama||'').trim(), sandi=String(req.body?.sandi||'');
    const r=await db.query(`SELECT * FROM users WHERE lower(username)=lower($1) LIMIT 1`,[nama]);
    const u=r.rows[0];
    if(!u || !(await verifyPassword(sandi,u.password_hash))) return res.status(401).json({ok:false,message:'Nama atau Kata Sandi salah!'});
    if(u.banned) return res.status(403).json({ok:false,message:'Akun Anda telah di-banned! Hubungi admin.'});
    if(!u.active) return res.status(403).json({ok:false,message:'Akun Anda dinonaktifkan! Hubungi admin.'});
    const token=createUserToken(), expiresAt=userTokenExpiry();
    await db.query(`INSERT INTO auth_sessions(user_id,token_hash,expires_at) VALUES($1,$2,$3)`,[u.id,hashUserToken(token),expiresAt]);
    console.log('[USER] LOGIN:',u.username);
    res.json({ok:true,user:publicUser(u),token,expiresAt:expiresAt.toISOString()});
  } catch(e){ console.error('[USER] LOGIN ERROR:',e.message); res.status(500).json({ok:false,message:'Login gagal.'}); }
});
app.get('/api/auth/me', requireUser, (req,res) => res.json({ok:true,user:publicUser(req.user),expiresAt:new Date(req.user.session_expires_at).toISOString()}));
app.post('/api/auth/logout', requireUser, async (req,res) => {
  try { await db.query(`UPDATE auth_sessions SET revoked_at=NOW() WHERE token_hash=$1 AND revoked_at IS NULL`,[hashUserToken(req.userToken)]); res.json({ok:true}); }
  catch(e){ console.error('[USER] LOGOUT ERROR:',e.message); res.status(500).json({ok:false,message:'Logout gagal.'}); }
});
app.post('/api/admin/login', async (req,res) => {
  if(!requireDb(res)) return;
  try {
    const nama=String(req.body?.nama||'').trim(), sandi=String(req.body?.sandi||'');
    if(nama!==ADMIN_NAME || !(await verifyPassword(sandi,(await db.query(`SELECT password_hash FROM users WHERE lower(username)=lower($1) AND role='admin' LIMIT 1`,[nama])).rows[0]?.password_hash))) {
      return res.status(401).json({ok:false,message:'Nama atau Kata Sandi Admin salah.'});
    }
    const u=(await db.query(`SELECT id,username,role,active,banned FROM users WHERE lower(username)=lower($1) AND role='admin' LIMIT 1`,[nama])).rows[0];
    if(!u || !u.active || u.banned) return res.status(403).json({ok:false,message:'Akun Admin tidak diizinkan.'});
    const token=createAdminToken(), expiresAt=adminTokenExpiry();
    await db.query(`INSERT INTO admin_sessions(admin_user_id,token_hash,expires_at) VALUES($1,$2,$3)`,[u.id,hashAdminToken(token),expiresAt]);
    await auditAdmin({admin_name:u.username},'ADMIN_LOGIN',u.username,'Admin token issued');
    res.json({ok:true,admin:{id:u.id,nama:u.username,role:'admin'},token,expiresAt:expiresAt.toISOString()});
  } catch(e) { console.error('[ADMIN] LOGIN ERROR:',e.message); res.status(500).json({ok:false,message:'Login Admin gagal.'}); }
});
app.get('/api/admin/me', requireAdminToken, async (req,res) => {
  res.json({ok:true,admin:{nama:req.adminSession.username,role:'admin'},expiresAt:new Date(req.adminSession.expires_at).toISOString()});
});
app.post('/api/admin/logout', requireAdminToken, async (req,res) => {
  await db.query(`UPDATE admin_sessions SET revoked_at=NOW() WHERE token_hash=$1 AND revoked_at IS NULL`,[hashAdminToken(req.adminToken)]);
  await auditAdmin(req.adminSession,'ADMIN_LOGOUT',req.adminSession.username,'Admin token revoked');
  res.json({ok:true});
});

app.get('/api/users', requireAdminAny, async (req,res)=>{ if(!requireDb(res)) return; try { const r=await db.query(`SELECT * FROM users ORDER BY id ASC`); res.json({ok:true,users:r.rows.map(publicUser)}); } catch(e){res.status(500).json({ok:false,message:e.message});} });
app.post('/api/users', requireAdminAny, async (req,res)=>{ if(!requireDb(res)) return; try { const nama=String(req.body?.nama||'').trim(),sandi=String(req.body?.sandi||''); if(nama.length<2||sandi.length<4)return res.status(400).json({ok:false,message:'Nama/password tidak valid.'}); const h=await hashPassword(sandi); const r=await db.query(`INSERT INTO users(username,password_hash,role,active,banned,muted,created_by) VALUES($1,$2,'user',TRUE,FALSE,FALSE,$3) RETURNING *`,[nama,h,ADMIN_NAME]); console.log('[USER] ADMIN CREATE:',nama); await auditAdmin(req.adminSession,'USER_CREATE',nama,'User created by admin'); res.json({ok:true,user:publicUser(r.rows[0])}); } catch(e){ if(e.code==='23505')return res.status(409).json({ok:false,message:'Nama sudah terdaftar.'}); res.status(500).json({ok:false,message:e.message}); } });
app.patch('/api/users/:id', requireAdminAny, async (req,res)=>{ if(!requireDb(res)) return; try { const active=req.body?.status==='aktif', banned=!!req.body?.banned, muted=!!req.body?.muted; const r=await db.query(`UPDATE users SET active=$1,banned=$2,muted=$3,updated_at=NOW() WHERE id=$4 AND role<>'admin' RETURNING *`,[active,banned,muted,req.params.id]); if(!r.rows[0])return res.status(404).json({ok:false,message:'User tidak ditemukan/tidak dapat diubah.'}); console.log('[USER] UPDATE:',r.rows[0].username); await auditAdmin(req.adminSession,'USER_UPDATE',r.rows[0].username,JSON.stringify({status:req.body?.status,banned:req.body?.banned,muted:req.body?.muted})); res.json({ok:true,user:publicUser(r.rows[0])}); } catch(e){res.status(500).json({ok:false,message:e.message});} });
app.patch('/api/users/:id/password', requireAdminAny, async (req,res)=>{ if(!requireDb(res)) return; try { const sandi=String(req.body?.sandi||''); if(sandi.length<4)return res.status(400).json({ok:false,message:'Password minimal 4 karakter.'}); const h=await hashPassword(sandi); const r=await db.query(`UPDATE users SET password_hash=$1,updated_at=NOW() WHERE id=$2 AND role<>'admin' RETURNING username`,[h,req.params.id]); if(!r.rows[0])return res.status(404).json({ok:false,message:'User tidak ditemukan.'}); console.log('[USER] RESET PASSWORD:',r.rows[0].username); res.json({ok:true}); } catch(e){res.status(500).json({ok:false,message:e.message});} });
app.delete('/api/users/:id', requireAdminAny, async (req,res)=>{ if(!requireDb(res)) return; try { const r=await db.query(`DELETE FROM users WHERE id=$1 AND role<>'admin' RETURNING username`,[req.params.id]); if(!r.rows[0])return res.status(404).json({ok:false,message:'User tidak ditemukan.'}); console.log('[USER] DELETE:',r.rows[0].username); await auditAdmin(req.adminSession,'USER_DELETE',r.rows[0].username,'User deleted'); res.json({ok:true}); } catch(e){res.status(500).json({ok:false,message:e.message});} });

const sessions=new Map(), rooms=new Map(), kicked=new Map();
function publicSessions(){ const out={}; for(const s of sessions.values()) out[s.nama]={nama:s.nama,group:s.group,channel:s.channel,micStatus:!!s.micStatus,floorStatus:s.floorStatus||'idle',peerId:s.peerId||null,timestamp:s.timestamp}; return out; }
function roomUsers(room){ return [...(rooms.get(room)||new Set())].map(id=>sessions.get(id)).filter(Boolean).map(s=>({nama:s.nama,group:s.group,channel:s.channel,peerId:s.peerId,micStatus:!!s.micStatus,floorStatus:s.floorStatus||'idle'})); }
async function savePresence(s){ if(!db||!s)return; try{await db.query(`INSERT INTO online_sessions(socket_id,username,group_name,channel_name,peer_id,mic_status,floor_status,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,NOW()) ON CONFLICT(socket_id) DO UPDATE SET username=EXCLUDED.username,group_name=EXCLUDED.group_name,channel_name=EXCLUDED.channel_name,peer_id=EXCLUDED.peer_id,mic_status=EXCLUDED.mic_status,floor_status=EXCLUDED.floor_status,updated_at=NOW()`,[s.socketId,s.nama,s.group,s.channel,s.peerId,!!s.micStatus,s.floorStatus||'idle']);}catch(e){console.error('[DB] savePresence:',e.message);} }
async function removePresence(id){if(!db)return;try{await db.query(`DELETE FROM online_sessions WHERE socket_id=$1`,[id]);}catch(e){console.error('[DB] removePresence:',e.message);}}
function emitPresence(){io.emit('presence:update',publicSessions());}

app.get('/health',async(req,res)=>{let database='disabled';if(db){try{await db.query('SELECT 1');database='connected';}catch{database='error';}}res.json({ok:true,service:'komunikasi-group-realtime',version:'2.4.1-E-A1.5',database,time:new Date().toISOString(),users:sessions.size});});

// ===== ADMIN SYNC STAGE B: PostgreSQL Group/Channel API =====
app.get('/api/config/groups', async (req,res) => {
  if(!requireDb(res)) return;
  try {
    const r = await db.query(
      `SELECT config_value, updated_by, updated_at
       FROM app_config
       WHERE config_key=$1
       LIMIT 1`,
      ['groups']
    );
    const row = r.rows[0];
    io.emit('config:groups:update', {
  groups: r.rows[0].config_value,
  updatedBy: r.rows[0].updated_by,
  updatedAt: r.rows[0].updated_at
});
    res.json({
      ok:true,
      groups:row?.config_value || [],
      updatedBy:row?.updated_by || 'system',
      updatedAt:row?.updated_at || null
    });
  } catch(e) {
    console.error('[CONFIG] GET GROUPS:', e.message);
    res.status(500).json({ok:false,message:'Gagal membaca konfigurasi Group/Channel.'});
  }
});

app.put('/api/config/groups', requireAdminAny, async (req,res) => {
  if(!requireDb(res)) return;
  try {
    if(!Array.isArray(req.body?.groups)) {
      return res.status(400).json({ok:false,message:'Format groups tidak valid.'});
    }

    const groups = req.body.groups.map(g => ({
      nama:String(g?.nama || '').trim(),
      prefix:String(g?.prefix || ''),
      status:g?.status === 'nonaktif' ? 'nonaktif' : 'aktif',
      channel:Array.isArray(g?.channel) ? g.channel.map(c => ({
        nama:String(c?.nama || '').trim(),
        prefix:String(c?.prefix || ''),
        maxUsers:Math.max(0, Number(c?.maxUsers) || 0),
        pttTimeout:Math.max(0, Number(c?.pttTimeout) || 0),
        status:c?.status === 'nonaktif' ? 'nonaktif' : 'aktif',
        locked:!!c?.locked,
        muted:!!c?.muted
      })).filter(c => c.nama) : []
    })).filter(g => g.nama);

    const r = await db.query(
      `INSERT INTO app_config(config_key,config_value,updated_by,updated_at)
       VALUES($1,$2::jsonb,$3,NOW())
       ON CONFLICT(config_key) DO UPDATE SET
         config_value=EXCLUDED.config_value,
         updated_by=EXCLUDED.updated_by,
         updated_at=NOW()
       RETURNING config_value,updated_by,updated_at`,
      ['groups', JSON.stringify(groups), req.adminSession?.admin_name || ADMIN_NAME]
    );

    console.log('[CONFIG] GROUPS SAVED:', groups.length);
    res.json({
      ok:true,
      groups:r.rows[0].config_value,
      updatedBy:r.rows[0].updated_by,
      updatedAt:r.rows[0].updated_at
    });
  } catch(e) {
    console.error('[CONFIG] PUT GROUPS:', e.message);
    res.status(500).json({ok:false,message:'Gagal menyimpan konfigurasi Group/Channel.'});
  }
});

app.get('/api/presence',(req,res)=>res.json({ok:true,sessions:publicSessions()}));

// ===== CLOUDFLARE REALTIME TURN =====
// TURN Key ID dan API Token tetap hanya di Railway Variables.
app.get('/api/turn-credentials', async (req, res) => {
  const keyId = process.env.CLOUDFLARE_TURN_KEY_ID;
  const apiToken = process.env.CLOUDFLARE_TURN_API_TOKEN;

  if (!keyId || !apiToken) {
    console.error('[TURN] Cloudflare TURN variables belum lengkap.');
    return res.status(503).json({ ok:false, message:'Cloudflare TURN belum dikonfigurasi di server.' });
  }

  try {
    const cfResponse = await fetch(
      `https://rtc.live.cloudflare.com/v1/turn/keys/${encodeURIComponent(keyId)}/credentials/generate-ice-servers`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ ttl: 86400 })
      }
    );

    const data = await cfResponse.json().catch(() => null);

    if (!cfResponse.ok) {
      console.error('[TURN] Cloudflare request gagal:', cfResponse.status, data);
      return res.status(502).json({
        ok:false,
        message:'Gagal memperoleh TURN credentials dari Cloudflare.',
        status:cfResponse.status
      });
    }

    let iceServers = [];
    if (Array.isArray(data?.iceServers)) iceServers = data.iceServers;
    else if (data && (data.urls || data.url)) iceServers = [data];

    if (!iceServers.length) {
      console.error('[TURN] Respons Cloudflare tidak berisi ICE servers.');
      return res.status(502).json({ ok:false, message:'Respons TURN Cloudflare tidak valid.' });
    }

    console.log('[TURN] Temporary ICE credentials generated.');
    res.json({ ok:true, ttl:86400, iceServers });
  } catch (e) {
    console.error('[TURN] ERROR:', e.message);
    res.status(502).json({ ok:false, message:'Tidak dapat menghubungi Cloudflare TURN.' });
  }
});

app.get('/api/db-test',async(req,res)=>{if(!requireDb(res))return;try{const r=await db.query(`SELECT NOW() AS server_time,current_database() AS database_name`);res.json({ok:true,database:'connected',result:r.rows[0]});}catch(e){res.status(500).json({ok:false,error:e.message});}});

// ===== SOCKET AUTH HARDENING (A1.4) =====
// Authentication is completed BEFORE the connection handler runs, removing the
// race where room:join could arrive before asynchronous token validation.
io.use(async (socket,next)=>{
  try {
    const adminToken=String(socket.handshake?.auth?.adminToken||'').trim();
    socket.data.admin=null;
    if(adminToken && db) {
      const admin=await getAdminFromToken(adminToken);
      if(!admin) return next(new Error('Admin Token tidak valid atau sudah berakhir.'));
      socket.data.admin=admin;
    }
    next();
  } catch(e) { next(new Error('Gagal memvalidasi Admin Token.')); }
});

io.use(async (socket,next)=>{
  try {
    const token=String(socket.handshake?.auth?.token||'').trim();
    socket.data.userToken=token;
    socket.data.user=null;

    // Backward compatibility: legacy Web clients may connect without a token.
    if(!token){
      return next();
    }
    if(!db){
      return next(new Error('Database belum tersedia untuk autentikasi.'));
    }

    const user=await getUserFromToken(token);
    if(!user){
      return next(new Error('Token tidak valid atau sudah kedaluwarsa.'));
    }

    socket.data.user=user;
    next();
  } catch(e){
    console.error('[SOCKET AUTH ERROR]',e.message);
    next(new Error('Gagal memvalidasi token.'));
  }
});

io.on('connection',socket=>{
  const socketToken=socket.data.userToken||'';
  const socketUser=socket.data.user||null;
  if(socketUser){
    socket.emit('auth:ready',{ok:true,user:publicUser(socketUser)});
  }
  console.log('[SOCKET] Connected:',socket.id); socket.emit('server:ready',{version:'2.4.1-E-A1.5',transport:socket.conn.transport.name});
  socket.on('room:join',async payload=>{try{
    const namaPayload=String(payload?.nama||'').trim(),group=String(payload?.group||'').trim(),channel=String(payload?.channel||'').trim(),peerId=String(payload?.peerId||'').trim(),maxUsers=Number(payload?.maxUsers||0);
    if(!namaPayload||!group||!channel||!peerId)return socket.emit('room:error',{message:'Data room tidak lengkap.'});
    if(socketToken&&!socketUser)return socket.emit('room:error',{message:'Autentikasi user gagal. Silakan login kembali.'});
    const nama=socketUser?socketUser.username:namaPayload;
    if(db){const ur=await db.query(`SELECT active,banned FROM users WHERE lower(username)=lower($1) LIMIT 1`,[nama]); if(!ur.rows[0])return socket.emit('room:error',{message:'User tidak terdaftar di database.'}); if(ur.rows[0].banned||!ur.rows[0].active)return socket.emit('room:error',{message:'Akun tidak diizinkan masuk.'});}
    const blockedUntil=kicked.get(nama);if(blockedUntil&&blockedUntil>Date.now())return socket.emit('room:error',{message:'Anda sedang di-kick oleh admin.'});
    const room=`${group}::${channel}`; const existing=[...(rooms.get(room)||new Set())].map(id=>sessions.get(id)).filter(Boolean).filter(s=>s.nama!==nama); if(maxUsers>0&&existing.length>=maxUsers)return socket.emit('room:error',{message:`Channel penuh! Maksimal ${maxUsers} user.`});
    const old=sessions.get(socket.id);if(old?.room){rooms.get(old.room)?.delete(socket.id);socket.leave(old.room);} const session={socketId:socket.id,nama,group,channel,room,peerId,micStatus:false,floorStatus:'idle',timestamp:Date.now()}; sessions.set(socket.id,session);if(!rooms.has(room))rooms.set(room,new Set());rooms.get(room).add(socket.id);socket.join(room);await savePresence(session);socket.emit('room:joined',{room,users:roomUsers(room),self:session});io.to(room).emit('room:users',roomUsers(room));emitPresence();console.log('[ROOM JOIN]',nama,'=>',room);
  }catch(e){console.error('[ROOM JOIN ERROR]',e);socket.emit('room:error',{message:e.message||'Gagal bergabung room.'});}});
  socket.on('presence:update',async patch=>{const s=sessions.get(socket.id);if(!s)return;if(typeof patch?.micStatus==='boolean')s.micStatus=patch.micStatus;if(typeof patch?.floorStatus==='string')s.floorStatus=patch.floorStatus;s.timestamp=Date.now();await savePresence(s);io.to(s.room).emit('room:users',roomUsers(s.room));emitPresence();});
  socket.on('floor:event',event=>{const s=sessions.get(socket.id);if(!s?.room)return;socket.to(s.room).emit('floor:event',{...event,from:s.nama});});
  socket.on('chat:send',async(payload,ack)=>{try{const s=sessions.get(socket.id);if(!s?.room){ack?.({ok:false,message:'Belum masuk channel.'});return;}const message=String(payload?.message||'').trim().slice(0,2000);if(!message){ack?.({ok:false,message:'Pesan kosong.'});return;}if(db){const ur=await db.query(`SELECT muted,active,banned FROM users WHERE lower(username)=lower($1) LIMIT 1`,[s.nama]);if(ur.rows[0]?.muted||!ur.rows[0]?.active||ur.rows[0]?.banned){ack?.({ok:false,message:'Akun tidak diizinkan mengirim pesan.'});return;}await db.query(`INSERT INTO chat_messages(username,group_name,channel_name,message) VALUES($1,$2,$3,$4)`,[s.nama,s.group,s.channel,message]);}io.to(s.room).emit('chat:message',{nama:s.nama,message});ack?.({ok:true});}catch(e){console.error('[CHAT ERROR]',e.message);socket.emit('chat:error',{message:'Pesan gagal dikirim.'});ack?.({ok:false,message:'Pesan gagal dikirim.'});}});
  socket.on('admin:kick',async ({nama},ack)=>{
    if(!nama) return ack?.({ok:false,message:'Target user wajib diisi.'});
    const adminToken=String(socket.handshake?.auth?.adminToken||'').trim();
    let admin=socket.data.admin||null;
    if(!admin && adminToken && db) admin=await getAdminFromToken(adminToken);
    const legacyAllowed=String(process.env.LEGACY_ADMIN_SOCKET_KICK||'true').toLowerCase()==='true';
    if(!admin && !legacyAllowed) return ack?.({ok:false,message:'Admin Socket Token diperlukan.'});
    if(!admin && legacyAllowed) console.warn('[SECURITY] Legacy admin:kick accepted; migrate Web V2 to Admin Token.');
    kicked.set(nama,Date.now()+300000);
    for(const s of sessions.values()) if(s.nama===nama){
      io.to(s.socketId).emit('admin:kick',{nama,expiresAt:kicked.get(nama)});
      io.sockets.sockets.get(s.socketId)?.disconnect(true);
    }
    if(db) await auditAdmin(admin||{admin_name:ADMIN_NAME},'USER_KICK',nama,'Socket kick');
    ack?.({ok:true});
  });
  socket.on('disconnect',async reason=>{const s=sessions.get(socket.id);console.log('[SOCKET] Disconnect:',socket.id,reason);if(!s)return;rooms.get(s.room)?.delete(socket.id);if(rooms.get(s.room)?.size===0)rooms.delete(s.room);sessions.delete(socket.id);await removePresence(socket.id);if(s.room)io.to(s.room).emit('room:users',roomUsers(s.room));emitPresence();});
});
setInterval(async()=>{const cutoff=Date.now()-65000;for(const[id,s]of sessions)if(s.timestamp<cutoff){rooms.get(s.room)?.delete(id);sessions.delete(id);await removePresence(id);}emitPresence();},15000);

async function startServer(){console.log('========================================');console.log(' Komunikasi Group V2 Backend');console.log(' Version 2.4.1-E / A1.5');console.log('========================================');await testDatabase();await initializeDatabase();server.listen(PORT,()=>{console.log(`[SERVER] Listening on port ${PORT}`);console.log(`[SERVER] PostgreSQL: ${db?'ENABLED':'DISABLED'}`);});}
startServer();
