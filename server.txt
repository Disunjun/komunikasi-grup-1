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
const FRONTEND_ORIGINS = (process.env.FRONTEND_ORIGINS || '*').split(',').map(s => s.trim()).filter(Boolean);
const ADMIN_NAME = process.env.ADMIN_NAME || 'Didik Suntoro';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'D1d1kSunt0r0@#$';
const ADMIN_SESSION_TTL_MS = Math.max(5 * 60 * 1000, Number(process.env.ADMIN_SESSION_TTL_MS || 30 * 60 * 1000));
const adminSessions = new Map(); // tokenHash -> {adminName, expiresAt, createdAt}

const corsOrigin = FRONTEND_ORIGINS.includes('*') ? true : FRONTEND_ORIGINS;
const io = new Server(server, { cors: { origin: corsOrigin, methods: ['GET','POST','PATCH','DELETE'] }, transports: ['websocket','polling'] });
app.use(cors({ origin: corsOrigin }));
app.use(express.json({ limit: '64kb' }));

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
function publicUser(row) {
  return { id: row.id, nama: row.username, role: row.role || 'user', status: row.active ? 'aktif' : 'nonaktif', banned: !!row.banned, muted: !!row.muted, dibuatOleh: row.created_by || 'system', tanggalDibuat: row.created_at ? new Date(row.created_at).toLocaleDateString('id-ID') : '-' };
}
function requireDb(res) { if (db) return true; res.status(503).json({ok:false,message:'Database belum tersedia'}); return false; }
function hashAdminToken(token) {
  return crypto.createHash('sha256').update(String(token || '')).digest('hex');
}
function createAdminSession(adminName=ADMIN_NAME) {
  const token = crypto.randomBytes(32).toString('base64url');
  const tokenHash = hashAdminToken(token);
  const now = Date.now();
  const expiresAt = now + ADMIN_SESSION_TTL_MS;
  adminSessions.set(tokenHash, { adminName, createdAt:now, expiresAt });
  return { token, expiresAt };
}
function getBearerToken(req) {
  const h = String(req.get('authorization') || '');
  return h.toLowerCase().startsWith('bearer ') ? h.slice(7).trim() : '';
}
function getAdminSession(req) {
  const token = getBearerToken(req);
  if(!token) return null;
  const tokenHash = hashAdminToken(token);
  const s = adminSessions.get(tokenHash);
  if(!s) return null;
  if(s.expiresAt <= Date.now()) {
    adminSessions.delete(tokenHash);
    return null;
  }
  return { ...s, tokenHash };
}
function requireAdmin(req,res,next) {
  const session = getAdminSession(req);
  if(session) {
    req.adminSession = session;
    return next();
  }
  return res.status(401).json({ok:false,message:'Session Admin tidak valid atau sudah berakhir.'});
}

function publicAudit(row) {
  return {
    id: row.id,
    adminName: row.admin_name,
    action: row.action,
    target: row.target || '',
    detail: row.detail || '',
    createdAt: row.created_at
  };
}

async function writeAudit(adminName, action, target='', detail='') {
  if (!db) return null;
  try {
    const r = await db.query(
      `INSERT INTO audit_logs(admin_name,action,target,detail,created_at)
       VALUES($1,$2,$3,$4,NOW())
       RETURNING *`,
      [
        String(adminName || ADMIN_NAME).slice(0,100),
        String(action || '').slice(0,100),
        String(target || '').slice(0,2000),
        String(detail || '').slice(0,10000)
      ]
    );
    const log = publicAudit(r.rows[0]);
    io.emit('audit:new', log);
    return log;
  } catch(e) {
    console.error('[AUDIT] WRITE ERROR:', e.message);
    return null;
  }
}

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

    // ===== STAGE G1: centralized user activity/statistics =====
    await db.query(`CREATE TABLE IF NOT EXISTS activity_logs (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(100) NOT NULL,
      group_name VARCHAR(100),
      channel_name VARCHAR(100),
      action VARCHAR(30) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    await db.query(`CREATE INDEX IF NOT EXISTS idx_activity_logs_created_at ON activity_logs(created_at DESC)`);
    await db.query(`CREATE INDEX IF NOT EXISTS idx_activity_logs_group_channel ON activity_logs(group_name,channel_name)`);

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

// ===== STAGE H1: SHORT-LIVED ADMIN SESSION TOKEN =====
const adminLoginAttempts = new Map();
function loginAttemptKey(req) {
  return String(req.ip || req.socket?.remoteAddress || 'unknown');
}
function checkAdminLoginRate(req) {
  const key = loginAttemptKey(req);
  const now = Date.now();
  const state = adminLoginAttempts.get(key);
  if(!state || state.resetAt <= now) {
    adminLoginAttempts.set(key, {count:0, resetAt:now + 10*60*1000});
    return {ok:true,key};
  }
  if(state.count >= 5) return {ok:false,key,retryAfterMs:state.resetAt-now};
  return {ok:true,key};
}
function recordAdminLoginFailure(key) {
  const state = adminLoginAttempts.get(key) || {count:0, resetAt:Date.now()+10*60*1000};
  state.count++;
  adminLoginAttempts.set(key,state);
}
function clearAdminLoginFailures(key) { adminLoginAttempts.delete(key); }

app.post('/api/admin/login', async (req,res) => {
  const rate = checkAdminLoginRate(req);
  if(!rate.ok) {
    res.set('Retry-After', String(Math.ceil(rate.retryAfterMs/1000)));
    return res.status(429).json({ok:false,message:'Terlalu banyak percobaan login Admin. Coba lagi beberapa menit.'});
  }

  const nama = String(req.body?.nama || '').trim();
  const sandi = String(req.body?.sandi || '');

  // Constant-time-ish verification path through password hash in PostgreSQL when available.
  try {
    let valid = false;
    if(db) {
      const r = await db.query(`SELECT username,password_hash,role,active,banned FROM users WHERE LOWER(username)=LOWER($1) LIMIT 1`, [nama]);
      const u = r.rows[0];
      if(u && u.role === 'admin' && u.active && !u.banned) {
        valid = await verifyPassword(sandi, u.password_hash);
      }
    } else {
      valid = nama === ADMIN_NAME && sandi === ADMIN_PASSWORD;
    }

    if(!valid) {
      recordAdminLoginFailure(rate.key);
      await writeAudit(nama || 'unknown','LOGIN ADMIN GAGAL','admin',`ip=${loginAttemptKey(req)}`);
      return res.status(401).json({ok:false,message:'ID atau password Admin salah.'});
    }

    clearAdminLoginFailures(rate.key);
    const session = createAdminSession(nama);
    await writeAudit(nama,'LOGIN ADMIN','admin',`session TTL=${Math.round(ADMIN_SESSION_TTL_MS/60000)} menit`);
    return res.json({
      ok:true,
      admin:{nama},
      token:session.token,
      expiresAt:new Date(session.expiresAt).toISOString(),
      expiresInSeconds:Math.floor(ADMIN_SESSION_TTL_MS/1000)
    });
  } catch(e) {
    console.error('[ADMIN AUTH] LOGIN ERROR:', e.message);
    return res.status(500).json({ok:false,message:'Login Admin gagal.'});
  }
});

app.get('/api/admin/session', requireAdmin, (req,res) => {
  res.json({
    ok:true,
    admin:{nama:req.adminSession?.adminName || ADMIN_NAME},
    expiresAt:req.adminSession?.expiresAt ? new Date(req.adminSession.expiresAt).toISOString() : null
  });
});

app.post('/api/admin/logout', requireAdmin, async (req,res) => {
  const token = getBearerToken(req);
  if(token) adminSessions.delete(hashAdminToken(token));
  await writeAudit(req.adminSession?.adminName || ADMIN_NAME,'LOGOUT ADMIN','admin','Session dicabut');
  res.json({ok:true});
});

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
    const u=r.rows[0]; if(!u || !(await verifyPassword(sandi,u.password_hash))) return res.status(401).json({ok:false,message:'Nama atau Kata Sandi salah!'});
    if(u.banned) return res.status(403).json({ok:false,message:'Akun Anda telah di-banned! Hubungi admin.'});
    if(!u.active) return res.status(403).json({ok:false,message:'Akun Anda dinonaktifkan! Hubungi admin.'});
    console.log('[USER] LOGIN:',u.username); res.json({ok:true,user:publicUser(u)});
  } catch(e){ console.error('[USER] LOGIN ERROR:',e.message); res.status(500).json({ok:false,message:'Login gagal.'}); }
});
app.post('/api/auth/me', async (req,res) => {
  try {
    const nama = String(req.body?.nama || '').trim();
    const sandi = String(req.body?.sandi || '');
    if(!nama || !sandi) return res.status(400).json({ok:false,message:'Nama dan password wajib diisi'});
    if(!db) return res.status(503).json({ok:false,message:'Database tidak tersedia'});

    const r = await db.query(`SELECT id,username,password_hash,role,active,banned,muted,created_at FROM users WHERE LOWER(username)=LOWER($1) LIMIT 1`, [nama]);
    const u = r.rows[0];
    if(!u || !(await verifyPassword(sandi, u.password_hash))) {
      return res.status(401).json({ok:false,message:'Nama atau password salah'});
    }
    if(!u.active) return res.status(403).json({ok:false,message:'Akun dinonaktifkan'});
    if(u.banned) return res.status(403).json({ok:false,message:'Akun dibanned'});

    return res.json({ok:true,user:{
      id:u.id,
      nama:u.username,
      role:u.role,
      status:u.active ? 'aktif' : 'nonaktif',
      banned:!!u.banned,
      muted:!!u.muted,
      createdAt:u.created_at
    }});
  } catch(e) {
    console.error('[AUTH ME] ERROR:', e.message);
    return res.status(500).json({ok:false,message:'Gagal memverifikasi user'});
  }
});


app.get('/api/users', requireAdmin, async (req,res)=>{ if(!requireDb(res)) return; try { const r=await db.query(`SELECT * FROM users ORDER BY id ASC`); res.json({ok:true,users:r.rows.map(publicUser)}); } catch(e){res.status(500).json({ok:false,message:e.message});} });
app.post('/api/users', requireAdmin, async (req,res)=>{ if(!requireDb(res)) return; try { const nama=String(req.body?.nama||'').trim(),sandi=String(req.body?.sandi||''); if(nama.length<2||sandi.length<4)return res.status(400).json({ok:false,message:'Nama/password tidak valid.'}); const h=await hashPassword(sandi); const r=await db.query(`INSERT INTO users(username,password_hash,role,active,banned,muted,created_by) VALUES($1,$2,'user',TRUE,FALSE,FALSE,$3) RETURNING *`,[nama,h,ADMIN_NAME]); console.log('[USER] ADMIN CREATE:',nama); await writeAudit(ADMIN_NAME,'BUAT USER',nama,'User dibuat melalui Admin Panel'); res.json({ok:true,user:publicUser(r.rows[0])}); } catch(e){ if(e.code==='23505')return res.status(409).json({ok:false,message:'Nama sudah terdaftar.'}); res.status(500).json({ok:false,message:e.message}); } });
app.patch('/api/users/:id', requireAdmin, async (req,res)=>{ if(!requireDb(res)) return; try { const active=req.body?.status==='aktif', banned=!!req.body?.banned, muted=!!req.body?.muted; const r=await db.query(`UPDATE users SET active=$1,banned=$2,muted=$3,updated_at=NOW() WHERE id=$4 AND role<>'admin' RETURNING *`,[active,banned,muted,req.params.id]); if(!r.rows[0])return res.status(404).json({ok:false,message:'User tidak ditemukan/tidak dapat diubah.'}); console.log('[USER] UPDATE:',r.rows[0].username); await writeAudit(ADMIN_NAME,'UPDATE USER',r.rows[0].username,`status=${active?'aktif':'nonaktif'}, banned=${banned}, muted=${muted}`); res.json({ok:true,user:publicUser(r.rows[0])}); } catch(e){res.status(500).json({ok:false,message:e.message});} });
app.patch('/api/users/:id/password', requireAdmin, async (req,res)=>{ if(!requireDb(res)) return; try { const sandi=String(req.body?.sandi||''); if(sandi.length<4)return res.status(400).json({ok:false,message:'Password minimal 4 karakter.'}); const h=await hashPassword(sandi); const r=await db.query(`UPDATE users SET password_hash=$1,updated_at=NOW() WHERE id=$2 AND role<>'admin' RETURNING username`,[h,req.params.id]); if(!r.rows[0])return res.status(404).json({ok:false,message:'User tidak ditemukan.'}); console.log('[USER] RESET PASSWORD:',r.rows[0].username); await writeAudit(ADMIN_NAME,'RESET PASSWORD',r.rows[0].username,'Password user direset oleh Admin'); res.json({ok:true}); } catch(e){res.status(500).json({ok:false,message:e.message});} });
app.delete('/api/users/:id', requireAdmin, async (req,res)=>{ if(!requireDb(res)) return; try { const r=await db.query(`DELETE FROM users WHERE id=$1 AND role<>'admin' RETURNING username`,[req.params.id]); if(!r.rows[0])return res.status(404).json({ok:false,message:'User tidak ditemukan.'}); console.log('[USER] DELETE:',r.rows[0].username); await writeAudit(ADMIN_NAME,'HAPUS USER',r.rows[0].username,'User dihapus melalui Admin Panel'); res.json({ok:true}); } catch(e){res.status(500).json({ok:false,message:e.message});} });

const sessions=new Map(), rooms=new Map(), kicked=new Map();
function publicSessions(){ const out={}; for(const s of sessions.values()) out[s.nama]={nama:s.nama,group:s.group,channel:s.channel,micStatus:!!s.micStatus,floorStatus:s.floorStatus||'idle',peerId:s.peerId||null,timestamp:s.timestamp}; return out; }
function roomUsers(room){ return [...(rooms.get(room)||new Set())].map(id=>sessions.get(id)).filter(Boolean).map(s=>({nama:s.nama,group:s.group,channel:s.channel,peerId:s.peerId,micStatus:!!s.micStatus,floorStatus:s.floorStatus||'idle'})); }
async function savePresence(s){ if(!db||!s)return; try{await db.query(`INSERT INTO online_sessions(socket_id,username,group_name,channel_name,peer_id,mic_status,floor_status,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,NOW()) ON CONFLICT(socket_id) DO UPDATE SET username=EXCLUDED.username,group_name=EXCLUDED.group_name,channel_name=EXCLUDED.channel_name,peer_id=EXCLUDED.peer_id,mic_status=EXCLUDED.mic_status,floor_status=EXCLUDED.floor_status,updated_at=NOW()`,[s.socketId,s.nama,s.group,s.channel,s.peerId,!!s.micStatus,s.floorStatus||'idle']);}catch(e){console.error('[DB] savePresence:',e.message);} }
async function removePresence(id){if(!db)return;try{await db.query(`DELETE FROM online_sessions WHERE socket_id=$1`,[id]);}catch(e){console.error('[DB] removePresence:',e.message);}}
function emitPresence(){io.emit('presence:update',publicSessions());}

app.get('/health',async(req,res)=>{let database='disabled';if(db){try{await db.query('SELECT 1');database='connected';}catch{database='error';}}res.json({ok:true,service:'komunikasi-group-realtime',version:'2.7.2-H3.1-DUAL-AUTH',database,time:new Date().toISOString(),users:sessions.size});});

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

app.put('/api/config/groups', requireAdmin, async (req,res) => {
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
      ['groups', JSON.stringify(groups), ADMIN_NAME]
    );

    console.log('[CONFIG] GROUPS SAVED:', groups.length);
    await writeAudit(
      ADMIN_NAME,
      'SIMPAN GROUP/CHANNEL',
      'groups',
      `group=${groups.length}, channel=${groups.reduce((n,g)=>n+(Array.isArray(g.channel)?g.channel.length:0),0)}`
    );
    io.emit('config:groups:update', {
      groups:r.rows[0].config_value,
      updatedBy:r.rows[0].updated_by,
      updatedAt:r.rows[0].updated_at
    });
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


// ===== ADMIN SYNC STAGE E1: PostgreSQL Audit Log API =====
app.get('/api/audit-logs', requireAdmin, async (req,res) => {
  if(!requireDb(res)) return;
  try {
    const requested = Number(req.query?.limit || 200);
    const limit = Math.min(1000, Math.max(1, Number.isFinite(requested) ? requested : 200));
    const r = await db.query(
      `SELECT id,admin_name,action,target,detail,created_at
       FROM audit_logs
       ORDER BY id DESC
       LIMIT $1`,
      [limit]
    );
    res.json({ok:true,logs:r.rows.map(publicAudit)});
  } catch(e) {
    console.error('[AUDIT] GET ERROR:', e.message);
    res.status(500).json({ok:false,message:'Gagal membaca Audit Log.'});
  }
});

app.delete('/api/audit-logs', requireAdmin, async (req,res) => {
  if(!requireDb(res)) return;
  try {
    const count = await db.query(`SELECT COUNT(*)::int AS total FROM audit_logs`);
    await db.query(`DELETE FROM audit_logs`);
    const log = await writeAudit(ADMIN_NAME,'HAPUS AUDIT LOG','audit_logs',`Menghapus ${count.rows[0]?.total || 0} log lama`);
    res.json({ok:true,deleted:count.rows[0]?.total || 0,log});
  } catch(e) {
    console.error('[AUDIT] DELETE ERROR:', e.message);
    res.status(500).json({ok:false,message:'Gagal menghapus Audit Log.'});
  }
});


async function writeActivity(username, groupName, channelName, action) {
  if (!db) return;
  try {
    await db.query(
      `INSERT INTO activity_logs(username,group_name,channel_name,action,created_at)
       VALUES($1,$2,$3,$4,NOW())`,
      [
        String(username || '').slice(0,100),
        String(groupName || '').slice(0,100),
        String(channelName || '').slice(0,100),
        String(action || '').slice(0,30)
      ]
    );
  } catch(e) {
    console.error('[ACTIVITY] WRITE ERROR:', e.message);
  }
}

// Centralized Monitoring + Statistics source for Admin Panel.
app.get('/api/admin/stats', requireAdmin, async (req,res) => {
  if(!requireDb(res)) return;
  try {
    const [usersR, groupsR, activityR] = await Promise.all([
      db.query(`SELECT COUNT(*)::int AS total FROM users`),
      db.query(`SELECT config_value FROM app_config WHERE config_key='groups' LIMIT 1`),
      db.query(`
        SELECT id,username,group_name,channel_name,action,created_at
        FROM activity_logs
        WHERE created_at >= NOW() - INTERVAL '12 months'
        ORDER BY id DESC
        LIMIT 10000
      `)
    ]);

    const groups = Array.isArray(groupsR.rows[0]?.config_value) ? groupsR.rows[0].config_value : [];
    const totalChannels = groups.reduce((n,g)=>n+(Array.isArray(g.channel)?g.channel.length:0),0);

    res.json({
      ok:true,
      summary:{
        totalUsers: usersR.rows[0]?.total || 0,
        onlineUsers: sessions.size,
        totalGroups: groups.length,
        totalChannels
      },
      sessions: publicSessions(),
      activity: activityR.rows.map(r=>({
        id:r.id,
        nama:r.username,
        group:r.group_name || '',
        channel:r.channel_name || '',
        aksi:r.action,
        createdAt:r.created_at
      }))
    });
  } catch(e) {
    console.error('[STATS] GET ERROR:', e.message);
    res.status(500).json({ok:false,message:'Gagal membaca Monitoring/Statistik.'});
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

io.on('connection',socket=>{
  console.log('[SOCKET] Connected:',socket.id); socket.emit('server:ready',{version:'2.7.1-H3-TOKEN-ONLY',transport:socket.conn.transport.name});
  socket.on('room:join',async payload=>{try{
    const nama=String(payload?.nama||'').trim(),group=String(payload?.group||'').trim(),channel=String(payload?.channel||'').trim(),peerId=String(payload?.peerId||'').trim(),maxUsers=Number(payload?.maxUsers||0);
    if(!nama||!group||!channel||!peerId)return socket.emit('room:error',{message:'Data room tidak lengkap.'});
    if(db){const ur=await db.query(`SELECT active,banned FROM users WHERE lower(username)=lower($1) LIMIT 1`,[nama]); if(!ur.rows[0])return socket.emit('room:error',{message:'User tidak terdaftar di database.'}); if(ur.rows[0].banned||!ur.rows[0].active)return socket.emit('room:error',{message:'Akun tidak diizinkan masuk.'});}
    const blockedUntil=kicked.get(nama);if(blockedUntil&&blockedUntil>Date.now())return socket.emit('room:error',{message:'Anda sedang di-kick oleh admin.'});
    const room=`${group}::${channel}`; const existing=[...(rooms.get(room)||new Set())].map(id=>sessions.get(id)).filter(Boolean).filter(s=>s.nama!==nama); if(maxUsers>0&&existing.length>=maxUsers)return socket.emit('room:error',{message:`Channel penuh! Maksimal ${maxUsers} user.`});
    const old=sessions.get(socket.id);
    if(old?.room){
      rooms.get(old.room)?.delete(socket.id);
      socket.leave(old.room);
      await writeActivity(old.nama,old.group,old.channel,'KELUAR');
    }
    const session={socketId:socket.id,nama,group,channel,room,peerId,micStatus:false,floorStatus:'idle',timestamp:Date.now()};
    sessions.set(socket.id,session);
    if(!rooms.has(room))rooms.set(room,new Set());
    rooms.get(room).add(socket.id);
    socket.join(room);
    await savePresence(session);
    await writeActivity(nama,group,channel,'MASUK');
    socket.emit('room:joined',{room,users:roomUsers(room),self:session});
    io.to(room).emit('room:users',roomUsers(room));
    emitPresence();
    console.log('[ROOM JOIN]',nama,'=>',room);
  }catch(e){console.error('[ROOM JOIN ERROR]',e);socket.emit('room:error',{message:e.message||'Gagal bergabung room.'});}});
  socket.on('presence:update',async patch=>{const s=sessions.get(socket.id);if(!s)return;if(typeof patch?.micStatus==='boolean')s.micStatus=patch.micStatus;if(typeof patch?.floorStatus==='string')s.floorStatus=patch.floorStatus;s.timestamp=Date.now();await savePresence(s);io.to(s.room).emit('room:users',roomUsers(s.room));emitPresence();});
  socket.on('floor:event',event=>{const s=sessions.get(socket.id);if(!s?.room)return;socket.to(s.room).emit('floor:event',{...event,from:s.nama});});
  socket.on('chat:send',async(payload,ack)=>{try{const s=sessions.get(socket.id);if(!s?.room){ack?.({ok:false,message:'Belum masuk channel.'});return;}const message=String(payload?.message||'').trim().slice(0,2000);if(!message){ack?.({ok:false,message:'Pesan kosong.'});return;}if(db){const ur=await db.query(`SELECT muted,active,banned FROM users WHERE lower(username)=lower($1) LIMIT 1`,[s.nama]);if(ur.rows[0]?.muted||!ur.rows[0]?.active||ur.rows[0]?.banned){ack?.({ok:false,message:'Akun tidak diizinkan mengirim pesan.'});return;}await db.query(`INSERT INTO chat_messages(username,group_name,channel_name,message) VALUES($1,$2,$3,$4)`,[s.nama,s.group,s.channel,message]);}io.to(s.room).emit('chat:message',{nama:s.nama,message});ack?.({ok:true});}catch(e){console.error('[CHAT ERROR]',e.message);socket.emit('chat:error',{message:'Pesan gagal dikirim.'});ack?.({ok:false,message:'Pesan gagal dikirim.'});}});
  socket.on('admin:kick',async({nama})=>{if(!nama)return;kicked.set(nama,Date.now()+300000);await writeAudit(ADMIN_NAME,'KICK USER',nama,'User di-kick selama 5 menit');for(const s of sessions.values())if(s.nama===nama){io.to(s.socketId).emit('admin:kick',{nama,expiresAt:kicked.get(nama)});io.sockets.sockets.get(s.socketId)?.disconnect(true);}});
  socket.on('disconnect',async reason=>{const s=sessions.get(socket.id);console.log('[SOCKET] Disconnect:',socket.id,reason);if(!s)return;rooms.get(s.room)?.delete(socket.id);if(rooms.get(s.room)?.size===0)rooms.delete(s.room);sessions.delete(socket.id);await removePresence(socket.id);await writeActivity(s.nama,s.group,s.channel,'KELUAR');if(s.room)io.to(s.room).emit('room:users',roomUsers(s.room));emitPresence();});
});
setInterval(()=>{
  const now=Date.now();
  for(const [tokenHash,s] of adminSessions) if(s.expiresAt<=now) adminSessions.delete(tokenHash);
},60000);

setInterval(async()=>{const cutoff=Date.now()-65000;for(const[id,s]of sessions)if(s.timestamp<cutoff){rooms.get(s.room)?.delete(id);sessions.delete(id);await removePresence(id);await writeActivity(s.nama,s.group,s.channel,'KELUAR');}emitPresence();},15000);

async function startServer(){console.log('========================================');console.log(' Komunikasi Group V2 Backend');console.log(' Version 2.7.1-H3-TOKEN-ONLY');console.log('========================================');await testDatabase();await initializeDatabase();server.listen(PORT,()=>{console.log(`[SERVER] Listening on port ${PORT}`);console.log(`[SERVER] PostgreSQL: ${db?'ENABLED':'DISABLED'}`);});}
startServer();
