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
if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
  throw new Error(`PORT tidak valid: ${process.env.PORT}`);
}

/*
 * ============================================================
 * ENV / CORS
 * ============================================================
 */

const ADMIN_NAME = String(process.env.ADMIN_NAME || 'Didik Suntoro').trim();
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || '').trim();

const FRONTEND_ORIGINS = String(process.env.FRONTEND_ORIGINS || '')
  .split(',')
  .map(s => s.trim().replace(/\/+$/, ''))
  .filter(Boolean);

const ALLOWED_CORS_ORIGINS = Array.from(new Set([
  ...FRONTEND_ORIGINS,
  'https://komunikasi-group-1.netlify.app',
  'https://komunikasi-group.netlify.app'
]));

function normalizeOrigin(origin) {
  return String(origin || '').trim().replace(/\/+$/, '');
}

function corsOriginAllowed(origin) {
  if (!origin) return true;
  const normalized = normalizeOrigin(origin);

  if (ALLOWED_CORS_ORIGINS.includes('*')) return true;
  return ALLOWED_CORS_ORIGINS.includes(normalized);
}

/*
 * Manual CORS middleware is intentionally used here.
 * This guarantees that browser OPTIONS preflight receives the
 * required headers before any authentication/database route.
 */
app.use((req, res, next) => {
  const origin = req.get('Origin');

  if (origin && corsOriginAllowed(origin)) {
    res.setHeader('Access-Control-Allow-Origin', normalizeOrigin(origin));
    res.setHeader('Access-Control-Allow-Methods', 'GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS');
    res.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type, Authorization, X-Admin-Name, X-Admin-Password'
    );
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  } else if (origin) {
    console.warn(`[CORS] Origin ditolak: ${origin}`);
  }

  if (req.method === 'OPTIONS') {
    if (!origin || corsOriginAllowed(origin)) {
      return res.sendStatus(204);
    }
    return res.status(403).json({
      ok: false,
      message: 'CORS origin tidak diizinkan.'
    });
  }

  next();
});

/*
 * Keep the cors package installed/available for compatibility with
 * the existing package.json, but do not let a second CORS middleware
 * interfere with the explicit headers above.
 */
void cors;

app.use(express.json({ limit: '64kb' }));

/*
 * ============================================================
 * DATABASE
 * ============================================================
 */

let db = null;

if (process.env.DATABASE_URL) {
  db = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });

  db.on('error', err => {
    console.error('[DB] Unexpected PostgreSQL pool error:', err.message);
  });

  console.log('[DB] DATABASE_URL ditemukan.');
} else {
  console.warn('[DB] DATABASE_URL tidak ditemukan. Database dinonaktifkan.');
}

function requireDb(res) {
  if (db) return true;

  res.status(503).json({
    ok: false,
    message: 'Database belum tersedia.'
  });

  return false;
}

async function testDatabase() {
  if (!db) return;

  try {
    const result = await db.query('SELECT NOW() AS waktu');
    console.log('[DB] PostgreSQL CONNECTED:', result.rows[0].waktu);
  } catch (error) {
    console.error('[DB] PostgreSQL CONNECTION ERROR:', error.message);
  }
}

/*
 * ============================================================
 * ROOT / HEALTH
 * ============================================================
 */

const VERSION = '2.4.1-E / A1.5 + CORS/Health/Security Patch';

app.get('/', (req, res) => {
  res.status(200).json({
    ok: true,
    service: 'Komunikasi Group V2 Backend',
    version: VERSION,
    status: 'online',
    time: new Date().toISOString()
  });
});

async function healthHandler(req, res) {
  let database = 'disabled';
  let statusCode = 200;

  if (db) {
    try {
      await db.query('SELECT 1');
      database = 'connected';
    } catch (error) {
      database = 'error';
      statusCode = 503;
      console.error('[HEALTH] PostgreSQL:', error.message);
    }
  }

  res.status(statusCode).json({
    ok: statusCode === 200,
    service: 'komunikasi-group-realtime',
    version: VERSION,
    database,
    port: PORT,
    time: new Date().toISOString(),
    users: sessions.size
  });
}

app.get('/health', healthHandler);
app.get('/api/health', healthHandler);

/*
 * ============================================================
 * PASSWORD / TOKEN HELPERS
 * ============================================================
 */

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = await scryptAsync(String(password), salt, 64);

  return `scrypt$${salt}$${Buffer.from(derived).toString('hex')}`;
}

async function verifyPassword(password, stored) {
  if (!stored) return false;

  if (!String(stored).startsWith('scrypt$')) {
    const a = Buffer.from(String(password));
    const b = Buffer.from(String(stored));

    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }

  const parts = String(stored).split('$');
  if (parts.length !== 3) return false;

  const [, salt, hex] = parts;

  try {
    const derived = Buffer.from(await scryptAsync(String(password), salt, 64));
    const expected = Buffer.from(hex, 'hex');

    return (
      derived.length === expected.length &&
      crypto.timingSafeEqual(derived, expected)
    );
  } catch {
    return false;
  }
}

/*
 * ============================================================
 * USER TOKEN AUTH
 * ============================================================
 */

const USER_TOKEN_TTL_DAYS = Math.max(
  1,
  Number(process.env.USER_TOKEN_TTL_DAYS || 30)
);

function hashUserToken(token) {
  return crypto
    .createHash('sha256')
    .update(String(token))
    .digest('hex');
}

function createUserToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function userTokenExpiry() {
  return new Date(Date.now() + USER_TOKEN_TTL_DAYS * 86400000);
}

function bearerToken(req) {
  const value = String(req.get('authorization') || '');
  const match = value.match(/^Bearer\s+(.+)$/i);

  return match ? match[1].trim() : '';
}

async function getUserFromToken(token) {
  if (!db || !token) return null;

  const result = await db.query(
    `SELECT
       u.*,
       s.id AS session_id,
       s.expires_at AS session_expires_at
     FROM auth_sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = $1
       AND s.revoked_at IS NULL
       AND s.expires_at > NOW()
       AND u.active = TRUE
       AND u.banned = FALSE
     LIMIT 1`,
    [hashUserToken(token)]
  );

  const user = result.rows[0];

  if (!user) return null;

  await db.query(
    `UPDATE auth_sessions
     SET last_used_at = NOW()
     WHERE id = $1`,
    [user.session_id]
  );

  return user;
}

async function requireUser(req, res, next) {
  if (!requireDb(res)) return;

  try {
    const token = bearerToken(req);
    const user = await getUserFromToken(token);

    if (!user) {
      return res.status(401).json({
        ok: false,
        message: 'Token tidak valid atau sudah kedaluwarsa.'
      });
    }

    req.user = user;
    req.userToken = token;

    next();
  } catch (error) {
    console.error('[AUTH] TOKEN ERROR:', error.message);

    res.status(500).json({
      ok: false,
      message: 'Gagal memvalidasi token.'
    });
  }
}

/*
 * ============================================================
 * ADMIN TOKEN AUTH
 * ============================================================
 */

const ADMIN_TOKEN_TTL_HOURS = Math.max(
  1,
  Number(process.env.ADMIN_TOKEN_TTL_HOURS || 8)
);

function createAdminToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function hashAdminToken(token) {
  return crypto
    .createHash('sha256')
    .update(String(token))
    .digest('hex');
}

function adminTokenExpiry() {
  return new Date(Date.now() + ADMIN_TOKEN_TTL_HOURS * 3600000);
}

function adminBearerToken(req) {
  return bearerToken(req);
}

async function getAdminFromToken(token) {
  if (!db || !token) return null;

  const result = await db.query(
    `SELECT
       a.*,
       u.username
     FROM admin_sessions a
     JOIN users u ON u.id = a.admin_user_id
     WHERE a.token_hash = $1
       AND a.revoked_at IS NULL
       AND a.expires_at > NOW()
       AND u.role = 'admin'
       AND u.active = TRUE
       AND u.banned = FALSE
     LIMIT 1`,
    [hashAdminToken(token)]
  );

  const admin = result.rows[0];

  if (!admin) return null;

  await db.query(
    `UPDATE admin_sessions
     SET last_used_at = NOW()
     WHERE id = $1`,
    [admin.id]
  );

  return admin;
}

function isAdminRequest(req) {
  if (!ADMIN_PASSWORD) return false;

  return (
    req.get('x-admin-name') === ADMIN_NAME &&
    req.get('x-admin-password') === ADMIN_PASSWORD
  );
}

async function requireAdminToken(req, res, next) {
  if (!requireDb(res)) return;

  try {
    const token = adminBearerToken(req);
    const admin = await getAdminFromToken(token);

    if (!admin) {
      return res.status(401).json({
        ok: false,
        message: 'Admin Token tidak valid atau sudah berakhir.'
      });
    }

    req.adminSession = admin;
    req.adminToken = token;

    next();
  } catch (error) {
    console.error('[ADMIN AUTH] TOKEN ERROR:', error.message);

    res.status(500).json({
      ok: false,
      message: 'Gagal memvalidasi Admin Token.'
    });
  }
}

async function requireAdminAny(req, res, next) {
  if (adminBearerToken(req)) {
    return requireAdminToken(req, res, next);
  }

  if (ADMIN_PASSWORD && isAdminRequest(req)) {
    req.adminSession = {
      admin_name: ADMIN_NAME,
      legacy: true
    };

    return next();
  }

  return res.status(401).json({
    ok: false,
    message: 'Admin tidak terautentikasi.'
  });
}

function requireAdmin(req, res, next) {
  if (!isAdminRequest(req)) {
    return res.status(401).json({
      ok: false,
      message: 'Admin tidak terautentikasi.'
    });
  }

  next();
}

async function auditAdmin(adminSession, action, target = '', detail = '') {
  if (!db) return;

  const name =
    adminSession?.admin_name ||
    adminSession?.username ||
    ADMIN_NAME;

  try {
    await db.query(
      `INSERT INTO audit_logs(admin_name, action, target, detail)
       VALUES($1, $2, $3, $4)`,
      [name, action, target, detail]
    );
  } catch (error) {
    console.error('[AUDIT] ERROR:', error.message);
  }
}

function publicUser(row) {
  return {
    id: row.id,
    nama: row.username,
    role: row.role || 'user',
    status: row.active ? 'aktif' : 'nonaktif',
    banned: !!row.banned,
    muted: !!row.muted,
    dibuatOleh: row.created_by || 'system',
    tanggalDibuat: row.created_at
      ? new Date(row.created_at).toLocaleDateString('id-ID')
      : '-'
  };
}

/*
 * ============================================================
 * DATABASE INITIALIZATION
 * ============================================================
 */

async function initializeDatabase() {
  if (!db) return;

  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS users (
        id BIGSERIAL PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        password_hash TEXT,
        role VARCHAR(30) DEFAULT 'user',
        active BOOLEAN DEFAULT TRUE,
        muted BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await db.query(`
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS banned BOOLEAN DEFAULT FALSE
    `);

    await db.query(`
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS created_by VARCHAR(100) DEFAULT 'system'
    `);

    await db.query(`
      CREATE TABLE IF NOT EXISTS online_sessions (
        socket_id VARCHAR(255) PRIMARY KEY,
        username VARCHAR(100) NOT NULL,
        group_name VARCHAR(100),
        channel_name VARCHAR(100),
        peer_id VARCHAR(255),
        mic_status BOOLEAN DEFAULT FALSE,
        floor_status VARCHAR(30) DEFAULT 'idle',
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await db.query(`
      CREATE TABLE IF NOT EXISTS chat_messages (
        id BIGSERIAL PRIMARY KEY,
        username VARCHAR(100) NOT NULL,
        group_name VARCHAR(100),
        channel_name VARCHAR(100),
        message TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await db.query(`
      CREATE TABLE IF NOT EXISTS auth_sessions (
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash CHAR(64) UNIQUE NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        last_used_at TIMESTAMPTZ DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL,
        revoked_at TIMESTAMPTZ
      )
    `);

    await db.query(`
      CREATE INDEX IF NOT EXISTS idx_auth_sessions_token_hash
      ON auth_sessions(token_hash)
    `);

    await db.query(`
      CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_id
      ON auth_sessions(user_id)
    `);

    await db.query(`
      CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires_at
      ON auth_sessions(expires_at)
    `);

    await db.query(`
      CREATE TABLE IF NOT EXISTS admin_sessions (
        id BIGSERIAL PRIMARY KEY,
        admin_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash CHAR(64) UNIQUE NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        last_used_at TIMESTAMPTZ DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL,
        revoked_at TIMESTAMPTZ
      )
    `);

    await db.query(`
      CREATE INDEX IF NOT EXISTS idx_admin_sessions_token_hash
      ON admin_sessions(token_hash)
    `);

    await db.query(`
      CREATE INDEX IF NOT EXISTS idx_admin_sessions_admin_user_id
      ON admin_sessions(admin_user_id)
    `);

    await db.query(`
      DELETE FROM admin_sessions
      WHERE expires_at <= NOW()
         OR revoked_at IS NOT NULL
    `);

    await db.query(`
      DELETE FROM auth_sessions
      WHERE expires_at <= NOW()
         OR revoked_at IS NOT NULL
    `);

    await db.query(`
      CREATE TABLE IF NOT EXISTS app_config (
        config_key VARCHAR(100) PRIMARY KEY,
        config_value JSONB NOT NULL,
        updated_by VARCHAR(100) DEFAULT 'system',
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await db.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id BIGSERIAL PRIMARY KEY,
        admin_name VARCHAR(100) NOT NULL,
        action VARCHAR(100) NOT NULL,
        target TEXT,
        detail TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    const defaultGroups = [
      {
        nama: 'Grup 1',
        prefix: '',
        status: 'aktif',
        channel: [
          {
            nama: 'CH 01',
            prefix: '',
            maxUsers: 0,
            pttTimeout: 0,
            status: 'aktif',
            locked: false,
            muted: false
          },
          {
            nama: 'CH 02',
            prefix: '',
            maxUsers: 5,
            pttTimeout: 30,
            status: 'aktif',
            locked: false,
            muted: false
          },
          {
            nama: 'CH 03',
            prefix: '',
            maxUsers: 0,
            pttTimeout: 0,
            status: 'aktif',
            locked: false,
            muted: false
          }
        ]
      },
      {
        nama: 'Grup 2',
        prefix: '',
        status: 'aktif',
        channel: [
          {
            nama: 'CH 01',
            prefix: '',
            maxUsers: 0,
            pttTimeout: 0,
            status: 'aktif',
            locked: false,
            muted: false
          },
          {
            nama: 'CH 02',
            prefix: '',
            maxUsers: 3,
            pttTimeout: 15,
            status: 'aktif',
            locked: false,
            muted: false
          }
        ]
      }
    ];

    await db.query(
      `INSERT INTO app_config(config_key, config_value, updated_by)
       VALUES($1, $2::jsonb, $3)
       ON CONFLICT(config_key) DO NOTHING`,
      ['groups', JSON.stringify(defaultGroups), 'system']
    );

    if (ADMIN_PASSWORD) {
      const adminHash = await hashPassword(ADMIN_PASSWORD);

      await db.query(
        `INSERT INTO users(
           username,
           password_hash,
           role,
           active,
           banned,
           muted,
           created_by
         )
         VALUES($1, $2, 'admin', TRUE, FALSE, FALSE, 'system')
         ON CONFLICT(username)
         DO UPDATE SET
           password_hash = EXCLUDED.password_hash,
           role = 'admin',
           active = TRUE,
           banned = FALSE`,
        [ADMIN_NAME, adminHash]
      );

      console.log('[DB] Admin account synchronized.');
    } else {
      console.warn(
        '[SECURITY] ADMIN_PASSWORD kosong; admin account seed/update dilewati.'
      );
    }

    console.log('[DB] Database tables READY.');
  } catch (error) {
    console.error('[DB] Database initialization ERROR:', error.message);
  }
}

/*
 * ============================================================
 * USER / AUTH API
 * ============================================================
 */

app.post('/api/auth/register', async (req, res) => {
  if (!requireDb(res)) return;

  try {
    const nama = String(req.body?.nama || '').trim();
    const sandi = String(req.body?.sandi || '');

    if (nama.length < 2 || sandi.length < 4) {
      return res.status(400).json({
        ok: false,
        message: 'Nama minimal 2 karakter dan password minimal 4 karakter.'
      });
    }

    if (nama.toLowerCase() === ADMIN_NAME.toLowerCase()) {
      return res.status(400).json({
        ok: false,
        message: 'Nama ini tidak boleh digunakan.'
      });
    }

    const hash = await hashPassword(sandi);

    const result = await db.query(
      `INSERT INTO users(
         username,
         password_hash,
         role,
         active,
         banned,
         muted,
         created_by
       )
       VALUES($1, $2, 'user', TRUE, FALSE, FALSE, $1)
       RETURNING *`,
      [nama, hash]
    );

    console.log('[USER] REGISTER:', nama);

    res.json({
      ok: true,
      user: publicUser(result.rows[0])
    });
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({
        ok: false,
        message: 'Nama sudah terdaftar.'
      });
    }

    console.error('[USER] REGISTER ERROR:', error.message);

    res.status(500).json({
      ok: false,
      message: 'Gagal mendaftar user.'
    });
  }
});

app.post('/api/auth/login', async (req, res) => {
  if (!requireDb(res)) return;

  try {
    const nama = String(req.body?.nama || '').trim();
    const sandi = String(req.body?.sandi || '');

    const result = await db.query(
      `SELECT *
       FROM users
       WHERE lower(username) = lower($1)
       LIMIT 1`,
      [nama]
    );

    const user = result.rows[0];

    if (!user || !(await verifyPassword(sandi, user.password_hash))) {
      return res.status(401).json({
        ok: false,
        message: 'Nama atau Kata Sandi salah!'
      });
    }

    if (user.banned) {
      return res.status(403).json({
        ok: false,
        message: 'Akun Anda telah di-banned! Hubungi admin.'
      });
    }

    if (!user.active) {
      return res.status(403).json({
        ok: false,
        message: 'Akun Anda dinonaktifkan! Hubungi admin.'
      });
    }

    const token = createUserToken();
    const expiresAt = userTokenExpiry();

    await db.query(
      `INSERT INTO auth_sessions(user_id, token_hash, expires_at)
       VALUES($1, $2, $3)`,
      [user.id, hashUserToken(token), expiresAt]
    );

    console.log('[USER] LOGIN:', user.username);

    res.json({
      ok: true,
      user: publicUser(user),
      token,
      expiresAt: expiresAt.toISOString()
    });
  } catch (error) {
    console.error('[USER] LOGIN ERROR:', error.message);

    res.status(500).json({
      ok: false,
      message: 'Login gagal.'
    });
  }
});

app.get('/api/auth/me', requireUser, (req, res) => {
  res.json({
    ok: true,
    user: publicUser(req.user),
    expiresAt: new Date(req.user.session_expires_at).toISOString()
  });
});

app.post('/api/auth/logout', requireUser, async (req, res) => {
  try {
    await db.query(
      `UPDATE auth_sessions
       SET revoked_at = NOW()
       WHERE token_hash = $1
         AND revoked_at IS NULL`,
      [hashUserToken(req.userToken)]
    );

    res.json({ ok: true });
  } catch (error) {
    console.error('[USER] LOGOUT ERROR:', error.message);

    res.status(500).json({
      ok: false,
      message: 'Logout gagal.'
    });
  }
});

/*
 * ============================================================
 * ADMIN AUTH API
 * ============================================================
 */

app.post('/api/admin/login', async (req, res) => {
  if (!requireDb(res)) return;

  try {
    const nama = String(req.body?.nama || '').trim();
    const sandi = String(req.body?.sandi || '');

    const result = await db.query(
      `SELECT password_hash
       FROM users
       WHERE lower(username) = lower($1)
         AND role = 'admin'
       LIMIT 1`,
      [nama]
    );

    const passwordHash = result.rows[0]?.password_hash;

    if (
      nama !== ADMIN_NAME ||
      !(await verifyPassword(sandi, passwordHash))
    ) {
      return res.status(401).json({
        ok: false,
        message: 'Nama atau Kata Sandi Admin salah.'
      });
    }

    const userResult = await db.query(
      `SELECT id, username, role, active, banned
       FROM users
       WHERE lower(username) = lower($1)
         AND role = 'admin'
       LIMIT 1`,
      [nama]
    );

    const user = userResult.rows[0];

    if (!user || !user.active || user.banned) {
      return res.status(403).json({
        ok: false,
        message: 'Akun Admin tidak diizinkan.'
      });
    }

    const token = createAdminToken();
    const expiresAt = adminTokenExpiry();

    await db.query(
      `INSERT INTO admin_sessions(admin_user_id, token_hash, expires_at)
       VALUES($1, $2, $3)`,
      [user.id, hashAdminToken(token), expiresAt]
    );

    await auditAdmin(
      { admin_name: user.username },
      'ADMIN_LOGIN',
      user.username,
      'Admin token issued'
    );

    res.json({
      ok: true,
      admin: {
        id: user.id,
        nama: user.username,
        role: 'admin'
      },
      token,
      expiresAt: expiresAt.toISOString()
    });
  } catch (error) {
    console.error('[ADMIN] LOGIN ERROR:', error.message);

    res.status(500).json({
      ok: false,
      message: 'Login Admin gagal.'
    });
  }
});

app.get('/api/admin/me', requireAdminToken, async (req, res) => {
  res.json({
    ok: true,
    admin: {
      nama: req.adminSession.username,
      role: 'admin'
    },
    expiresAt: new Date(req.adminSession.expires_at).toISOString()
  });
});

app.post('/api/admin/logout', requireAdminToken, async (req, res) => {
  try {
    await db.query(
      `UPDATE admin_sessions
       SET revoked_at = NOW()
       WHERE token_hash = $1
         AND revoked_at IS NULL`,
      [hashAdminToken(req.adminToken)]
    );

    await auditAdmin(
      req.adminSession,
      'ADMIN_LOGOUT',
      req.adminSession.username,
      'Admin token revoked'
    );

    res.json({ ok: true });
  } catch (error) {
    console.error('[ADMIN] LOGOUT ERROR:', error.message);

    res.status(500).json({
      ok: false,
      message: 'Logout Admin gagal.'
    });
  }
});

/*
 * ============================================================
 * USER MANAGEMENT
 * ============================================================
 */

app.get('/api/users', requireAdminAny, async (req, res) => {
  if (!requireDb(res)) return;

  try {
    const result = await db.query(
      `SELECT *
       FROM users
       ORDER BY id ASC`
    );

    res.json({
      ok: true,
      users: result.rows.map(publicUser)
    });
  } catch (error) {
    res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.post('/api/users', requireAdminAny, async (req, res) => {
  if (!requireDb(res)) return;

  try {
    const nama = String(req.body?.nama || '').trim();
    const sandi = String(req.body?.sandi || '');

    if (nama.length < 2 || sandi.length < 4) {
      return res.status(400).json({
        ok: false,
        message: 'Nama/password tidak valid.'
      });
    }

    if (nama.toLowerCase() === ADMIN_NAME.toLowerCase()) {
      return res.status(400).json({
        ok: false,
        message: 'Nama admin tidak boleh dibuat sebagai user.'
      });
    }

    const hash = await hashPassword(sandi);

    const result = await db.query(
      `INSERT INTO users(
         username,
         password_hash,
         role,
         active,
         banned,
         muted,
         created_by
       )
       VALUES($1, $2, 'user', TRUE, FALSE, FALSE, $3)
       RETURNING *`,
      [
        nama,
        hash,
        req.adminSession?.admin_name ||
          req.adminSession?.username ||
          ADMIN_NAME
      ]
    );

    console.log('[USER] ADMIN CREATE:', nama);

    await auditAdmin(
      req.adminSession,
      'USER_CREATE',
      nama,
      'User created by admin'
    );

    res.json({
      ok: true,
      user: publicUser(result.rows[0])
    });
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({
        ok: false,
        message: 'Nama sudah terdaftar.'
      });
    }

    res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.patch('/api/users/:id', requireAdminAny, async (req, res) => {
  if (!requireDb(res)) return;

  try {
    const active = req.body?.status === 'aktif';
    const banned = !!req.body?.banned;
    const muted = !!req.body?.muted;

    const result = await db.query(
      `UPDATE users
       SET
         active = $1,
         banned = $2,
         muted = $3,
         updated_at = NOW()
       WHERE id = $4
         AND role <> 'admin'
       RETURNING *`,
      [active, banned, muted, req.params.id]
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        ok: false,
        message: 'User tidak ditemukan/tidak dapat diubah.'
      });
    }

    console.log('[USER] UPDATE:', result.rows[0].username);

    await auditAdmin(
      req.adminSession,
      'USER_UPDATE',
      result.rows[0].username,
      JSON.stringify({
        status: req.body?.status,
        banned: req.body?.banned,
        muted: req.body?.muted
      })
    );

    res.json({
      ok: true,
      user: publicUser(result.rows[0])
    });
  } catch (error) {
    res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.patch('/api/users/:id/password', requireAdminAny, async (req, res) => {
  if (!requireDb(res)) return;

  try {
    const sandi = String(req.body?.sandi || '');

    if (sandi.length < 4) {
      return res.status(400).json({
        ok: false,
        message: 'Password minimal 4 karakter.'
      });
    }

    const hash = await hashPassword(sandi);

    const result = await db.query(
      `UPDATE users
       SET
         password_hash = $1,
         updated_at = NOW()
       WHERE id = $2
         AND role <> 'admin'
       RETURNING username`,
      [hash, req.params.id]
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        ok: false,
        message: 'User tidak ditemukan.'
      });
    }

    console.log(
      '[USER] RESET PASSWORD:',
      result.rows[0].username
    );

    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.delete('/api/users/:id', requireAdminAny, async (req, res) => {
  if (!requireDb(res)) return;

  try {
    const result = await db.query(
      `DELETE FROM users
       WHERE id = $1
         AND role <> 'admin'
       RETURNING username`,
      [req.params.id]
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        ok: false,
        message: 'User tidak ditemukan.'
      });
    }

    console.log(
      '[USER] DELETE:',
      result.rows[0].username
    );

    await auditAdmin(
      req.adminSession,
      'USER_DELETE',
      result.rows[0].username,
      'User deleted'
    );

    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

/*
 * ============================================================
 * REALTIME STATE
 * ============================================================
 */

const sessions = new Map();
const rooms = new Map();
const kicked = new Map();

function publicSessions() {
  const output = {};

  for (const session of sessions.values()) {
    output[session.nama] = {
      nama: session.nama,
      group: session.group,
      channel: session.channel,
      micStatus: !!session.micStatus,
      floorStatus: session.floorStatus || 'idle',
      peerId: session.peerId || null,
      timestamp: session.timestamp
    };
  }

  return output;
}

function roomUsers(room) {
  return [...(rooms.get(room) || new Set())]
    .map(id => sessions.get(id))
    .filter(Boolean)
    .map(session => ({
      nama: session.nama,
      group: session.group,
      channel: session.channel,
      peerId: session.peerId,
      micStatus: !!session.micStatus,
      floorStatus: session.floorStatus || 'idle'
    }));
}

async function savePresence(session) {
  if (!db || !session) return;

  try {
    await db.query(
      `INSERT INTO online_sessions(
         socket_id,
         username,
         group_name,
         channel_name,
         peer_id,
         mic_status,
         floor_status,
         updated_at
       )
       VALUES($1, $2, $3, $4, $5, $6, $7, NOW())
       ON CONFLICT(socket_id)
       DO UPDATE SET
         username = EXCLUDED.username,
         group_name = EXCLUDED.group_name,
         channel_name = EXCLUDED.channel_name,
         peer_id = EXCLUDED.peer_id,
         mic_status = EXCLUDED.mic_status,
         floor_status = EXCLUDED.floor_status,
         updated_at = NOW()`,
      [
        session.socketId,
        session.nama,
        session.group,
        session.channel,
        session.peerId,
        !!session.micStatus,
        session.floorStatus || 'idle'
      ]
    );
  } catch (error) {
    console.error('[DB] savePresence:', error.message);
  }
}

async function removePresence(socketId) {
  if (!db) return;

  try {
    await db.query(
      `DELETE FROM online_sessions
       WHERE socket_id = $1`,
      [socketId]
    );
  } catch (error) {
    console.error('[DB] removePresence:', error.message);
  }
}

function emitPresence() {
  io.emit('presence:update', publicSessions());
}

app.get('/api/presence', (req, res) => {
  res.json({
    ok: true,
    sessions: publicSessions()
  });
});

/*
 * ============================================================
 * GROUP / CHANNEL CONFIG
 * ============================================================
 */

app.get('/api/config/groups', async (req, res) => {
  if (!requireDb(res)) return;

  try {
    const result = await db.query(
      `SELECT config_value, updated_by, updated_at
       FROM app_config
       WHERE config_key = $1
       LIMIT 1`,
      ['groups']
    );

    const row = result.rows[0];

    const groups = row?.config_value || [];
    const updatedBy = row?.updated_by || 'system';
    const updatedAt = row?.updated_at || null;

    io.emit('config:groups:update', {
      groups,
      updatedBy,
      updatedAt
    });

    res.json({
      ok: true,
      groups,
      updatedBy,
      updatedAt
    });
  } catch (error) {
    console.error(
      '[CONFIG] GET GROUPS:',
      error.message
    );

    res.status(500).json({
      ok: false,
      message: 'Gagal membaca konfigurasi Group/Channel.'
    });
  }
});

app.put('/api/config/groups', requireAdminAny, async (req, res) => {
  if (!requireDb(res)) return;

  try {
    if (!Array.isArray(req.body?.groups)) {
      return res.status(400).json({
        ok: false,
        message: 'Format groups tidak valid.'
      });
    }

    const groups = req.body.groups
      .map(group => ({
        nama: String(group?.nama || '').trim(),
        prefix: String(group?.prefix || ''),
        status:
          group?.status === 'nonaktif'
            ? 'nonaktif'
            : 'aktif',
        channel: Array.isArray(group?.channel)
          ? group.channel
              .map(channel => ({
                nama: String(channel?.nama || '').trim(),
                prefix: String(channel?.prefix || ''),
                maxUsers: Math.max(
                  0,
                  Number(channel?.maxUsers) || 0
                ),
                pttTimeout: Math.max(
                  0,
                  Number(channel?.pttTimeout) || 0
                ),
                status:
                  channel?.status === 'nonaktif'
                    ? 'nonaktif'
                    : 'aktif',
                locked: !!channel?.locked,
                muted: !!channel?.muted
              }))
              .filter(channel => channel.nama)
          : []
      }))
      .filter(group => group.nama);

    const updatedBy =
      req.adminSession?.admin_name ||
      req.adminSession?.username ||
      ADMIN_NAME;

    const result = await db.query(
      `INSERT INTO app_config(
         config_key,
         config_value,
         updated_by,
         updated_at
       )
       VALUES($1, $2::jsonb, $3, NOW())
       ON CONFLICT(config_key)
       DO UPDATE SET
         config_value = EXCLUDED.config_value,
         updated_by = EXCLUDED.updated_by,
         updated_at = NOW()
       RETURNING config_value, updated_by, updated_at`,
      ['groups', JSON.stringify(groups), updatedBy]
    );

    console.log(
      '[CONFIG] GROUPS SAVED:',
      groups.length
    );

    io.emit('config:groups:update', {
      groups: result.rows[0].config_value,
      updatedBy: result.rows[0].updated_by,
      updatedAt: result.rows[0].updated_at
    });

    await auditAdmin(
      req.adminSession,
      'GROUP_CONFIG_UPDATE',
      'groups',
      `Saved ${groups.length} groups`
    );

    res.json({
      ok: true,
      groups: result.rows[0].config_value,
      updatedBy: result.rows[0].updated_by,
      updatedAt: result.rows[0].updated_at
    });
  } catch (error) {
    console.error(
      '[CONFIG] PUT GROUPS:',
      error.message
    );

    res.status(500).json({
      ok: false,
      message: 'Gagal menyimpan konfigurasi Group/Channel.'
    });
  }
});

/*
 * ============================================================
 * CLOUDFLARE TURN
 * ============================================================
 */

app.get('/api/turn-credentials', async (req, res) => {
  const keyId = process.env.CLOUDFLARE_TURN_KEY_ID;
  const apiToken = process.env.CLOUDFLARE_TURN_API_TOKEN;

  if (!keyId || !apiToken) {
    console.error(
      '[TURN] Cloudflare TURN variables belum lengkap.'
    );

    return res.status(503).json({
      ok: false,
      message:
        'Cloudflare TURN belum dikonfigurasi di server.'
    });
  }

  try {
    const response = await fetch(
      `https://rtc.live.cloudflare.com/v1/turn/keys/${encodeURIComponent(
        keyId
      )}/credentials/generate-ice-servers`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          ttl: 86400
        })
      }
    );

    const data = await response
      .json()
      .catch(() => null);

    if (!response.ok) {
      console.error(
        '[TURN] Cloudflare request gagal:',
        response.status,
        data
      );

      return res.status(502).json({
        ok: false,
        message:
          'Gagal memperoleh TURN credentials dari Cloudflare.',
        status: response.status
      });
    }

    let iceServers = [];

    if (Array.isArray(data?.iceServers)) {
      iceServers = data.iceServers;
    } else if (data && (data.urls || data.url)) {
      iceServers = [data];
    }

    if (!iceServers.length) {
      console.error(
        '[TURN] Respons Cloudflare tidak berisi ICE servers.'
      );

      return res.status(502).json({
        ok: false,
        message:
          'Respons TURN Cloudflare tidak valid.'
      });
    }

    console.log(
      '[TURN] Temporary ICE credentials generated.'
    );

    res.json({
      ok: true,
      ttl: 86400,
      iceServers
    });
  } catch (error) {
    console.error(
      '[TURN] ERROR:',
      error.message
    );

    res.status(502).json({
      ok: false,
      message:
        'Tidak dapat menghubungi Cloudflare TURN.'
    });
  }
});

app.get('/api/db-test', async (req, res) => {
  if (!requireDb(res)) return;

  try {
    const result = await db.query(
      `SELECT
         NOW() AS server_time,
         current_database() AS database_name`
    );

    res.json({
      ok: true,
      database: 'connected',
      result: result.rows[0]
    });
  } catch (error) {
    res.status(500).json({
      ok: false,
      error: error.message
    });
  }
});

/*
 * ============================================================
 * SOCKET.IO
 * ============================================================
 */

const io = new Server(server, {
  cors: {
    origin(origin, callback) {
      if (corsOriginAllowed(origin)) {
        return callback(null, true);
      }

      console.warn(
        `[SOCKET CORS] Origin ditolak: ${origin}`
      );

      return callback(null, false);
    },
    methods: [
      'GET',
      'HEAD',
      'POST',
      'PUT',
      'PATCH',
      'DELETE',
      'OPTIONS'
    ],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Admin-Name',
      'X-Admin-Password'
    ],
    credentials: true
  },
  transports: ['websocket', 'polling']
});

io.use(async (socket, next) => {
  try {
    const adminToken = String(
      socket.handshake?.auth?.adminToken || ''
    ).trim();

    socket.data.admin = null;

    if (adminToken) {
      if (!db) {
        return next(
          new Error(
            'Database belum tersedia untuk Admin Token.'
          )
        );
      }

      const admin = await getAdminFromToken(adminToken);

      if (!admin) {
        return next(
          new Error(
            'Admin Token tidak valid atau sudah berakhir.'
          )
        );
      }

      socket.data.admin = admin;
    }

    next();
  } catch (error) {
    console.error(
      '[SOCKET ADMIN AUTH ERROR]',
      error.message
    );

    next(
      new Error(
        'Gagal memvalidasi Admin Token.'
      )
    );
  }
});

io.use(async (socket, next) => {
  try {
    const token = String(
      socket.handshake?.auth?.token || ''
    ).trim();

    socket.data.userToken = token;
    socket.data.user = null;

    /*
     * Backward compatibility:
     * old clients may connect without a user token.
     */
    if (!token) {
      return next();
    }

    if (!db) {
      return next(
        new Error(
          'Database belum tersedia untuk autentikasi.'
        )
      );
    }

    const user = await getUserFromToken(token);

    if (!user) {
      return next(
        new Error(
          'Token tidak valid atau sudah kedaluwarsa.'
        )
      );
    }

    socket.data.user = user;
    next();
  } catch (error) {
    console.error(
      '[SOCKET AUTH ERROR]',
      error.message
    );

    next(
      new Error(
        'Gagal memvalidasi token.'
      )
    );
  }
});

io.on('connection', socket => {
  const socketToken =
    socket.data.userToken || '';

  const socketUser =
    socket.data.user || null;

  if (socketUser) {
    socket.emit('auth:ready', {
      ok: true,
      user: publicUser(socketUser)
    });
  }

  console.log(
    '[SOCKET] Connected:',
    socket.id
  );

  socket.emit('server:ready', {
    version: VERSION,
    transport: socket.conn.transport.name
  });

  socket.on('room:join', async payload => {
    try {
      const namaPayload =
        String(payload?.nama || '').trim();

      const group =
        String(payload?.group || '').trim();

      const channel =
        String(payload?.channel || '').trim();

      const peerId =
        String(payload?.peerId || '').trim();

      const maxUsers =
        Number(payload?.maxUsers || 0);

      if (
        !namaPayload ||
        !group ||
        !channel ||
        !peerId
      ) {
        return socket.emit(
          'room:error',
          {
            message:
              'Data room tidak lengkap.'
          }
        );
      }

      if (
        socketToken &&
        !socketUser
      ) {
        return socket.emit(
          'room:error',
          {
            message:
              'Autentikasi user gagal. Silakan login kembali.'
          }
        );
      }

      const nama = socketUser
        ? socketUser.username
        : namaPayload;

      if (db) {
        const userResult =
          await db.query(
            `SELECT active, banned
             FROM users
             WHERE lower(username) = lower($1)
             LIMIT 1`,
            [nama]
          );

        if (!userResult.rows[0]) {
          return socket.emit(
            'room:error',
            {
              message:
                'User tidak terdaftar di database.'
            }
          );
        }

        if (
          userResult.rows[0].banned ||
          !userResult.rows[0].active
        ) {
          return socket.emit(
            'room:error',
            {
              message:
                'Akun tidak diizinkan masuk.'
            }
          );
        }
      }

      const blockedUntil =
        kicked.get(nama);

      if (
        blockedUntil &&
        blockedUntil > Date.now()
      ) {
        return socket.emit(
          'room:error',
          {
            message:
              'Anda sedang di-kick oleh admin.'
          }
        );
      }

      const room =
        `${group}::${channel}`;

      const existing = [
        ...(rooms.get(room) || new Set())
      ]
        .map(id => sessions.get(id))
        .filter(Boolean)
        .filter(session =>
          session.nama !== nama
        );

      if (
        maxUsers > 0 &&
        existing.length >= maxUsers
      ) {
        return socket.emit(
          'room:error',
          {
            message:
              `Channel penuh! Maksimal ${maxUsers} user.`
          }
        );
      }

      const old =
        sessions.get(socket.id);

      if (old?.room) {
        rooms
          .get(old.room)
          ?.delete(socket.id);

        socket.leave(old.room);
      }

      const session = {
        socketId: socket.id,
        nama,
        group,
        channel,
        room,
        peerId,
        micStatus: false,
        floorStatus: 'idle',
        timestamp: Date.now()
      };

      sessions.set(
        socket.id,
        session
      );

      if (!rooms.has(room)) {
        rooms.set(
          room,
          new Set()
        );
      }

      rooms
        .get(room)
        .add(socket.id);

      socket.join(room);

      await savePresence(session);

      socket.emit(
        'room:joined',
        {
          room,
          users: roomUsers(room),
          self: session
        }
      );

      io.to(room).emit(
        'room:users',
        roomUsers(room)
      );

      emitPresence();

      console.log(
        '[ROOM JOIN]',
        nama,
        '=>',
        room
      );
    } catch (error) {
      console.error(
        '[ROOM JOIN ERROR]',
        error
      );

      socket.emit(
        'room:error',
        {
          message:
            error.message ||
            'Gagal bergabung room.'
        }
      );
    }
  });

  socket.on(
    'presence:update',
    async patch => {
      const session =
        sessions.get(socket.id);

      if (!session) return;

      if (
        typeof patch?.micStatus ===
        'boolean'
      ) {
        session.micStatus =
          patch.micStatus;
      }

      if (
        typeof patch?.floorStatus ===
        'string'
      ) {
        session.floorStatus =
          patch.floorStatus;
      }

      session.timestamp =
        Date.now();

      await savePresence(
        session
      );

      io.to(session.room).emit(
        'room:users',
        roomUsers(session.room)
      );

      emitPresence();
    }
  );

  socket.on(
    'floor:event',
    event => {
      const session =
        sessions.get(socket.id);

      if (!session?.room) return;

      socket
        .to(session.room)
        .emit(
          'floor:event',
          {
            ...event,
            from: session.nama
          }
        );
    }
  );

  socket.on(
    'chat:send',
    async (payload, ack) => {
      try {
        const session =
          sessions.get(socket.id);

        if (!session?.room) {
          ack?.({
            ok: false,
            message:
              'Belum masuk channel.'
          });

          return;
        }

        const message = String(
          payload?.message || ''
        )
          .trim()
          .slice(0, 2000);

        if (!message) {
          ack?.({
            ok: false,
            message:
              'Pesan kosong.'
          });

          return;
        }

        if (db) {
          const userResult =
            await db.query(
              `SELECT muted, active, banned
               FROM users
               WHERE lower(username) = lower($1)
               LIMIT 1`,
              [session.nama]
            );

          const user =
            userResult.rows[0];

          if (
            user?.muted ||
            !user?.active ||
            user?.banned
          ) {
            ack?.({
              ok: false,
              message:
                'Akun tidak diizinkan mengirim pesan.'
            });

            return;
          }

          await db.query(
            `INSERT INTO chat_messages(
               username,
               group_name,
               channel_name,
               message
             )
             VALUES($1, $2, $3, $4)`,
            [
              session.nama,
              session.group,
              session.channel,
              message
            ]
          );
        }

        io.to(session.room).emit(
          'chat:message',
          {
            nama: session.nama,
            message
          }
        );

        ack?.({ ok: true });
      } catch (error) {
        console.error(
          '[CHAT ERROR]',
          error.message
        );

        socket.emit(
          'chat:error',
          {
            message:
              'Pesan gagal dikirim.'
          }
        );

        ack?.({
          ok: false,
          message:
            'Pesan gagal dikirim.'
        });
      }
    }
  );

  socket.on(
    'admin:kick',
    async ({ nama } = {}, ack) => {
      if (!nama) {
        return ack?.({
          ok: false,
          message:
            'Target user wajib diisi.'
        });
      }

      const adminToken =
        String(
          socket.handshake?.auth
            ?.adminToken || ''
        ).trim();

      let admin =
        socket.data.admin || null;

      if (
        !admin &&
        adminToken &&
        db
      ) {
        admin =
          await getAdminFromToken(
            adminToken
          );
      }

      const legacyAllowed =
        String(
          process.env
            .LEGACY_ADMIN_SOCKET_KICK ||
            'false'
        ).toLowerCase() ===
        'true';

      if (
        !admin &&
        !legacyAllowed
      ) {
        return ack?.({
          ok: false,
          message:
            'Admin Socket Token diperlukan.'
        });
      }

      if (
        !admin &&
        legacyAllowed
      ) {
        console.warn(
          '[SECURITY] Legacy admin:kick accepted; migrate Web V2 to Admin Token.'
        );
      }

      kicked.set(
        nama,
        Date.now() + 300000
      );

      for (
        const session
        of sessions.values()
      ) {
        if (
          session.nama === nama
        ) {
          io
            .to(session.socketId)
            .emit(
              'admin:kick',
              {
                nama,
                expiresAt:
                  kicked.get(nama)
              }
            );

          io.sockets.sockets
            .get(session.socketId)
            ?.disconnect(true);
        }
      }

      if (db) {
        await auditAdmin(
          admin || {
            admin_name:
              ADMIN_NAME
          },
          'USER_KICK',
          nama,
          'Socket kick'
        );
      }

      ack?.({ ok: true });
    }
  );

  socket.on(
    'disconnect',
    async reason => {
      const session =
        sessions.get(socket.id);

      console.log(
        '[SOCKET] Disconnect:',
        socket.id,
        reason
      );

      if (!session) return;

      rooms
        .get(session.room)
        ?.delete(socket.id);

      if (
        rooms.get(session.room)
          ?.size === 0
      ) {
        rooms.delete(
          session.room
        );
      }

      sessions.delete(
        socket.id
      );

      await removePresence(
        socket.id
      );

      if (session.room) {
        io.to(session.room).emit(
          'room:users',
          roomUsers(session.room)
        );
      }

      emitPresence();
    }
  );
});

/*
 * ============================================================
 * STALE SESSION CLEANUP
 * ============================================================
 */

setInterval(async () => {
  const cutoff =
    Date.now() - 65000;

  for (
    const [id, session]
    of sessions
  ) {
    if (
      session.timestamp <
      cutoff
    ) {
      rooms
        .get(session.room)
        ?.delete(id);

      sessions.delete(id);

      await removePresence(id);
    }
  }

  emitPresence();
}, 15000);

/*
 * ============================================================
 * SERVER START
 * ============================================================
 */

async function startServer() {
  console.log(
    '========================================'
  );

  console.log(
    ' Komunikasi Group V2 Backend'
  );

  console.log(
    ` Version ${VERSION}`
  );

  console.log(
    '========================================'
  );

  console.log(
    '[SERVER] PORT:',
    PORT
  );

  console.log(
    '[SERVER] Allowed CORS origins:',
    ALLOWED_CORS_ORIGINS.join(', ')
  );

  if (!ADMIN_PASSWORD) {
    console.error(
      '[SECURITY] ADMIN_PASSWORD belum di-set di Railway Variables. Admin login dinonaktifkan sampai secret tersedia.'
    );
  }

  await testDatabase();
  await initializeDatabase();

  server.listen(
    PORT,
    '0.0.0.0',
    () => {
      console.log(
        `[SERVER] Listening on 0.0.0.0:${PORT}`
      );

      console.log(
        `[SERVER] PostgreSQL: ${
          db ? 'ENABLED' : 'DISABLED'
        }`
      );

      console.log(
        '[SERVER] Health: /health and /api/health'
      );
    }
  );
}

startServer().catch(error => {
  console.error(
    '[FATAL] Server failed to start:',
    error
  );

  process.exit(1);
});
