# komunikasi-grup-1

Aplikasi komunikasi grup berbasis web (suara WebRTC + teks + panel admin). Frontend PWA di Netlify, backend Node.js (Express + Socket.IO) di Railway/Render/VM.

- Frontend: `index.html` + `manifest.json` + `sw.js` (deploy root ke Netlify)
- Backend: `server.js` + `package.json` + `.env` (deploy ke Railway/Render/Fly.io/VM Node.js)
- Database: PostgreSQL opsional (register/login user, chat, audit, statistik)

## 1. Deploy backend

Di folder ini:

```bash
npm install
npm start
```

Environment variables yang dipakai:

| Variabel | Wajib? | Keterangan |
| --- | --- | --- |
| `PORT` | tidak | Port HTTP (platform biasanya mengisi otomatis) |
| `FRONTEND_ORIGINS` | ya | Asal frontend, mis. `https://komunikasi-group.netlify.app` (pisah koma jika lebih dari satu) |
| `ADMIN_NAME` | tidak | Nama admin (default `Didik Suntoro`) |
| `ADMIN_PASSWORD` | **ya** | Password admin. Jika tidak diisi, server membuat password acak dan mencetaknya ke log saat start. |
| `DATABASE_URL` | disarankan | PostgreSQL connection string. Tanpa ini register/login user, chat, dan audit dinonaktifkan. |
| `CLOUDFLARE_TURN_KEY_ID` | opsional | Key ID Cloudflare TURN (WebRTC tembus NAT ketat) |
| `CLOUDFLARE_TURN_API_TOKEN` | opsional | API Token Cloudflare TURN |

Contoh file `.env` (lihat `.env.example`):

```env
PORT=3000
FRONTEND_ORIGINS=https://komunikasi-group.netlify.app
ADMIN_NAME=Didik Suntoro
ADMIN_PASSWORD=GANTI_DENGAN_PASSWORD_KUAT
DATABASE_URL=postgres://user:password@host:5432/dbname
```

Health check: `GET /health`.

> Catatan: tabel PostgreSQL dibuat otomatis saat server start. `schema.sql` disediakan hanya untuk penyiapan manual, dan kolomnya sudah disesuaikan dengan kode server (mis. `audit_logs.admin_name`).

## 2. Hubungkan frontend

Di `index.html`, set:

```js
const REALTIME_SERVER_URL = "https://YOUR-BACKEND.example.com";
```

Frontend sudah disiapkan agar Socket.IO melakukan room join, daftar user per channel, presence/heartbeat, kick event, floor/PTT event, dan sinkronisasi online user.

## 3. WebRTC

PeerJS Cloud dipakai sebagai signaling WebRTC, dengan fallback STUN Google. Untuk jaringan/NAT yang sulit, backend menyediakan `GET /api/turn-credentials` yang mengambil kredensial TURN Cloudflare sementara; jika gagal, STUN publik tetap dipakai.

## 4. Keamanan

- Password di-hash dengan scrypt.
- Login admin dilindungi rate limit (5 percobaan / 10 menit) + session token ber-TTL.
- Login/register user dilindungi rate limit; user login mengeluarkan token yang wajib dikirim saat `room:join`.
- Event Socket.IO `admin:kick` hanya bisa dipanggil socket dengan token admin.
- Semua konten chat di-escape di frontend (anti XSS).
