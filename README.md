# Komunikasi Group v2 – Realtime Fix

Paket ini memperbaiki masalah "Langkah 1/4: Menghubung ke server" dengan menambahkan server Socket.IO untuk room discovery/presence. PeerJS tetap dipakai untuk audio WebRTC.

## 1. Deploy backend

Masuk ke `server/` lalu:

```bash
npm install
npm start
```

Deploy folder `server/` ke Railway/Render/Fly.io/VM Node.js. Set:

- `PORT` (platform biasanya mengisi otomatis)
- `FRONTEND_ORIGINS=https://komunikasi-group.netlify.app`
- opsional `SUPABASE_URL`
- opsional `SUPABASE_SERVICE_ROLE_KEY`

Health check: `/health`.

## 2. Hubungkan frontend

Di `index.html`, set:

```js
const REALTIME_SERVER_URL = "https://YOUR-BACKEND.example.com";
```

Frontend sudah disiapkan agar Socket.IO melakukan:
- room join
- daftar user per channel
- heartbeat/presence
- kick event
- floor/PTT event
- sinkronisasi online user

## 3. Supabase

Jika ingin persistence, jalankan `supabase/schema.sql` pada SQL Editor Supabase dan isi env backend.

## 4. WebRTC

PeerJS Cloud masih dipakai sebagai signaling WebRTC. STUN Google dipertahankan. Untuk jaringan/NAT yang sulit, tambahkan TURN server pada konfigurasi `iceServers`.
