# Sini Ngumpul — Security Guard

Website komunitas seni berdasarkan `index-2.html`, sekarang memiliki backend dan Security Guard server-side.

## Fitur
- Landing page Sini Ngumpul
- Mading dan karya
- Pengiriman karya -> status pending
- Moderasi admin/moderator
- Login dengan password hash bcrypt
- Session cookie httpOnly + sameSite
- Helmet security headers
- Rate limit global, login, dan pengiriman karya
- Validasi input server-side
- Security log
- SQLite database lokal
- Escape output pada halaman karya/admin

## Menjalankan di komputer
1. Install Node.js 18+.
2. Buka folder project.
3. Jalankan `npm install`.
4. Salin `.env.example` menjadi `.env` dan ganti password/SESSION_SECRET.
5. Jalankan `npm start`.
6. Buka `http://localhost:3000`.

Akun admin dibuat otomatis dari `ADMIN_EMAIL` dan `ADMIN_PASSWORD`.

## Catatan produksi
- Gunakan HTTPS.
- Gunakan secret session yang panjang dan acak.
- Jangan gunakan password default.
- Untuk deployment serius, gunakan reverse proxy dan session store yang cocok.
- Backup database.
- Tambahkan verifikasi email/2FA bila diperlukan.
