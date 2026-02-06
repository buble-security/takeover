# Subdomain Takeover & Dangling DNS Detector
Script ini adalah alat otomatis untuk mendeteksi potensi subdomain takeover dan dangling DNS pada sebuah domain atau daftar subdomain.
1. Pemindaian DNS menyeluruh untuk CNAME, A, AAAA, dan NS record, termasuk deteksi NXDOMAIN, SERVFAIL, dan kondisi DNS
2. Deteksi layanan rentan berbasis fingerprint can-i-take-over-xyz
3. Manajemen resolver DNS canggih
4. Manajemen User‑Agent dinamis (download dari beberapa sumber, cache lokal, dan fallback), dengan rotasi User‑Agent di setiap permintaan HTTP
5. Pemrosesan paralel menggunakan ThreadPool untuk pemeriksaan DNS yang cepat pada banyak subdomain

Screenshot
<img width="1718" height="878" alt="Screenshot_2026-02-06_17_19_03" src="https://github.com/user-attachments/assets/9bf5d6c9-cd64-4e8c-9997-9e3a4a33e4de" />
