# Abliteration 🛡️

Web Security Scanner sederhana berbasis Python untuk mendeteksi kerentanan refleksi dasar seperti SQL Injection (SQLi) dan Cross-Site Scripting (XSS).

## Fitur
- Deteksi refleksi error SQL (MySQL, PostgreSQL, MSSQL, SQLite)
- Deteksi refleksi tag XSS pada parameter URL
- Tampilan antarmuka terminal berwarna
- Logging hasil pemindaian otomatis ke `OUTPUT/log.txt`

## Prasyarat
- Python 3.8+
- Library `requests`

## Cara Pakai
1. Clone repositori:
   ```bash
   git clone https://github.com/itzluthfi/abliteration.git
   cd abliteration
   ```
2. Install dependensi:
   ```bash
   pip install -r requirements.txt
   ```
3. Jalankan scanner:
   ```bash
   python abliteration.py
   ```
4. Masukkan URL target yang ingin diuji (contoh: `http://testphp.vulnweb.com/listproducts.php`).

## Struktur Proyek
```text
abliteration/
├── abliteration.py      # Script scanner utama
├── requirements.txt     # Dependensi Python
├── README.md            # Dokumentasi proyek
├── .gitignore           # File pengabaian Git
└── OUTPUT/              # Log hasil scan
```

## Disclaimer
Alat ini dibuat semata-mata untuk tujuan edukasi, pengujian keamanan terotorisasi (*authorized penetration testing*), dan audit keamanan website milik sendiri. Penyalahgunaan terhadap sistem tanpa izin pemilik sah berada di luar tanggung jawab pengembang.

## Author
- **itzluthfi**
