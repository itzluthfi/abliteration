# Abliteration V2 🛡️

Advanced Web Security Scanner & Assessment Toolkit.

## Features
- 🏃 **Fast Multi-Threaded Scanning**: Menjalankan pengecekan kerentanan secara paralel dengan thread terpisah.
- 🎯 **Deep Detection Logic**:
  - **SQLi**: Boolean-based and Time-delay heuristic testing.
  - **XSS**: Reflected & stored parameter checking.
  - **IDOR**: Parameter tamper check.
  - **CSRF**: Token presence verification.
  - **LFI / Path Traversal**: Directory traversal probe.
  - **Sensitive Files (Dorking)**: Deteksi file sensitif yang terekspos (`.env`, `.git/config`, `wp-config.php`, `backup.sql`).
  - **Security Headers**: Audit `X-Frame-Options`, `Content-Security-Policy`, dan `Strict-Transport-Security`.
- 📄 **Exportable Reports**: Hasil pemindaian disimpan otomatis di `OUTPUT/scan_result.txt`.

## Project Structure
```text
abliteration/
├── src/
│   ├── core.py          # Logika pendeteksi & modul request
│   └── scanner.py       # Threading & orchestration runner
├── OUTPUT/
│   └── scan_result.txt  # Hasil log pemindaian
├── requirements.txt
├── abliteration.py      # Entry point utama
├── README.md
└── .gitignore
```

## Installation & Usage
```bash
git clone https://github.com/itzluthfi/abliteration.git
cd abliteration
pip install -r requirements.txt
python abliteration.py
```

## Disclaimer
Tool ini dibuat semata-mata untuk tujuan edukasi, audit internal, penelitian keamanan siber, dan pengujian penetrasi terotorisasi (*authorized penetration testing*). Dilarang menguji target tanpa izin tertulis dari pemilik sistem.

## Author
- **itzluthfi**
