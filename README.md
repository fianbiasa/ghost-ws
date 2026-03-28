# Ghost Web Scanner

Scanner keamanan web berbasis heuristic untuk recon dan audit awal keamanan aplikasi web.
**Fork dan Rebuild dari : https://github.com/Sneijderlino/Ghost-Web_Scanner**

## Ringkasan
Ghost Web Scanner (file utama: `gws.py`) membantu melakukan pemeriksaan awal terhadap target web, termasuk:
- Recon dasar target
- Audit header dan cookie security
- CORS check
- HTTP method exposure check
- TLS certificate check
- Well-known endpoint check
- Form audit (GET login, indikasi CSRF)
- Parameter indicator (SQLi/XSS berbasis heuristic)
- Output laporan JSON dan SARIF

Penting: hasil scanner adalah indikator awal, bukan bukti exploitability final.

## Rebranding
- Nama tool: Ghost Web Scanner
- File utama: `gws.py`
- Author: Zulfianto
- GitHub: https://github.com/fianbiasa/ghost-ws

## Fitur Saat Ini
- 3 mode scan:
  - `cepat`
  - `normal`
  - `agresif`
- Retry + exponential backoff + concurrency control
- Severity filter untuk export report
- Export report:
  - JSON
  - SARIF (untuk tooling security/devops)

## Requirement
### Minimum Sistem
- Python 3.10+
- Linux / Termux / environment POSIX direkomendasikan

### Python Dependencies
Lihat file `requirements.txt`:
- `requests`
- `beautifulsoup4`
- `urllib3`

## Instalasi
## 1) Clone Repository
```bash
git clone https://github.com/fianbiasa/ghost-ws.git
cd ghost-ws
```

## 2) Setup Virtual Environment (Direkomendasikan)
### Ubuntu / Debian / Kali
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
```

Jika muncul error `ensurepip is not available`, install paket venv versi Python kamu, contoh:
```bash
sudo apt install -y python3.10-venv
```

### Termux
```bash
pkg update -y && pkg upgrade -y
pkg install -y python git

python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
```

## 3) Jalankan Scanner
### Interaktif
```bash
python gws.py
```
Scanner akan meminta:
- Target URL
- Mode scan (`cepat/normal/agresif`)

### Non-Interaktif (CLI)
```bash
python gws.py --target https://example.com --mode normal --min-severity LOW
```

## Opsi CLI Lengkap
```bash
python gws.py \
  --target https://target.com \
  --mode normal \
  --min-severity MEDIUM \
  --insecure
```

Opsi:
- `--target`: URL target
- `--mode`: `cepat`, `normal`, `agresif`
- `--min-severity`: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- `--insecure`: nonaktifkan verifikasi TLS (hanya untuk testing/troubleshooting)

## Cara Install Ulang Cepat (Jika Environment Rusak)
```bash
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
```

## Output Laporan
Setiap scan menghasilkan file di folder `reports/`:
- `scan_<domain>_<timestamp>.json`
- `scan_<domain>_<timestamp>.sarif`

### Isi JSON (ringkas)
- Metadata target
- Konfigurasi scan
- Risk summary
- Findings (severity/confidence/evidence)
- Endpoint notes
- Request warnings

### Isi SARIF
Kompatibel untuk integrasi ke security tooling yang mendukung format SARIF 2.1.0.

## Metodologi Pengecekan
Scanner melakukan pemeriksaan terhadap:
- Target intelligence
- Security headers
- Cookie flags
- CORS policy
- Exposed HTTP methods
- TLS certificate/protocol/cipher
- Well-known endpoint exposure
- Form weakness indicators
- SQLi/XSS indicators via payload comparison

## Troubleshooting
## 1) `source .venv/bin/activate: No such file or directory`
Penyebab: venv gagal dibuat. Solusi:
```bash
sudo apt install -y python3-venv
python3 -m venv .venv
```

## 2) SSL verify gagal (`CERTIFICATE_VERIFY_FAILED`)
Opsi:
- Perbaiki CA bundle sistem
- Atau sementara gunakan `--insecure` untuk testing

## 3) PIP warning invalid distribution
Jika ada folder aneh seperti `~setuptools` di `.venv`, hapus folder tersebut lalu install ulang dependencies.

## 4) Scan terasa lambat
Gunakan mode `cepat`:
```bash
python gws.py --target https://target.com --mode cepat
```

## Disclaimer
Tool ini untuk audit keamanan yang sah dan berizin.
Jangan melakukan scanning tanpa izin tertulis dari pemilik sistem.

Author tidak bertanggung jawab atas penyalahgunaan.

## Kontribusi
Pull request dan issue sangat diterima.
Silakan lihat `CONTRIBUTING.md` untuk alur kontribusi.

## Lisensi
Project ini menggunakan lisensi MIT. Lihat file `LICENSE`.
