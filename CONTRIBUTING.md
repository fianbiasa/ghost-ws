# Contributing to Ghost Web Scanner

Terima kasih sudah ingin berkontribusi ke Ghost Web Scanner.
Dokumen ini menjelaskan alur kontribusi, standar perubahan, dan checklist sebelum pull request.

## 1. Persiapan Environment

### Clone repository
```bash
git clone https://github.com/fianbiasa/ghost-ws.git
cd ghost-ws
```

### Buat virtual environment
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
```

Jika di Debian/Ubuntu muncul error `ensurepip is not available`, install:
```bash
sudo apt install -y python3-venv
```

## 2. Workflow Kontribusi

1. Fork repository.
2. Buat branch baru dari branch utama.
3. Lakukan perubahan seperlunya (kecil, fokus, jelas).
4. Jalankan pengujian dasar.
5. Commit dengan pesan yang deskriptif.
6. Push branch.
7. Buka Pull Request.

Contoh:
```bash
git checkout -b feat/nama-fitur
# edit file
git add .
git commit -m "feat: tambah audit CORS checker"
git push origin feat/nama-fitur
```

## 3. Standar Kode

- Gunakan Python yang kompatibel dengan requirement project.
- Pertahankan style dan struktur kode yang sudah ada.
- Hindari refactor besar pada PR kecil.
- Jangan hardcode kredensial, token, atau data sensitif.
- Jika menambah fitur, update dokumentasi terkait.

## 4. Pengujian Minimum Sebelum PR

Jalankan minimal command berikut:

```bash
source .venv/bin/activate
python -m py_compile gws.py
python gws.py --target https://example.com --mode cepat --insecure --min-severity LOW
```

Pastikan:
- Script tidak error.
- Report JSON dan SARIF tetap terbuat di folder `reports/`.

## 5. Area yang Sering Diubah

- File utama scanner: `gws.py`
- Dokumentasi: `README.md`, `CONTRIBUTING.md`
- Dependencies: `requirements.txt`

Jika mengubah behavior scanner, sertakan contoh output singkat di deskripsi PR.

## 6. Panduan Pull Request

Saat membuka PR, sertakan:

- Ringkasan perubahan.
- Alasan perubahan (bugfix/fitur/performance).
- Dampak ke user.
- Cara verifikasi lokal.

Template ringkas:

```text
Ringkasan:
- ...

Alasan:
- ...

Verifikasi:
- python -m py_compile gws.py
- python gws.py --target https://example.com --mode cepat --insecure --min-severity LOW
```

## 7. Scope yang Tidak Diterima

- Perubahan yang mendorong penyalahgunaan tool.
- Penambahan payload berbahaya tanpa konteks defensive.
- Perubahan destruktif pada struktur project tanpa alasan kuat.

## 8. Responsible Use

Kontribusi harus menjaga tujuan project untuk audit defensif dan penggunaan legal.
Lakukan scanning hanya pada sistem yang Anda miliki izin eksplisit.
