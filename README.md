# Palmerah RedCheck

Harness validasi pertahanan untuk Hackathon DPR RI 2026 "Keamanan Data".

## Apa ini

RedCheck menjalankan 31 pengecekan kelemahan (A1–A15 SIMAD, B1–B16 Parlemen360) terhadap dua web dummy tim — sekali di `MODE=vuln`, sekali di `MODE=hardened` — lalu membandingkan hasilnya. Output: laporan JSON per mode + `compare.html` scoreboard before/after.

## Prasyarat

| Kebutuhan | Status |
|---|---|
| Python 3.12 | ✅ sudah ada |
| Docker Desktop | ⚠️ **belum dipasang** — diperlukan untuk menyalakan target (`dprdemoweb`) dan untuk demo |

Tanpa Docker, RedCheck tetap selesai dan teruji secara offline (fixtures + sample output di `out/`).

## Instalasi

```powershell
cd C:\Users\gemz\Documents\Github\hackathon_scan
pip install -e .
```

## Konfigurasi

```powershell
copy .env.example .env
# Edit .env: isi DPRDEMOWEB_DIR jika berbeda
```

## Cara Pakai

### Offline (tanpa Docker) — bisa sekarang

```powershell
make test           # pytest hijau — semua detektor teruji via fixtures
make compare        # bangun out/compare.html dari sample JSON
python -m redcheck.runner --base http://evil.com:9999  # → keluar nonzero "refused"
```

### Live (perlu Docker Desktop)

```powershell
# 1. Nyalakan target dalam mode vuln
cd C:\Users\gemz\Documents\Github\dprdemoweb
make up             # atau: make vuln

# 2. Jalankan RedCheck vuln
cd C:\Users\gemz\Documents\Github\hackathon_scan
make redcheck-vuln  # → out/redcheck_vuln.json

# 3. Switch ke hardened
cd C:\Users\gemz\Documents\Github\dprdemoweb
make hardened

# 4. Jalankan RedCheck hardened
cd C:\Users\gemz\Documents\Github\hackathon_scan
make redcheck-hardened  # → out/redcheck_hardened.json

# 5. Bandingkan
make compare        # → out/compare.html (buka di browser)
```

### Demo lengkap + rekam

```powershell
make record         # menjalankan alur penuh dan merekam ke record/redcheck.log
```

## Output

| File | Isi |
|---|---|
| `out/redcheck_vuln.json` | Findings + scoreboard mode vuln |
| `out/redcheck_hardened.json` | Findings + scoreboard mode hardened |
| `out/compare.html` | Laporan HTML before/after, offline, standalone |

## Harapan hasil

- **Scoreboard vuln**: ratusan nik/rekening/email bocor
- **Scoreboard hardened**: ~0 (nilainya ciphertext atau tidak dikirim)
- **Proof (c)**: semua peran-sah hijau di hardened

## Struktur

```
redcheck/
  config.py          env + target definitions
  safety.py          allowlist guard (enforced in code)
  client.py          httpx factory + rate limiter
  accounts.py        demo accounts from TARGETS.md
  pii.py             PII patterns + scoreboard counter
  schema.py          Finding & Report dataclasses + JSON writer
  report.py          HTML compare generator
  checks/
    legacy_simad.py  A1–A15 checks
    modern_p360.py   B1–B16 checks
    proofs.py        proof (a)/(b)/(c)
  runner.py          orchestration entrypoint
tests/               pytest offline suite
fixtures/            recorded/synthetic responses for unit tests
out/                 sample output (committed)
record/              recording scripts
```
