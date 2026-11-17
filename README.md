# zhongkui 鍾馗

[![CI](https://github.com/malasahjagotwin/zhongkui/actions/workflows/ci.yml/badge.svg)](https://github.com/malasahjagotwin/zhongkui/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#lisensi)

Auditor keamanan source code dengan bantuan LLM.

> 鍾馗 — penakluk siluman. Sosok berwibawa yang berburu dan menundukkan roh
> jahat; gambarnya dipasang di pintu sebagai penjaga. Nama itu yang dipakai
> di sini: sesuatu yang berkeliling mencari yang bersembunyi, lalu menamainya.

Zhongkui bekerja dua lapis:

1. **Rule deterministik** — regex untuk kredensial hardcoded dan heuristik pola
   kode berbahaya (shell injection, SQL string concat, TLS verify dimatikan,
   hash lemah, dll). Berjalan **offline**, hasilnya bisa direproduksi persis,
   aman dipakai di CI.
2. **Analisis LLM** — opsional, lewat endpoint OpenAI-compatible. Dipakai untuk
   men-triase temuan (buang false positive, koreksi severity) dan mencari
   kerentanan yang lolos dari regex.

Lapis kedua **opt-in**, bukan default. Alasannya di bagian [Keamanan](#keamanan).

## Instalasi

```bash
cargo build --release
./target/release/zhongkui --help
```

## Pemakaian

### Audit kode (offline)

```bash
zhongkui audit ./src
zhongkui audit .                      # seluruh repo
zhongkui audit ./src --min-severity high
zhongkui audit ./src --format json > report.json
zhongkui audit ./src --format grep    # file:line:SEV:rule:pesan, ramah grep
zhongkui audit ./src --source rule    # hanya temuan rule, tanpa usulan LLM
```

Temuan rule dan LLM bisa menunjuk baris yang sama untuk masalah yang sama.
`--source rule` memberi daftar bersih tanpa tumpang tindih; `--source llm`
menampilkan hanya usulan model.

### Audit kode dengan LLM

```bash
export LELUHUR_API_KEY=sk-...
zhongkui audit ./ --llm               # triase temuan deterministik
zhongkui audit ./ --llm-discover      # + kirim isi file untuk cari yang lolos regex
zhongkui audit ./ --llm --llm-discover
```

Isi kode dikirim ke endpoint pihak ketiga pada mode ini, dan zhongkui akan
memperingatkan sebelum melakukannya.

### Cek dependency

```bash
zhongkui deps Cargo.lock
zhongkui deps Cargo.lock --offline    # hanya daftar paket, tanpa panggil OSV
```

Query ke [OSV](https://osv.dev) — API publik, gratis, tanpa kredensial.

## Konfigurasi

Semua lewat environment variable:

| Variabel | Default | Keterangan |
|---|---|---|
| `LELUHUR_API_KEY` | — | Wajib untuk mode LLM |
| `LELUHUR_BASE_URL` | `https://leluhurcy.us.ci/v1` | Endpoint OpenAI-compatible |
| `ZHONGKUI_MODEL` | `ds-meji` | Nama model |

API key **hanya** dibaca dari environment, tidak pernah dari file di dalam repo.

## Format keluaran

- `text` (default) — berwarna, untuk dibaca manusia
- `json` — `{ summary, findings }`, untuk dikonsumsi tool lain
- `grep` — `file:line:SEVERITY:rule_id:pesan`, tanpa warna

Exit code `0` kalau pemindaian berhasil, `1` kalau terjadi error. Temuan
sendiri **tidak** membuat exit code gagal — supaya bisa dibedakan antara
"ada temuan" dan "tool-nya rusak".

## Keamanan

Tool yang mencari kebocoran kredensial itu sendiri jalur kebocoran yang
mudah terlewat. Beberapa keputusan yang diambil karena itu:

- **Nilai rahasia diredaksi di laporan.** Yang muncul hanya 4 karakter awal
  dan akhir. Laporan sering di-paste ke issue tracker atau chat.
- **Mode jaringan opt-in.** Pemindaian default tidak menyentuh jaringan sama
  sekali. Ini juga berarti tidak ada telemetri.
- **API key hanya dari env var**, supaya tidak gampang ikut ter-commit.
- **Batas jumlah data yang dikirim ke LLM** (`--llm-discover`): maksimal 20
  file, 40 KB per file, 300 KB total. Berkas yang namanya sendiri menandakan
  rahasia (`.env`, `*.pem`, `id_rsa`, …) **tidak dikirim sama sekali**, dan
  isi berkas lain diredaksi dulu sebelum dikirim — rahasia hardcoded memang
  sudah tertangkap rule lokal, jadi tidak ada gunanya mengirimkannya keluar.
- **Temuan dari LLM ditandai terpisah** (`sumber: llm`). Temuan itu
  probabilistik dan harus diverifikasi manusia sebelum dilaporkan ke siapa pun.

### Batasan yang perlu disadari

- Regex tidak bisa membedakan `Command::new("ls")` dari `Command::new(input)`.
  Rule pola adalah **petunjuk**, bukan bukti. Severity-nya sengaja konservatif.
- `--llm-discover` mengirim isi kode ke relay pihak ketiga. Untuk kode
  proprietary, pakai endpoint sendiri lewat `LELUHUR_BASE_URL`, atau jangan
  pakai flag ini.
- `zhongkui deps` mengungkap daftar dependency kamu ke OSV.
- **`--llm-discover` belum bebas prompt injection.** Isi berkas dibungkus
  penanda data-tak-terpercaya (bukan pagar markdown yang bisa di-*breakout*),
  penandanya dinetralkan kalau muncul di dalam isi, dan isinya diredaksi. Itu
  mengurangi risiko secara nyata — tetapi tidak menghilangkannya. Model bahasa
  masih bisa terpengaruh instruksi yang tersembunyi di dalam kode. Perlakukan
  temuan `--llm-discover` sebagai saran, bukan gerbang keamanan, dan jangan
  pakai flag ini pada kode yang tidak kamu percaya tanpa pengawasan.

## Arsitektur

```
src/
  main.rs          entry point, exit code
  cli.rs           definisi argumen (clap)
  finding.rs       model temuan, Severity, redaksi kredensial
  rules/
    mod.rs         walker file + orkestrasi rule
    secrets.rs     deteksi kredensial hardcoded
    patterns.rs    heuristik pola kode berbahaya
  llm.rs           klien endpoint OpenAI-compatible (retry 429/5xx)
  json.rs          ekstraksi JSON dari keluaran model
  audit.rs         perintah audit + triase/discovery LLM
  deps.rs          parsing Cargo.lock + query OSV
  report.rs        penyajian text/json/grep
```

## Lisensi

Dilisensikan ganda di bawah [MIT](LICENSE-MIT) atau [Apache-2.0](LICENSE-APACHE),
sesuai pilihanmu. Ini konvensi ekosistem Rust dan berarti kamu boleh memakai,
memodifikasi, dan mendistribusikan zhongkui dengan syarat yang sangat ringan.
