# Kebijakan Keamanan

zhongkui adalah tool keamanan, jadi cacat di dalamnya bisa berbahaya: alat yang
seharusnya menemukan kebocoran justru bisa menjadi jalur kebocoran.

## Melaporkan kerentanan

Jangan buka issue publik. Gunakan **GitHub Private Vulnerability Reporting**:
tab **Security** → **Report a vulnerability** di
https://github.com/malasahjagotwin/zhongkui/security/advisories/new

Sertakan: versi, perintah yang dijalankan, dan langkah reproduksi sekecil
mungkin. Kalau kamu perlu menyertakan kredensial asli sebagai bukti, **jangan** —
ganti dengan nilai sintetis yang memicu perilaku yang sama.

## Yang termasuk lingkup

- **Kebocoran nilai rahasia** lewat kanal apa pun: laporan, pesan error,
  stderr, keluaran JSON, atau log. Termasuk kegagalan redaksi.
- **Prompt injection** dari isi berkas yang dipindai, yang mengakibatkan model
  menghasilkan temuan palsu, menyembunyikan temuan nyata, atau membocorkan data
  ke pihak lain.
- **Panic atau crash** akibat masukan yang dikendalikan penyerang: berkas yang
  dipindai, lockfile, atau respons dari endpoint LLM.
- **Eksekusi kode** yang dipicu oleh isi berkas yang dipindai.
- **Keluar dari direktori** yang di-scan (symlink, path traversal) saat
  menelusuri berkas.
- **Kebocoran data** ke endpoint jaringan yang tidak sesuai dengan yang
  didokumentasikan, atau terkirim tanpa sepengetahuan pemakai.

## Yang di luar lingkup

- **False positive dan false negative pada heuristik.** Rule pola memang
  menduga-duga dan tidak bisa membedakan `Command::new("ls")` dari
  `Command::new(input)`. Laporkan sebagai issue biasa, bukan laporan keamanan.
- **Kualitas keluaran model.** zhongkui tidak melatih model; temuan dari LLM
  selalu ditandai `sumber: llm` justru karena harus diverifikasi manusia.
- **Kerentanan pada dependency pihak ketiga** — laporkan ke proyek masing-masing
  (atau biarkan Dependabot yang menangani).
- **Salah konfigurasi endpoint LLM** oleh pemakai, termasuk memakai relay
  pihak ketiga untuk kode rahasia. Itu keputusan pemakai dan sudah diperingatkan.

## Batasan yang diketahui

Didokumentasikan terbuka di [README](README.md#keamanan) — bukan kerentanan,
tapi hal yang perlu disadari sebelum memakai tool ini.