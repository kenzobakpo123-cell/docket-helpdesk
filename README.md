# Docket — Portal Helpdesk IT Internal

Docket adalah aplikasi helpdesk internal untuk perusahaan kecil atau menengah. Karyawan menggunakannya untuk melaporkan kendala teknologi kantor, sementara tim IT menggunakan satu antrean untuk menugaskan, memperbarui, dan menyelesaikan laporan tersebut.

## Masalah yang diselesaikan

Permintaan bantuan IT yang dikirim lewat chat atau lisan mudah terlewat dan sulit dilacak. Docket menyediakan alur yang tercatat: karyawan membuat tiket, tim IT menindaklanjuti, dan kedua pihak melihat status serta percakapan pada tiket yang sama.

## Jenis kendala

- Perangkat keras, seperti laptop atau printer.
- Perangkat lunak dan aplikasi kerja.
- Jaringan kantor dan Wi-Fi.
- Akun serta hak akses.
- Kendala IT lain yang belum masuk kategori tersebut.

## Fitur

- Akun karyawan dengan persetujuan super admin sebelum akses diberikan.
- Tiga peran dengan batas akses berbeda: karyawan, admin/tim IT, dan super admin.
- Tiket dengan kategori, prioritas, status, pembuat, dan penanggung jawab.
- Percakapan komentar pada tiket.
- Pencarian, filter, pengurutan, dan paginasi daftar tiket.
- Ekspor tiket yang sedang cocok dengan filter ke CSV.
- Pusat panduan mandiri untuk masalah IT yang umum; panduan dapat membuka formulir tiket dengan judul dan kategori terisi.
- Ringkasan antrean dan indikator target waktu penanganan.
- Riwayat aktivitas untuk super admin: login/logout, pendaftaran, perubahan akses akun, pembuatan laporan, komentar, status, dan penugasan.
- Filter riwayat aktivitas berdasarkan jenis kejadian dan nama pengguna, dengan paginasi.
- Notifikasi push per perangkat untuk laporan baru, komentar, perubahan tiket, dan persetujuan akun.
- Riwayat perubahan status, penugasan, komentar, dan pembuatan tiket pada setiap tiket.
- Lampiran privat berupa JPG/PNG/WebP hingga 5 MB, dengan akses unduh yang dibatasi sesuai hak akses tiket.
- Laporan operasional tim IT: jumlah tiket 30 hari, kategori/status, rerata penyelesaian, beban tiket aktif, dan tiket yang melewati target.
- Preferensi push per kategori notifikasi.
- Template jawaban cepat yang dapat dikelola tim IT dan digunakan pada percakapan tiket.
- Pengingat push satu jam sebelum target dan sekali setelah target SLA terlewati.

## Target waktu pada demo

Target waktu adalah simulasi portofolio berbasis jam kalender UTC, bukan SLA resmi atau jaminan respons perusahaan:

| Prioritas | Target simulasi |
| --- | --- |
| Tinggi | 4 jam |
| Sedang | 24 jam |
| Rendah | 72 jam |

## Alur penggunaan

1. Karyawan masuk, mencari panduan, lalu membuat tiket bila kendala belum selesai.
2. Karyawan melihat status, penanggung jawab, target simulasi, dan komentar pada tiketnya.
3. Tim IT melihat antrean, memfilter tiket, mengubah status, menetapkan penanggung jawab, dan membalas melalui komentar.
4. Tim IT dapat mengekspor antrean sesuai filter untuk kebutuhan laporan.
5. Super admin menyetujui/menolak pendaftaran dan menetapkan akun sebagai karyawan atau admin/tim IT.

## Peran dan persetujuan akun

| Peran | Akses |
| --- | --- |
| Karyawan (`user`) | Membuat laporan, membaca panduan, dan melihat atau mengomentari laporan miliknya sendiri. |
| Tim IT (`admin`) | Semua antrean, pencarian, ekspor, komentar, perubahan status, dan penugasan. Tidak dapat mengatur pengguna atau peran. |
| Super admin (`super_admin`) | Semua kemampuan tim IT, serta menyetujui/menolak akun, menonaktifkan akses, menetapkan peran karyawan atau tim IT, dan melihat riwayat aktivitas. |

Riwayat aktivitas mencatat login yang berhasil/logout, nama dan email aktor, jenis tindakan, ringkasan aman, target berupa ID tiket/akun, dan waktu UTC. Isi tiket/komentar, kata sandi, serta alamat IP tidak dicatat. Halaman riwayat hanya dapat dibuka oleh super admin. Log mulai terkumpul setelah versi ini berjalan dan belum memiliki masa retensi/penghapusan otomatis.

Pendaftaran publik selalu membuat akun `pending` dengan peran karyawan. Akun belum dapat login sampai disetujui super admin. Super admin pertama ditetapkan secara manual pada database yang benar, bukan lewat formulir pendaftaran:

1. Pastikan akun Icha sudah terdaftar di aplikasi.
2. Jalankan `python make_admin.py` pada lingkungan yang terhubung ke database deployment.
3. Masukkan email akun Icha yang tepat dan konfirmasi promosi.
4. Masuk sebagai Icha, buka **Kelola akun**, lalu setujui pendaftaran berikutnya dan pilih perannya.

Skrip promosi awal hanya berjalan jika belum ada super admin. Jangan menjalankannya dengan database lokal jika yang ingin diubah adalah akun di hosting.

Saat aplikasi mulai, kolom status persetujuan, preferensi notifikasi, dan timestamp pengingat SLA ditambahkan ke database lama bila belum ada. Akun lama dipertahankan aktif; hanya pendaftaran baru yang menunggu persetujuan. Tabel riwayat tiket, lampiran, dan template jawaban dibuat otomatis.

## Notifikasi push

Notifikasi push dikirim setelah pengguna mengaktifkannya melalui tombol **Aktifkan notifikasi** pada perangkat. Aplikasi memberi notifikasi untuk laporan IT baru kepada tim IT, komentar/perubahan tiket kepada pihak terkait, serta persetujuan akun jika akun tersebut sudah memiliki langganan perangkat aktif sebelumnya. Pengguna baru yang masih menunggu persetujuan belum dapat masuk untuk mengaktifkan push. Isi notifikasi sengaja tidak menyertakan judul atau isi laporan.

Untuk mengaktifkan pengiriman:

1. Pasang dependensi terbaru di virtualenv deployment: `pip install -r requirements.txt`.
2. Buat kunci VAPID di server (jangan di folder repository) dan simpan private key di luar folder publik/repo. Contoh:

   ```bash
   python -c "import base64; from py_vapid import Vapid; from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat; v=Vapid(); v.generate_keys(); v.save_key('/home/kafa/.docket-vapid.pem'); print(base64.urlsafe_b64encode(v.public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)).decode().rstrip('='))"
   ```

   Jalankan `chmod 600 /home/kafa/.docket-vapid.pem` setelahnya. Simpan nilai yang dicetak sebagai `VAPID_PUBLIC_KEY`. Jangan membagikan private key.
3. Atur variabel environment server yang tidak di-commit ke Git. Di PythonAnywhere, kamu dapat menaruhnya di `.env` server (jangan commit file ini) atau menetapkannya di file WSGI sebelum aplikasi di-import:
   - `VAPID_PUBLIC_KEY`: nilai publik yang dicetak pada langkah sebelumnya.
   - `VAPID_PRIVATE_KEY`: path ke file private key, misalnya `/home/kafa/.docket-vapid.pem`.
   - `VAPID_CLAIMS_EMAIL`: email kontak pengelola, tanpa awalan `mailto:`.
4. Reload aplikasi. Setiap pengguna mengaktifkan notifikasi di masing-masing browser/perangkat. Izin browser harus diberikan.

Laptop dan Android memerlukan browser yang mendukung Web Push. Untuk iPhone/iPad, gunakan iOS/iPadOS 16.4 atau lebih baru, tambahkan situs ke Layar Utama, buka dari ikon tersebut, lalu aktifkan notifikasi. Situs harus memakai HTTPS. Jika kunci server belum diatur, tombol aktivasi tidak ditampilkan dan push belum dikirim.

## Lampiran privat dan pengingat SLA

Lampiran tiket dibatasi ke JPG, JPEG, PNG, dan WebP dengan ukuran maksimal 5 MB. File disimpan di `instance/uploads` (bukan direktori static) dan hanya dapat diunduh oleh pemilik tiket atau tim IT. Pastikan direktori `instance/uploads` ikut dicadangkan dan tidak dipindahkan ke lokasi publik.

Pengingat SLA memerlukan Scheduled Task yang berjalan setiap jam, konfigurasi VAPID, dan aplikasi serta database deployment yang sama. Pada PythonAnywhere, buat task hourly dengan perintah berikut dan sesuaikan nama virtualenv serta lokasi proyek:

```bash
/home/kafa/.virtualenvs/docket-env/bin/python /home/kafa/docket-helpdesk/send_sla_reminders.py
```

Script memberi pengingat satu jam sebelum target kepada pembuat dan penanggung jawab tiket, serta pemberitahuan satu kali saat tiket aktif melewati target. Preferensi push pengguna tetap dihormati. Target dalam demo dihitung berdasarkan jam kalender UTC, bukan jam kerja; reminder membutuhkan konfigurasi push dan Scheduled Task aktif.

## Penjelasan singkat untuk portofolio

> “Docket adalah portal helpdesk IT internal untuk perusahaan kecil dan menengah. Aplikasi ini membantu karyawan melaporkan masalah perangkat, aplikasi, jaringan, atau akun; lalu membantu tim IT mengelola penugasan, status, komunikasi, panduan mandiri, dan ringkasan antrean dalam satu tempat.”

## Batasan demo

Docket bukan marketplace jasa IT dan tidak memproses pembayaran. Target waktu hanya simulasi; aplikasi belum mengatur jam kerja, hari libur, eskalasi otomatis, atau notifikasi email. Push memerlukan konfigurasi kunci VAPID dan izin pada setiap perangkat; push bukan pengganti notifikasi email yang dijamin terkirim. Persetujuan akun saat ini dilakukan oleh super admin di aplikasi; email belum diverifikasi otomatis. Untuk penggunaan perusahaan sungguhan, batasi pendaftaran ke karyawan yang berwenang dan sesuaikan kebijakan akses, target layanan, serta penyimpanan data dengan perusahaan.
