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

Saat aplikasi mulai, kolom status persetujuan ditambahkan ke database lama bila belum ada. Akun lama dipertahankan aktif; hanya pendaftaran baru yang menunggu persetujuan.

## Penjelasan singkat untuk portofolio

> “Docket adalah portal helpdesk IT internal untuk perusahaan kecil dan menengah. Aplikasi ini membantu karyawan melaporkan masalah perangkat, aplikasi, jaringan, atau akun; lalu membantu tim IT mengelola penugasan, status, komunikasi, panduan mandiri, dan ringkasan antrean dalam satu tempat.”

## Batasan demo

Docket bukan marketplace jasa IT dan tidak memproses pembayaran. Target waktu hanya simulasi; aplikasi belum mengatur jam kerja, hari libur, eskalasi otomatis, atau notifikasi email. Persetujuan akun saat ini dilakukan oleh super admin di aplikasi; email belum diverifikasi otomatis. Untuk penggunaan perusahaan sungguhan, batasi pendaftaran ke karyawan yang berwenang dan sesuaikan kebijakan akses, target layanan, serta penyimpanan data dengan perusahaan.
