# AdBlock VPN

Aplikasi Android pemblokir iklan via DNS (VPN lokal, tanpa root) — gaya ONE HENDRIUS.

## Cara kerja

`VpnService` mode DNS-only: semua query DNS dicek ke `assets/blocklist.txt`
(76.104 domain, dari StevenBlack unified hosts). Domain yang diblokir
dijawab NXDOMAIN, sisanya diteruskan ke 8.8.8.8. Iklan di game dan aplikasi
lain yang dimuat lewat domain tersebut tidak tampil.

## Yang tidak bisa diblokir

- Iklan video YouTube (bukan lewat DNS).
- Iklan berhadiah di game tidak memberi hadiah selama VPN aktif.

## Build

Butuh Android SDK (build-tools 34.0.0, platform android-34) dan JDK 21.

```sh
bash build.sh
```

Hasil: `adblock-vpn.apk` (package `com.bahlil.adblock`).

## Catatan

- Keystore signing (`app.keystore`) TIDAK ada di repo ini — simpan terpisah.
  Update APK berikutnya harus ditandatangani dengan keystore yang sama.
- APK rilis ada di GitHub Releases, bukan di repo.
- Belum ada cek update otomatis di v1.0.
