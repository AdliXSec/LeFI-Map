# 🌙 LeFiMap — Advanced LFI Scanner & Exploitation Tools

LeFiMap adalah Tools pemindaian dan eksploitasi **Local File Inclusion (LFI)** yang dirancang untuk memberikan workflow lengkap: mulai dari identifikasi, fuzzing payload, bypass filter, wrapper injection, hingga post-exploitation shell. Dibangun secara sistematis untuk mendukung proses pengujian keamanan modern.

> **⚠️ Peringatan**: Gunakan LeFiMap hanya untuk keperluan legal seperti pembelajaran, riset keamanan, atau pengujian pada sistem yang Anda miliki izin resminya.

---

## ✨ Fitur Unggulan

* 🔍 *High-Accuracy LFI Detection* (EASY/HARD)
* 🧰 Wrapper PHP support: `php_filter`, `zip`, `phar`, dan `file`
* 🛡 *WAF/IDS Evasion* dengan encoding berlapis
* 🧪 Payload fuzzing otomatis berbasis wordlist
* 🌐 Routing melalui Tor + IP rotation
* ⚙️ Multi-threading + rate limiting
* 💣 Post-exploitation OS shell
* 🧭 Fingerprinting & DOM-based reflection scan
* 📦 Output logging + response capture

---

## 📦 Instalasi

```bash
git clone https://github.com/username/LeFiMap.git
cd LeFiMap
python3 lefimap.py -h
```

Install dependensi:

```bash
pip install -r requirements.txt
```

---

## 🚀 Contoh Penggunaan Cepat

### 1. Scan dasar

```bash
python3 lefimap.py -u "http://target.com/?file=FUZZ" -w payloads.txt
```

### 2. Cari file sensitif secara otomatis

```bash
python3 lefimap.py --url "http://site.com/?page=FUZZ" --file "flag.txt"
```

### 3. POST request dengan data custom

```bash
python3 lefimap.py -u "http://target/login" -m POST -d "id=FUZZ"
```

### 4. Evasion: double encoding + nullbyte

```bash
python3 lefimap.py -u "http://vuln.com/?p=FUZZ" -w list.txt -f "url,doubleurl,nullbyte"
```

### 5. Menggunakan Tor + Capture respons penuh

```bash
python3 lefimap.py -u "http://test/?v=FUZZ" --tor --tor-renew --capture all
```

---

## 🧩 Dokumentasi Opsi Lengkap

### 🎯 **Target Options**

| Opsi             | Deskripsi                                            |
| ---------------- | ---------------------------------------------------- |
| `-u, --url URL`  | Target URL (gunakan `FUZZ` sebagai injection point). |
| `-w, --wordlist` | Wordlist payload.                                    |
| `--file FILE`    | Cari file tertentu dengan traversal otomatis.        |

### 📡 **Request Options**

| Opsi            | Keterangan                         |
| --------------- | ---------------------------------- |
| `-m, --method`  | GET/POST. Default: GET.            |
| `-d, --data`    | Data POST (`id=FUZZ`).             |
| `-s, --session` | Cookie session.                    |
| `-t, --timeout` | Timeout request. Default 10 detik. |

### 🔍 **Detection Options**

| Opsi            | Deskripsi            |
| --------------- | -------------------- |
| `-l, --level`   | EASY/HARD detection. |
| `--success-key` | String keberhasilan. |
| `--failed-key`  | String kegagalan.    |

### 🛡 **Evasion Options**

| Opsi                  | Deskripsi                                               |
| --------------------- | ------------------------------------------------------- |
| `-f, --filter`        | url, doubleurl, base64, hex, utf8, traversal, nullbyte. |
| `--replace`           | Replace pattern custom.                                 |
| `-ra, --random-agent` | Random User-Agent.                                      |
| `--tor`               | Gunakan Tor.                                            |
| `--tor-renew`         | Renew IP Tor.                                           |

### 📦 **Wrapper Options**

| Opsi             | Deskripsi                    |
| ---------------- | ---------------------------- |
| `--wrapper`      | php_filter, file, zip, phar. |
| `--wrapper-args` | Argumen tambahan.            |

### 💣 **Exploitation Options**

| Opsi         | Deskripsi                  |
| ------------ | -------------------------- |
| `--os-shell` | Coba interactive OS shell. |

### ⚡ **Performance Options**

| Opsi             | Deskripsi   |
| ---------------- | ----------- |
| `-th, --threads` | Threading.  |
| `--limit`        | Rate limit. |

### 📤 **Output Options**

| Opsi           | Deskripsi                                               |
| -------------- | ------------------------------------------------------- |
| `-o, --output` | Simpan hasil scan.                                      |
| `--silent`     | Quiet mode.                                             |
| `--benchmark`  | Benchmark waktu.                                        |
| `--capture`    | Tampilkan respons (`500`, jumlah karakter, atau `all`). |

### 🔧 **Misc Options**

| Opsi         | Deskripsi              |
| ------------ | ---------------------- |
| `--identify` | Fingerprinting target. |
| `--dom-scan` | DOM reflection scan.   |

---

## 🌌 Contoh Penggunaan Lengkap (Rekomendasi)

```bash
python3 lefimap.py \
  -u "http://target.com/page?file=FUZZ" \
  -w payloads.txt \
  -f "url,doubleurl,nullbyte" \
  -l HARD \
  --capture all \
  --tor --tor-renew \
  -th 20 \
  -o results.txt
```

---

## 📈 Roadmap Pengembangan

* GUI Mode (Qt/PySide)
* Payload generator otomatis
* Integrasi Turbo Intruder Mode
* Response classifier berbasis Machine Learning
* Auto wrapper-by-waf detection

---

## 🤝 Kontribusi

Kontribusi selalu terbuka! Anda dapat menambahkan:

* Payload baru
* Modul wrapper tambahan
* Performa scanning
* Modul bypass WAF

Fork → Commit → Pull Request.

---

## 📜 Lisensi

Dirilis dengan lisensi **MIT License**.

---

## 💬 Kontak

Linkedin: https://www.linkedin.com/in/naufal-syahruradli-a23504343/
