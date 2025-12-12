import argparse

def capture_type(value):
    if value.lower() == 'all':
        return 'all'
    try:
        int_value = int(value)
        if int_value <= 0:
            raise argparse.ArgumentTypeError("Jumlah karakter harus positif.")
        return int_value 
    except ValueError:
        raise argparse.ArgumentTypeError(f"Nilai tidak valid: '{value}'. Harus berupa angka positif atau 'all'.")

def parse_args():
    parser = argparse.ArgumentParser(
        description="LeFiMap - Advanced LFI Scanner & Exploitation Tool",
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=40)
    )

    
    target_group = parser.add_argument_group('Target', 'Opsi untuk menentukan target dan payload')
    target_group.add_argument("-u", "--url", required=True, help="Target URL. Gunakan 'FUZZ' sebagai titik injeksi.")
    target_group.add_argument("-w", "--wordlist", help="Path ke file wordlist payload.")
    target_group.add_argument("--file", help="Cari satu file spesifik dengan path traversal otomatis (e.g., 'flag.txt').")

    
    request_group = parser.add_argument_group('Request', 'Opsi untuk mengontrol detail request HTTP')
    request_group.add_argument("-m", "--method", type=str.upper, default="GET", choices=["GET", "POST"], help="Metode HTTP (default: GET).")
    request_group.add_argument("-d", "--data", help="Data untuk metode POST (e.g., 'id=FUZZ').")
    request_group.add_argument("-s", "--session", help="Cookie sesi untuk autentikasi (e.g., 'PHPSESSID=...').")
    request_group.add_argument("--header", help="Header kustom untuk request (dapat digunakan berkali-kali)", action="append")
    request_group.add_argument("-t", "--timeout", type=int, default=10, help="Timeout untuk request (detik, default: 10).")

    
    detection_group = parser.add_argument_group('Detection', 'Opsi untuk mengontrol logika deteksi kerentanan')
    detection_group.add_argument("-l", "--level", type=str.upper, default="EASY", choices=["EASY", "HARD"], help="Level deteksi (EASY atau HARD, default: EASY).")
    detection_group.add_argument("--success-key", help="Tentukan string unik yang menandakan sukses (e.g., 'picoCTF{').")
    detection_group.add_argument("--failed-key", help="Tentukan string unik yang menandakan kegagalan (e.g., 'Incorrect syntax').")

    
    evasion_group = parser.add_argument_group('Evasion', 'Opsi untuk menghindari deteksi WAF/IDS')
    evasion_group.add_argument("-f", "--filter", help="Terapkan filter encoding (url, doubleurl, base64, hex, utf8, traversal, nullbyte), dipisahkan koma (e.g., 'url,base64').")
    evasion_group.add_argument("--replace", help="Ganti string kustom pada payload (e.g., \"../,__/\").")
    evasion_group.add_argument("-ra", "--random-agent", nargs='?', const='USE_DEFAULT_LIST', default=None, metavar='FILE', help="Gunakan User-Agent acak dari daftar internal atau dari file.")
    evasion_group.add_argument("--tor", action="store_true", help="Gunakan proxy Tor untuk semua request.")
    evasion_group.add_argument("--tor-type", type=str.upper, default="SOCKS5", choices=["SOCKS5", "SOCKS4", "HTTP"], help="Tipe proxy Tor (default: SOCKS5).")
    evasion_group.add_argument("--tor-host", default="127.0.0.1", help="Host proxy Tor (default: 127.0.0.1).")
    evasion_group.add_argument("--tor-port", type=int, default=9050, help="Port proxy SOCKS Tor (default: 9050).")
    evasion_group.add_argument("--tor-renew", action="store_true", help="Minta sirkuit/IP baru dari Tor sebelum scan.")
    evasion_group.add_argument("--tor-control-port", type=int, default=9051, help="Port Tor Control (default: 9051).")
    evasion_group.add_argument("--tor-control-password", help="Password untuk Tor Control Port.")


    wrapper_group = parser.add_argument_group('Wrapper', 'Opsi untuk menggunakan payload PHP Wrapper')
    wrapper_group.add_argument("--wrapper", choices=['php_filter', 'file', 'zip', 'phar', 'expect', 'input'], help="Gunakan payload wrapper spesifik. Membutuhkan argumen tambahan.")
    wrapper_group.add_argument("--wrapper-args", nargs='+', metavar='ARG', help="Argumen untuk wrapper. Contoh untuk php_filter: index.php. Untuk zip: /path/ke/file.zip shell.php")
    
    
    exploitation_group = parser.add_argument_group('Exploitation', 'Opsi untuk eksploitasi pasca penemuan')
    exploitation_group.add_argument("--os-shell", nargs='?', const=1, default=None, type=int, metavar='METHOD', choices=[1, 2, 3, 4], help="Coba shell interaktif. Opsional: pilih metode (1-4, default: 1).")
    
    
    performance_group = parser.add_argument_group('Performance', 'Opsi untuk mengatur kecepatan dan performa scan')
    performance_group.add_argument("-th", "--threads", type=int, default=10, help="Jumlah thread yang akan digunakan (default: 10).")
    performance_group.add_argument("--limit", nargs=2, type=int, metavar=('COUNT', 'SECONDS'), help="Batasi laju request (e.g., 50 10).")

    
    output_group = parser.add_argument_group('Output', 'Opsi untuk mengontrol tampilan output')
    output_group.add_argument("-o", "--output", help="Simpan hasil scan ke dalam file di folder 'output/'.")
    output_group.add_argument("--json", help="Simpan hasil dalam format JSON ke file yang ditentukan.")
    output_group.add_argument("--silent", action="store_true", help="Aktifkan silent mode untuk output minimal.")
    output_group.add_argument("--benchmark", action="store_true", help="Tampilkan benchmark waktu untuk temuan.")
    output_group.add_argument("--capture", nargs='?', const=500, default=None, type=capture_type, metavar='CHARS_OR_ALL', help="Tampilkan respons. Opsional: jumlah karakter atau 'all' (default: 500).")

    
    misc_group = parser.add_argument_group('Miscellaneous', 'Fitur-fitur tambahan')
    misc_group.add_argument("--identify", action="store_true", help="Lakukan identifikasi (fingerprinting) pada target.")
    misc_group.add_argument("--dom-scan", action="store_true", help="Aktifkan pengecekan sekunder untuk DOM-based reflection.")

    
    args = parser.parse_args()
        
    if args.method == "POST" and not args.data:
        parser.error("-d/--data diperlukan untuk metode POST.")

    if args.replace and ',' not in args.replace:
        parser.error("Format --replace salah. Gunakan format 'cari,ganti'.")
    
    if args.tor_renew and not args.tor:
        parser.error("--tor-renew membutuhkan --tor.")

    return args