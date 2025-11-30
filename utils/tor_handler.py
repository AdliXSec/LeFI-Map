import requests
import time
from stem import Signal
from stem.control import Controller
from utils.banner import info, warning, success

def check_tor_connection(host, port, proxy_protocol="socks5h"):
    print(f"{info()} Memverifikasi koneksi Tor...")
    proxies = {
        'http': f'{proxy_protocol}://{host}:{port}',
        'https': f'{proxy_protocol}://{host}:{port}'
    }
    try:
        ip_asli = requests.get('https://api.ipify.org', timeout=10).text
        ip_tor = requests.get('https://api.ipify.org', proxies=proxies, timeout=20).text
        
        if ip_asli != ip_tor:
            print(f"{success()} Koneksi Tor berhasil! IP Anda terlihat sebagai: {ip_tor}")
            return True
        else:
            print(f"{warning()} Peringatan: IP Tor sama dengan IP asli. Anonimitas mungkin gagal.")
            return False
    except requests.RequestException as e:
        print(f"{warning()} Gagal terhubung melalui Tor: {e}")
        return False

def renew_tor_circuit(control_port=9051, password='your_password'):
    try:
        with Controller.from_port(port=control_port) as controller:
            controller.authenticate(password=password)
            controller.signal(Signal.NEWNYM)
            print(f"{info()} Sinyal NEWNYM terkirim. Menunggu sirkuit baru...")
            print(f"{success()} Sirkuit Tor baru telah aktif.")
            return True
    except Exception as e:
        print(f"{warning()} Gagal mengganti sirkuit Tor: {e}")
        print("   Pastikan Tor Control Port sudah aktif dan password benar.")
        return False